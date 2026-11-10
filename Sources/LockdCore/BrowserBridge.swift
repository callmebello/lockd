import Foundation
import Darwin
import Security

/// Leitor de linhas com buffer (a conexão da extensão é um fluxo, não um pedido único).
final class LineReader {
    private let fd: Int32
    private var buf = Data()
    init(_ fd: Int32) { self.fd = fd }
    func next(limit: Int = 4_000_000) -> String? {
        var chunk = [UInt8](repeating: 0, count: 16384)
        while true {
            if let i = buf.firstIndex(of: 0x0A) {
                let line = buf[buf.startIndex..<i]
                buf.removeSubrange(buf.startIndex...i)
                return String(decoding: line, as: UTF8.self)
            }
            if buf.count > limit { return nil }
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { return nil }
            buf.append(contentsOf: chunk[0..<n])
        }
    }
}

/// Confere QUEM está do outro lado da conexão da extensão: o lockdctl precisa ter sido iniciado por um navegador
/// Chromium assinado (Chrome, Brave ou Edge). Um processo qualquer do usuário (inclusive o agente) não passa.
public enum BrowserPeer {
    /// Team IDs da Apple dos navegadores aceitos.
    static let teams = ["EQHXZ8M8AV", "KL8N8XSYF4", "UBF8T346G9"]   // Google, Brave, Microsoft

    public static func isBrowser(fd: Int32) -> Bool {
        var pid: pid_t = 0
        var len = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0, pid > 1 else { return false }
        // O host nativo é filho direto do navegador (aceita também um avô, caso o sistema coloque um intermediário).
        var current = pid
        for _ in 0..<2 {
            guard let parent = parentPid(current), parent > 1 else { return false }
            if signedBrowser(pid: parent) { return true }
            current = parent
        }
        return false
    }

    static func parentPid(_ pid: pid_t) -> pid_t? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { return nil }
        return info.kp_eproc.e_ppid
    }

    static func signedBrowser(pid: pid_t) -> Bool {
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else { return false }
        for team in teams {
            var req: SecRequirement?
            let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
            if SecRequirementCreateWithString(text as CFString, [], &req) == errSecSuccess, let req,
               SecCodeCheckValidity(code, [], req) == errSecSuccess { return true }
        }
        return false
    }
}

/// Canal com a extensão do navegador. Tudo o que passa aqui é um pedido de AÇÃO ("preencha este campo", "entregue a chave que apareceu");
/// o valor de uma chave só vai do cofre para a página (preencher) ou da página para o cofre (capturar) — nunca para o agente.
public final class BrowserBridge: @unchecked Sendable {
    /// Substituível em testes. Em produção só aceita navegadores assinados.
    nonisolated(unsafe) public static var peerCheck: (Int32) -> Bool = { BrowserPeer.isBrowser(fd: $0) }

    private final class Waiter { let sem = DispatchSemaphore(value: 0); var result: [String: Any]? }

    private let lock = NSLock()
    private var fd: Int32 = -1
    private var pending: [String: Waiter] = [:]
    /// (host, candidatos) → texto para a extensão mostrar ao usuário. Chamado quando o USUÁRIO clica "Salvar no Lockd" na página.
    public var onCapture: ((String, [String]) -> String)?
    public var onChange: (() -> Void)?

    public init() {}

    public var isConnected: Bool { lock.lock(); defer { lock.unlock() }; return fd >= 0 }

    /// Chamado pela thread do socket; só volta quando a extensão desconecta.
    func attach(_ c: Int32) {
        guard Self.peerCheck(c) else {
            BrokerWire.write(c, ["ok": false, "text": "Only a signed Chromium browser can attach to Lockd."]); return
        }
        lock.lock()
        let old = fd
        fd = c
        lock.unlock()
        if old >= 0 { shutdown(old, SHUT_RDWR) }
        send(c, ["ok": true, "t": "hello", "text": "attached"])
        onChange?()
        let reader = LineReader(c)
        while let line = reader.next() {
            guard let d = line.data(using: .utf8), let msg = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
                  let t = msg["t"] as? String else { continue }
            switch t {
            case "result":
                guard let id = msg["id"] as? String else { continue }
                lock.lock(); let w = pending.removeValue(forKey: id); lock.unlock()
                w?.result = msg; w?.sem.signal()
            case "capture":
                let host = (msg["host"] as? String) ?? ""
                let cands = (msg["candidates"] as? [String]) ?? []
                let cid = msg["cid"] as? String
                let text = onCapture?(host, cands) ?? "Lockd can't save this right now."
                send(c, ["t": "captured", "cid": cid ?? "", "text": text])
            default: break
            }
        }
        lock.lock()
        if fd == c { fd = -1 }
        let orphans = pending; pending = [:]
        lock.unlock()
        for (_, w) in orphans { w.result = ["ok": false, "text": "The browser extension disconnected."]; w.sem.signal() }
        onChange?()
    }

    private func send(_ c: Int32, _ obj: [String: Any]) {
        lock.lock(); defer { lock.unlock() }
        BrokerWire.write(c, obj)
    }

    /// Manda um comando à extensão e espera o resultado.
    func request(_ cmd: [String: Any], timeout: TimeInterval = 25) -> [String: Any] {
        lock.lock(); let c = fd; lock.unlock()
        guard c >= 0 else {
            return ["ok": false, "text": "The Lockd browser extension isn't connected. Open Chrome with the Lockd extension installed (Lockd → Settings → Browser)."]
        }
        let id = UUID().uuidString
        let w = Waiter()
        lock.lock(); pending[id] = w; lock.unlock()
        var m = cmd; m["t"] = "cmd"; m["id"] = id
        send(c, m)
        if w.sem.wait(timeout: .now() + timeout) == .timedOut {
            lock.lock(); pending.removeValue(forKey: id); lock.unlock()
            return ["ok": false, "text": "The browser didn't answer in time."]
        }
        return w.result ?? ["ok": false, "text": "no answer"]
    }
}

public enum BrowserInstaller {
    /// ID fixo da extensão (vem da chave pública no manifest). Mantido em sincronia com extension/manifest.json.
    public static let extensionID = "aplenjjnldnepbgelmlmnehcajacbpod"
    public static let hostName = "app.lockd.mac"

    static let browserDirs = [
        "Google/Chrome", "Google/Chrome Beta", "Google/Chrome Canary", "BraveSoftware/Brave-Browser",
        "Microsoft Edge", "Chromium", "Arc/User Data", "Vivaldi",
    ]

    /// Registra o host nativo nos navegadores instalados. Devolve os navegadores que receberam o manifest.
    @discardableResult
    public static func installHost(executable: String, extensionID: String = extensionID, home: URL = FileManager.default.homeDirectoryForCurrentUser) throws -> [String] {
        let manifest: [String: Any] = [
            "name": hostName, "description": "Lockd — keeps your keys out of the page and out of the agent's view",
            "path": executable, "type": "stdio", "allowed_origins": ["chrome-extension://\(extensionID)/"],
        ]
        let data = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys])
        var done: [String] = []
        let base = home.appendingPathComponent("Library/Application Support")
        for d in browserDirs {
            let root = base.appendingPathComponent(d)
            guard FileManager.default.fileExists(atPath: root.path) else { continue }
            let dir = root.appendingPathComponent("NativeMessagingHosts")
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try data.write(to: dir.appendingPathComponent("\(hostName).json"), options: .atomic)
            done.append(d.components(separatedBy: "/").last ?? d)
        }
        return done
    }
}
