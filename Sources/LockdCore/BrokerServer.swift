import Foundation
import Darwin

/// Socket Unix (0600) por onde o lockdctl/MCP fala com o app. Só aceita o mesmo usuário.
/// O socket só expõe operações COM política — não existe operação "mostrar valor".
public final class BrokerServer: @unchecked Sendable {
    private let broker: Broker
    private var fd: Int32 = -1

    public init(broker: Broker) { self.broker = broker }

    public func start() throws {
        let path = LockdPaths.socketFile.path
        guard path.utf8.count < 100 else { throw NSError(domain: "lockd.socket", code: 1, userInfo: [NSLocalizedDescriptionKey: "socket path too long"]) }
        unlink(path)
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NSError(domain: "lockd.socket", code: 2) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutablePointer(to: &addr.sun_path) { p in
            p.withMemoryRebound(to: CChar.self, capacity: 104) { _ = strncpy($0, path, 103) }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let r = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) } }
        guard r == 0 else { throw NSError(domain: "lockd.socket", code: 3, userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(errno))]) }
        chmod(path, 0o600)
        listen(fd, 16)
        let sock = fd
        Thread.detachNewThread { [weak self] in
            while true {
                let c = accept(sock, nil, nil)
                if c < 0 { if errno == EINTR { continue }; break }
                DispatchQueue.global().async { self?.serve(c) }
            }
        }
    }

    private func serve(_ c: Int32) {
        defer { close(c) }
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(c, &uid, &gid) == 0, uid == getuid() else { return }
        guard let line = BrokerWire.readLine(c), let d = line.data(using: .utf8),
              let req = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else {
            BrokerWire.write(c, ["ok": false, "text": "bad request"]); return
        }
        if (req["op"] as? String) == "browser_attach" {      // conexão longa da extensão (só navegador assinado)
            broker.bridge.attach(c); return
        }
        BrokerWire.write(c, broker.handle(req))
    }
}

public enum BrokerWire {
    public static func readLine(_ fd: Int32, limit: Int = 4_000_000) -> String? {
        var data = Data(); var buf = [UInt8](repeating: 0, count: 8192)
        while data.count < limit {
            let n = read(fd, &buf, buf.count)
            if n <= 0 { break }
            data.append(contentsOf: buf[0..<n])
            if data.contains(0x0A) { break }
        }
        return data.isEmpty ? nil : String(decoding: data.prefix { $0 != 0x0A }, as: UTF8.self)
    }

    public static func write(_ fd: Int32, _ obj: [String: Any]) {
        guard var d = try? JSONSerialization.data(withJSONObject: obj) else { return }
        d.append(0x0A)
        d.withUnsafeBytes { p in
            var off = 0
            while off < d.count { let n = Darwin.write(fd, p.baseAddress! + off, d.count - off); if n <= 0 { break }; off += n }
        }
    }
}

public enum BrokerClient {
    /// Abre uma conexão longa (extensão do navegador). Tenta abrir o app se necessário.
    public static func openStream(launchIfNeeded: Bool = true) -> Int32? {
        func connectOnce() -> Int32? {
            let path = LockdPaths.socketFile.path
            let fd = socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else { return nil }
            var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
            withUnsafeMutablePointer(to: &addr.sun_path) { p in p.withMemoryRebound(to: CChar.self, capacity: 104) { _ = strncpy($0, path, 103) } }
            let len = socklen_t(MemoryLayout<sockaddr_un>.size)
            let r = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) } }
            if r != 0 { close(fd); return nil }
            return fd
        }
        if let fd = connectOnce() { return fd }
        if launchIfNeeded {
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/open"); p.arguments = ["-g", "-a", "Lockd"]
            try? p.run(); p.waitUntilExit()
            for _ in 0..<20 { Thread.sleep(forTimeInterval: 0.3); if let fd = connectOnce() { return fd } }
        }
        return nil
    }

    /// Fala com o app. Se o app não estiver aberto, tenta abri-lo.
    public static func call(op: String, args: [String: Any] = [:], launchIfNeeded: Bool = true) -> [String: Any] {
        func attempt() -> [String: Any]? {
            let path = LockdPaths.socketFile.path
            let fd = socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else { return nil }
            defer { close(fd) }
            var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
            withUnsafeMutablePointer(to: &addr.sun_path) { p in p.withMemoryRebound(to: CChar.self, capacity: 104) { _ = strncpy($0, path, 103) } }
            let len = socklen_t(MemoryLayout<sockaddr_un>.size)
            let r = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) } }
            guard r == 0 else { return nil }
            BrokerWire.write(fd, ["op": op, "args": args])
            guard let line = BrokerWire.readLine(fd), let d = line.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return ["ok": false, "text": "no answer from Lockd"] }
            return obj
        }
        if let r = attempt() { return r }
        if launchIfNeeded {
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/open"); p.arguments = ["-g", "-a", "Lockd"]
            try? p.run(); p.waitUntilExit()
            for _ in 0..<20 { Thread.sleep(forTimeInterval: 0.3); if let r = attempt() { return r } }
        }
        return ["ok": false, "text": "Lockd isn't running. Open the Lockd app (it keeps your keys and asks for your Touch ID)."]
    }
}
