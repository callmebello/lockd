import XCTest
import Darwin
@testable import LockdCore

/// Ponta a ponta: broker + socket Unix reais, `lockdctl mcp` real falando JSON-RPC, HTTPS real com chave FALSA.
/// Precisa de internet (usa api.anthropic.com, que responde 401 à chave falsa). Sem Touch ID: modo teste (LOCKD_HOME).
final class EndToEndMCPTests: XCTestCase {
    private let fakeKey = "sk-ant-api03-FAKEendToEnd0123456789abcdefGHIJklmnopQRS"
    private var home: String!
    private var previous: String?
    private var server: BrokerServer?

    override func setUpWithError() throws {
        previous = ProcessInfo.processInfo.environment["LOCKD_HOME"]
        home = "/tmp/lk-e2e-\(UUID().uuidString.prefix(8))"          // curto: caminho de socket Unix tem limite
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        setenv("LOCKD_HOME", home, 1)
        Vault.shared.lockNow(); BrokerSettings.programsEnabled = false
    }

    override func tearDownWithError() throws {
        Vault.shared.lockNow()
        try? FileManager.default.removeItem(atPath: home)
        if let previous { setenv("LOCKD_HOME", previous, 1) } else { unsetenv("LOCKD_HOME") }
    }

    private var lockdctl: URL {
        Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("lockdctl")
    }

    /// Fala MCP com o lockdctl real; devolve {id: result} das respostas.
    private func mcp(_ calls: [(name: String, args: [String: Any])], list: Bool = false) throws -> [Int: [String: Any]] {
        var lines: [[String: Any]] = [["jsonrpc": "2.0", "id": 1, "method": "initialize", "params": ["protocolVersion": "2025-06-18"]],
                                      ["jsonrpc": "2.0", "method": "notifications/initialized"]]
        if list { lines.append(["jsonrpc": "2.0", "id": 2, "method": "tools/list"]) }
        for (i, c) in calls.enumerated() {
            lines.append(["jsonrpc": "2.0", "id": 10 + i, "method": "tools/call", "params": ["name": c.name, "arguments": c.args]])
        }
        let input = try lines.map { String(decoding: try JSONSerialization.data(withJSONObject: $0), as: UTF8.self) }.joined(separator: "\n") + "\n"
        let p = Process(); p.executableURL = lockdctl; p.arguments = ["mcp"]
        p.environment = ["LOCKD_HOME": home, "PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory()]
        let inPipe = Pipe(), outPipe = Pipe(); p.standardInput = inPipe; p.standardOutput = outPipe; p.standardError = FileHandle.nullDevice
        try p.run()
        inPipe.fileHandleForWriting.write(Data(input.utf8)); try inPipe.fileHandleForWriting.close()
        let data = outPipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        var out: [Int: [String: Any]] = [:]
        for l in String(decoding: data, as: UTF8.self).split(separator: "\n") {
            if let o = try? JSONSerialization.jsonObject(with: Data(l.utf8)) as? [String: Any], let id = o["id"] as? Int, let r = o["result"] as? [String: Any] { out[id] = r }
        }
        return out
    }

    private func text(_ r: [String: Any]?) -> String { ((r?["content"] as? [[String: Any]])?.first?["text"] as? String) ?? "" }
    private func isError(_ r: [String: Any]?) -> Bool { r?["isError"] as? Bool ?? true }

    func testFullFlowThroughRealMCPAndSocketWithRealHTTPS() throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: lockdctl.path), "lockdctl não foi construído")
        var hints = addrinfo(); hints.ai_socktype = SOCK_STREAM; var res: UnsafeMutablePointer<addrinfo>?
        try XCTSkipUnless(getaddrinfo("api.anthropic.com", "443", &hints, &res) == 0, "sem internet"); freeaddrinfo(res)

        // 1) chave falsa capturada + regras autorizadas (o que a UI faz com Touch ID)
        let store = Store()
        let item = try store.saveSecret(Detection(envName: "ANTHROPIC_API_KEY", service: "Anthropic", type: "API key", value: fakeKey, confident: true),
                                        project: "E2E", source: "test").item
        XCTAssertFalse(Policies.rulesVerified(store.items[0]), "regra sem assinatura deve nascer inativa")
        try store.authorizeRules([item.id]) { $0.allowHosts = ["api.anthropic.com"] }
        XCTAssertTrue(Policies.rulesVerified(store.items[0]))

        // 2) broker + socket reais
        let broker = Broker(store: store)
        server = BrokerServer(broker: broker); try server!.start()

        // 3) tudo via MCP
        let ok = ["method": "GET", "url": "https://api.anthropic.com/v1/models", "project": "E2E", "timeout": 20,
                  "headers": ["x-api-key": "{{ANTHROPIC_API_KEY}}", "anthropic-version": "2023-06-01"]] as [String: Any]
        let r = try mcp([
            ("lockd_status", [:]),
            ("lockd_list_secrets", ["project": "E2E"]),
            ("lockd_http", ok),                                                                             // 12 legítimo
            ("lockd_http", ["method": "GET", "url": "https://example.com/", "project": "E2E", "headers": ["x": "{{ANTHROPIC_API_KEY}}"]]), // 13 host fora
            ("lockd_http", ["method": "GET", "url": "https://1.1.1.1/", "project": "E2E", "headers": ["x": "{{ANTHROPIC_API_KEY}}"]]),     // 14 IP literal
            ("lockd_http", ["method": "GET", "url": "http://api.anthropic.com/", "project": "E2E", "headers": ["x": "{{ANTHROPIC_API_KEY}}"]]), // 15 http
            ("lockd_http", ["method": "GET", "url": "https://api.anthropic.com/v1/models", "project": "E2E", "headers": ["x": "a\r\nHost: evil"]]), // 16 CRLF
            ("lockd_run", ["argv": ["curl", "-s", "https://api.anthropic.com", "-H", "x: {{ANTHROPIC_API_KEY}}"], "project": "E2E"]),      // 17 programas
            ("lockd_write_env", ["path": ".env", "cwd": NSHomeDirectory(), "project": "E2E"]),                                               // 18 .env
            ("lockd_audit", ["limit": 20]),
        ], list: true)

        let tools = (r[2]?["tools"] as? [[String: Any]])?.compactMap { $0["name"] as? String } ?? []
        print("TOOLS:", tools)
        XCTAssertTrue(tools.contains("lockd_http"))
        XCTAssertFalse(tools.contains("lockd_run"), "programas devem estar escondidos por padrão")

        print("STATUS:", text(r[10]).prefix(100))
        print("LIST:", text(r[11]))
        XCTAssertTrue(text(r[11]).contains("ANTHROPIC_API_KEY"))
        XCTAssertFalse(text(r[11]).contains(fakeKey))

        let legit = text(r[12])
        print("HTTP LEGÍTIMO →", isError(r[12]) ? "ERRO" : "ok", "|", legit.prefix(260).replacingOccurrences(of: "\n", with: " "))
        XCTAssertFalse(legit.contains(fakeKey))
        XCTAssertTrue(legit.contains("401") || legit.lowercased().contains("authentication"), "api.anthropic.com deve rejeitar a chave falsa com 401: \(legit)")

        for (id, label) in [(13, "host fora da lista"), (14, "IP literal"), (15, "http sem TLS"), (16, "CRLF no header"), (17, "lockd_run escondido"), (18, ".env desligado")] {
            print("ATAQUE \(label) →", isError(r[id]) ? "BLOQUEADO" : "PASSOU", "|", text(r[id]).prefix(120).replacingOccurrences(of: "\n", with: " "))
            XCTAssertTrue(isError(r[id]), "\(label) deveria ser recusado: \(text(r[id]))")
            XCTAssertFalse(text(r[id]).contains(fakeKey))
        }

        let audit = text(r[19])
        print("AUDIT:\n" + audit)
        XCTAssertFalse(audit.contains(fakeKey))
        let file = (try? String(contentsOfFile: home + "/audit.jsonl", encoding: .utf8)) ?? ""
        XCTAssertFalse(file.contains(fakeKey), "audit.jsonl nunca pode ter o valor")
        XCTAssertTrue(file.contains("{{ANTHROPIC_API_KEY}}"))
        XCTAssertFalse((try? String(contentsOfFile: home + "/items.json", encoding: .utf8))?.contains(fakeKey) ?? false, "items.json só tem ciphertext")
    }
}
