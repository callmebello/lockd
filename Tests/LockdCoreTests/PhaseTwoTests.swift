import XCTest
import Network
import CryptoKit
import Darwin
@testable import LockdCore

final class PhaseTwoTests: XCTestCase {
    private var home: URL!
    private var previous: String?
    private let fake = "FAKE_HTTP_TOKEN_0123456789_abcdef"
    override func setUpWithError() throws {
        previous = ProcessInfo.processInfo.environment["LOCKD_HOME"]
        home = FileManager.default.temporaryDirectory.appendingPathComponent("lockd-phase2-\(UUID().uuidString)")
        setenv("LOCKD_HOME", home.path, 1)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        Vault.shared.lockNow(); BrokerSettings.programsEnabled = false
    }
    override func tearDownWithError() throws {
        Vault.shared.lockNow(); BrokerSettings.programsEnabled = false
        try? FileManager.default.removeItem(at: home)
        if let previous { setenv("LOCKD_HOME", previous, 1) } else { unsetenv("LOCKD_HOME") }
    }
    private func store(hosts: [String] = ["127.0.0.1"]) throws -> Store {
        let store = Store()
        let item = try store.saveSecret(Detection(envName: "HTTP_TOKEN", service: "Anthropic", type: "test", value: fake, confident: true), project: "Test", source: "test").item
        try store.authorizeRules([item.id]) { $0.allowHosts = hosts }
        return store
    }
    private func broker(_ store: Store, fresh: ((String) throws -> Void)? = nil) -> Broker {
        let broker = Broker(store: store, freshUnlock: fresh)
        broker.httpClient = SecureHTTPClient(testAllowLoopback: true)
        return broker
    }
    private func request(_ server: LocalHTTPFixture, path: String = "/", headers: [String: String] = ["Authorization": "Bearer {{HTTP_TOKEN}}"], body: Any? = nil) -> [String: Any] {
        var args: [String: Any] = ["method": "POST", "url": "http://127.0.0.1:\(server.port)" + path, "headers": headers, "project": "Test", "timeout": 5]
        if let body { args["body"] = body }
        return ["op": "http", "args": args]
    }
    func testHTTPKeyEchoIsFilteredAndAuditContainsTemplate() throws {
        let server = LocalHTTPFixture { request in (200, [:], Data(request.utf8), 0) }
        try server.start(); defer { server.stop() }
        let store = try store(), broker = broker(store)
        let result = broker.handle(request(server, body: ["key": "{{HTTP_TOKEN}}", "message": "hello"]))
        XCTAssertTrue(result["ok"] as? Bool ?? false, "\(result)")
        XCTAssertEqual(result["status"] as? Int, 200)
        XCTAssertFalse((result["text"] as? String ?? "").contains(fake))
        XCTAssertTrue((result["text"] as? String ?? "").contains("REDACTED"))
        XCTAssertTrue(server.requests.first?.contains(fake) ?? false)
        let audit = try String(contentsOf: LockdPaths.auditFile, encoding: .utf8)
        XCTAssertFalse(audit.contains(fake))
        XCTAssertTrue(audit.contains("{{HTTP_TOKEN}}"))
        XCTAssertTrue(audit.contains("http"))
    }
    func testUnauthorizedHostAndUnsignedPolicyAreDenied() throws {
        let server = LocalHTTPFixture(); try server.start(); defer { server.stop() }
        let store = try store(hosts: ["api.anthropic.com"]), broker = broker(store)
        XCTAssertFalse(broker.handle(request(server))["ok"] as? Bool ?? true)
        store.update(id: store.items[0].id) { $0.allowHosts = ["127.0.0.1"] }
        XCTAssertFalse(Policies.rulesVerified(store.items[0]))
        XCTAssertFalse(broker.handle(request(server))["ok"] as? Bool ?? true)
        XCTAssertTrue(server.requests.isEmpty)
    }
    func testRedirectDoesNotForwardAuthorization() throws {
        let destination = LocalHTTPFixture(); try destination.start(); defer { destination.stop() }
        let source = LocalHTTPFixture { _ in (302, ["Location": "http://localhost:\(destination.port)/steal"], Data(), 0) }
        try source.start(); defer { source.stop() }
        let broker = broker(try store(hosts: ["127.0.0.1", "localhost"]))
        let result = broker.handle(request(source))
        XCTAssertFalse(result["ok"] as? Bool ?? true)
        XCTAssertTrue((result["text"] as? String ?? "").contains("Redirect refused"))
        XCTAssertTrue(destination.requests.isEmpty)
    }
    func testPrivateAddressesAndLiteralIPsAreRejectedByProductionClient() throws {
        let client = SecureHTTPClient()
        for host in ["127.0.0.1", "10.0.0.1", "[::1]", "localhost", "169.254.169.254", "2130706433", "0177.0.0.1"] {
            XCTAssertThrowsError(try client.validateURL("https://" + host, hosts: [host]), host)
        }
        for address in ["0.0.0.0", "10.0.0.1", "127.0.0.1", "100.64.0.1", "169.254.169.254", "172.31.0.1", "192.168.1.1", "198.19.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "2002:7f00:1::"] {
            XCTAssertFalse(SecureHTTPClient.isPublicAddress(address), address)
        }
        XCTAssertTrue(SecureHTTPClient.isPublicAddress("8.8.8.8"))
        XCTAssertTrue(SecureHTTPClient.isPublicAddress("2606:4700:4700::1111"))
        XCTAssertThrowsError(try SecureHTTPClient.resolvePublic("localhost", timeout: 2))
    }
    func testCRLFAndLargeRequestAreRejectedBeforeNetwork() throws {
        let server = LocalHTTPFixture(); try server.start(); defer { server.stop() }
        let broker = broker(try store())
        for headers in [["x-test": "foo\r\nInjected: yes"], ["x-test\r\nInjected": "yes"], ["Host": "attacker.example"]] {
            let result = broker.handle(request(server, headers: headers, body: "{{HTTP_TOKEN}}"))
            XCTAssertFalse(result["ok"] as? Bool ?? true)
        }
        let result = broker.handle(request(server, body: String(repeating: "x", count: SecureHTTPClient.requestLimit + 1)))
        XCTAssertFalse(result["ok"] as? Bool ?? true)
        XCTAssertTrue(server.requests.isEmpty)
    }
    func testResponseLimitBinaryOmissionAndTimeout() throws {
        let large = LocalHTTPFixture { _ in (200, [:], Data(repeating: 65, count: SecureHTTPClient.responseLimit + 10000), 0) }
        try large.start(); defer { large.stop() }
        let client = SecureHTTPClient(testAllowLoopback: true)
        let result = try client.perform(method: "GET", url: "http://127.0.0.1:\(large.port)/", headers: [:], body: nil, hosts: ["127.0.0.1"], timeout: 3)
        XCTAssertEqual(result.data.count, SecureHTTPClient.responseLimit)
        XCTAssertTrue(result.truncated)
        let binary = LocalHTTPFixture { _ in (200, ["Content-Type": "application/octet-stream"], Data(self.fake.utf8), 0) }
        try binary.start(); defer { binary.stop() }
        let response = broker(try store()).handle(request(binary))
        XCTAssertTrue(response["ok"] as? Bool ?? false)
        XCTAssertFalse((response["text"] as? String ?? "").contains(fake))
        XCTAssertTrue((response["text"] as? String ?? "").contains("binary response omitted"))
        let slow = LocalHTTPFixture { _ in (200, [:], Data(), 1) }; try slow.start(); defer { slow.stop() }
        XCTAssertThrowsError(try client.perform(method: "GET", url: "http://127.0.0.1:\(slow.port)/", headers: [:], body: nil, hosts: ["127.0.0.1"], timeout: 0.05))
    }
    func testMethodPathAndPlaceholderRestrictions() throws {
        let server = LocalHTTPFixture(); try server.start(); defer { server.stop() }
        let store = try store()
        try store.authorizeRules([store.items[0].id]) { $0.allowedMethods = ["POST"]; $0.allowedPathPrefixes = ["/v1"] }
        let broker = broker(store)
        XCTAssertTrue(broker.handle(request(server, path: "/v1/messages"))["ok"] as? Bool ?? false)
        for path in ["/v10/secret", "/v1/../other", "/{{HTTP_TOKEN}}", "/%7B%7BHTTP_TOKEN%7D%7D"] {
            XCTAssertFalse(broker.handle(request(server, path: path))["ok"] as? Bool ?? true, path)
        }
        var args = request(server, path: "/v1")["args"] as! [String: Any]; args["method"] = "DELETE"
        XCTAssertFalse(broker.handle(["op": "http", "args": args])["ok"] as? Bool ?? true)
        let plan = try HTTPPlan(["method": "POST", "url": "http://127.0.0.1:\(server.port)/?key={{K}}", "body": ["value": "{{K}}"]], client: SecureHTTPClient(testAllowLoopback: true))
        let secret = "fake\"quoted&value"
        let (url, _, body) = try plan.materialized(["K": secret])
        XCTAssertEqual(URLComponents(string: url)?.queryItems?.first?.value, secret)
        XCTAssertEqual((try JSONSerialization.jsonObject(with: body!) as? [String: String])?["value"], secret)
    }
    func testFirstKeyHostRequiresFreshPresenceAndLockRevokesIt() throws {
        let server = LocalHTTPFixture(); try server.start(); defer { server.stop() }
        var calls = 0
        let broker = broker(try store(hosts: ["127.0.0.1", "localhost"]), fresh: { _ in calls += 1 })
        XCTAssertTrue(broker.handle(request(server))["ok"] as? Bool ?? false)
        XCTAssertTrue(broker.handle(request(server))["ok"] as? Bool ?? false)
        XCTAssertEqual(calls, 1)
        var args = request(server)["args"] as! [String: Any]
        args["url"] = "http://localhost:\(server.port)/"
        XCTAssertTrue(broker.handle(["op": "http", "args": args])["ok"] as? Bool ?? false)
        XCTAssertEqual(calls, 2)
        Vault.shared.lockNow()
        XCTAssertTrue(broker.handle(request(server))["ok"] as? Bool ?? false)
        XCTAssertEqual(calls, 3)
    }
    func testRuleTamperingCipherSwapAndLegacyMigration() throws {
        let store = try store()
        let original = store.items[0]
        var tampered = original; tampered.allowHosts = ["attacker.example"]
        XCTAssertFalse(Policies.rulesVerified(tampered))
        var moved = original; moved.id = UUID()
        XCTAssertFalse(Policies.rulesVerified(moved)); XCTAssertThrowsError(try store.secretValue(moved))
        XCTAssertThrowsError(try Vault.shared.decrypt(original.cipher!)) // v3 without UUID cannot hit cache
        let old = try Vault.shared.encryptLegacyForTests("FAKE_LEGACY_0123456789")
        let legacy = Item(kind: .secret, name: "LEGACY", service: "Anthropic", type: "test", fingerprint: "fake", preview: "", cipher: old)
        store.add(legacy)
        XCTAssertFalse(Policies.rulesVerified(legacy))
        try store.authorizeRules([legacy.id])
        let upgraded = try XCTUnwrap(store.item(id: legacy.id))
        XCTAssertTrue(upgraded.cipher!.hasPrefix("v3:")); XCTAssertTrue(Policies.rulesVerified(upgraded))
        XCTAssertEqual(try store.secretValue(upgraded), "FAKE_LEGACY_0123456789")
        var copied = upgraded; copied.id = UUID()
        XCTAssertThrowsError(try store.secretValue(copied))
        // Rollback de item isolado é detectado pelo manifesto mais recente.
        let manifestURL = LockdPaths.support.appendingPathComponent("rules-manifest.json")
        let oldManifest = try Data(contentsOf: manifestURL)
        try store.authorizeRules([original.id]) { $0.allowHosts = ["api.anthropic.com"] }
        XCTAssertFalse(Policies.rulesVerified(original))
        try oldManifest.write(to: manifestURL, options: .atomic)
        XCTAssertFalse(Policies.rulesVerified(original)) // contador em memória recusa rollback conjunto na sessão
    }
    func testPublicKeyMismatchAndMissingBlobStopEncryption() throws {
        _ = try store()
        let fakePublic = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let publicFile = LockdPaths.support.appendingPathComponent("se-key.pub")
        try fakePublic.write(to: publicFile)
        XCTAssertThrowsError(try Vault.shared.encrypt("FAKE_NEW", itemID: UUID()))
        XCTAssertNotNil(Vault.shared.keyIssue)
        try FileManager.default.removeItem(at: publicFile)
        let softwareBlob = LockdPaths.support.appendingPathComponent(".test-p256")
        try FileManager.default.removeItem(at: softwareBlob)
        XCTAssertThrowsError(try Vault.shared.encrypt("FAKE_NEW", itemID: UUID()))
        XCTAssertFalse(FileManager.default.fileExists(atPath: softwareBlob.path))
    }
    func testProgramsAreOffByDefaultEvenWithSignedRules() throws {
        let broker = broker(try store())
        XCTAssertFalse(broker.handle(["op": "capabilities"])["allow_programs"] as? Bool ?? true)
        let result = broker.handle(["op": "run", "args": ["argv": ["curl", "https://example.com"], "names": ["HTTP_TOKEN"]]])
        XCTAssertFalse(result["ok"] as? Bool ?? true)
        XCTAssertTrue((result["text"] as? String ?? "").contains("programs are disabled"))
    }
    func testSlowHTTPDoesNotExposeFakeInProcessArgumentsOrOpenFiles() throws {
        let server = LocalHTTPFixture { request in (200, [:], Data(request.utf8), 1) }
        try server.start(); defer { server.stop() }
        let broker = broker(try store()), finished = expectation(description: "slow HTTP")
        let payload = request(server)
        DispatchQueue.global().async {
            let result = broker.handle(payload)
            XCTAssertTrue(result["ok"] as? Bool ?? false)
            XCTAssertFalse((result["text"] as? String ?? "").contains(self.fake))
            finished.fulfill()
        }
        XCTAssertEqual(server.received.wait(timeout: .now() + 3), .success)
        func observe(_ executable: String, _ arguments: [String]) throws -> String {
            let process = Process(), pipe = Pipe()
            process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
            process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
            try process.run(); let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
            XCTAssertEqual(process.terminationStatus, 0)
            return String(decoding: data, as: UTF8.self)
        }
        XCTAssertFalse(try observe("/bin/ps", ["-ww", "-p", String(getpid()), "-o", "pid,ppid,args"]).contains(fake))
        XCTAssertFalse(try observe("/usr/sbin/lsof", ["-nP", "-p", String(getpid())]).contains(fake))
        wait(for: [finished], timeout: 6)
    }
    func testMCPHidesProgramsUnlessBrokerEnablesThem() throws {
        let ipc = URL(fileURLWithPath: "/tmp/lockd-mcp-" + UUID().uuidString.prefix(8))
        try FileManager.default.createDirectory(at: ipc, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: ipc); setenv("LOCKD_HOME", home.path, 1) }
        setenv("LOCKD_HOME", ipc.path, 1)
        let executable = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent(".build/debug/lockdctl")
        func listing() throws -> [String] {
            let process = Process(), input = Pipe(), output = Pipe()
            process.executableURL = executable; process.arguments = ["mcp"]
            process.standardInput = input; process.standardOutput = output; process.standardError = FileHandle.nullDevice
            try process.run()
            try input.fileHandleForWriting.write(contentsOf: Data("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n".utf8))
            try input.fileHandleForWriting.close()
            let data = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
            XCTAssertEqual(process.terminationStatus, 0)
            let response = try JSONSerialization.jsonObject(with: data) as! [String: Any]
            return ((response["result"] as? [String: Any])?["tools"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
        }
        XCTAssertFalse(try listing().contains("lockd_run")) // sem broker: fail closed, não abre app
        XCTAssertTrue(try listing().contains("lockd_http"))
        for enabled in [false, true] {
            let path = LockdPaths.socketFile.path
            let listener = socket(AF_UNIX, SOCK_STREAM, 0)
            XCTAssertGreaterThanOrEqual(listener, 0)
            var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
            withUnsafeMutablePointer(to: &address.sun_path) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: 104) { _ = strncpy($0, path, 103) }
            }
            let bound = withUnsafePointer(to: &address) { ptr in ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
            XCTAssertEqual(bound, 0); XCTAssertEqual(listen(listener, 1), 0)
            let replied = DispatchSemaphore(value: 0)
            DispatchQueue.global().async {
                let client = accept(listener, nil, nil)
                if client >= 0 {
                    _ = BrokerWire.readLine(client)
                    BrokerWire.write(client, ["ok": true, "allow_programs": enabled]); close(client)
                }
                replied.signal()
            }
            XCTAssertEqual(try listing().contains("lockd_run"), enabled)
            XCTAssertEqual(replied.wait(timeout: .now() + 3), .success)
            close(listener); unlink(path)
        }
    }
    func testProductionHTTPSUsesPinnedTunnelWithNormalTLS() throws {
        // Único teste externo novo: chave FALSA, nenhuma conta/credencial real.
        let response = try SecureHTTPClient().perform(method: "GET", url: "https://api.anthropic.com/v1/models",
            headers: ["x-api-key": "FAKE_HTTP_TEST_ONLY_0123456789"], body: nil, hosts: ["api.anthropic.com"], timeout: 15)
        XCTAssertTrue((100...599).contains(response.status))
    }
}

private final class LocalHTTPFixture: @unchecked Sendable {
    typealias Reply = (Int, [String: String], Data, TimeInterval)
    private let queue = DispatchQueue(label: "lockd.test.http")
    private let lock = NSLock()
    private var listener: NWListener?
    private var connections: [NWConnection] = []
    private var captured: [String] = []
    private let handler: (String) -> Reply
    let received = DispatchSemaphore(value: 0)
    private(set) var port: UInt16 = 0
    var requests: [String] { lock.lock(); defer { lock.unlock() }; return captured }
    init(_ handler: @escaping (String) -> Reply = { _ in (200, [:], Data("{\"ok\":true}".utf8), 0) }) { self.handler = handler }
    func start() throws {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let listener = try NWListener(using: params), ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in if case .ready = state { ready.signal() } }
        listener.newConnectionHandler = { connection in
            self.lock.lock(); self.connections.append(connection); self.lock.unlock()
            connection.start(queue: self.queue); self.read(connection, Data())
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 3) == .success, let port = listener.port else { throw HTTPFailure(message: "Fixture did not start") }
        self.port = port.rawValue; self.listener = listener
    }
    func stop() {
        listener?.cancel()
        lock.lock(); let connections = self.connections; self.connections = []; lock.unlock()
        connections.forEach { $0.cancel() }
    }
    private func read(_ connection: NWConnection, _ prefix: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { chunk, _, done, error in
            var data = prefix; if let chunk { data.append(chunk) }
            if let split = data.range(of: Data("\r\n\r\n".utf8)) {
                let head = String(decoding: data[..<split.lowerBound], as: UTF8.self)
                let length = head.components(separatedBy: "\r\n").first { $0.lowercased().hasPrefix("content-length:") }
                    .flatMap { Int($0.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)) } ?? 0
                if data.count - split.upperBound >= length {
                    let request = String(decoding: data, as: UTF8.self)
                    self.lock.lock(); self.captured.append(request); self.lock.unlock(); self.received.signal()
                    let (status, headers, body, delay) = self.handler(request)
                    var fields = headers; if fields["Content-Type"] == nil { fields["Content-Type"] = "application/json" }
                    var head = "HTTP/1.1 \(status) Test\r\nContent-Length: \(body.count)\r\nConnection: close\r\n"
                    for (name, value) in fields { head += "\(name): \(value)\r\n" }
                    let response = Data((head + "\r\n").utf8) + body
                    self.queue.asyncAfter(deadline: .now() + delay) {
                        connection.send(content: response, completion: .contentProcessed { _ in connection.cancel() })
                    }
                    return
                }
            }
            if done || error != nil || data.count > 512 * 1024 { connection.cancel() }
            else { self.read(connection, data) }
        }
    }
}
