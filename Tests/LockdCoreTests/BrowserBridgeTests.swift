import XCTest
import Darwin
@testable import LockdCore

/// A "extensão" aqui é um cliente falso do socket. Prova: o valor vai SÓ para a extensão atestada, nunca para o texto que o agente recebe.
final class BrowserBridgeTests: XCTestCase {
    private let fake = "sk_" + "live_FAKEbrowserKEY0123456789abcdef"
    private var home: String!
    private var previous: String?
    private var server: BrokerServer?
    private var broker: Broker!
    private var store: Store!
    private var freshCalls = 0

    override func setUpWithError() throws {
        previous = ProcessInfo.processInfo.environment["LOCKD_HOME"]
        home = "/tmp/lk-br-\(UUID().uuidString.prefix(8))"
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        setenv("LOCKD_HOME", home, 1)
        Vault.shared.lockNow(); BrokerSettings.programsEnabled = false
        store = Store()
        broker = Broker(store: store, freshUnlock: { [unowned self] _ in freshCalls += 1 })
        server = BrokerServer(broker: broker)
        try server?.start()
        BrowserBridge.peerCheck = { _ in true }
    }

    override func tearDownWithError() throws {
        BrowserBridge.peerCheck = { BrowserPeer.isBrowser(fd: $0) }
        Vault.shared.lockNow()
        try? FileManager.default.removeItem(atPath: home)
        if let previous { setenv("LOCKD_HOME", previous, 1) } else { unsetenv("LOCKD_HOME") }
    }

    private func addKey(hosts: [String]) throws {
        let item = try store.saveSecret(Detection(envName: "STRIPE_SECRET_KEY", service: "Stripe", type: "Secret key", value: fake, confident: true), project: "Shop", source: "t").item
        try store.authorizeRules([item.id]) { $0.allowHosts = hosts }
    }

    /// Extensão falsa: anexa e responde aos comandos com `handler`. Guarda tudo que recebeu.
    final class FakeExtension: @unchecked Sendable {
        let fd: Int32
        let reader: LineReader
        var received: [[String: Any]] = []
        init?() {
            guard let fd = BrokerClient.openStream(launchIfNeeded: false) else { return nil }
            self.fd = fd; reader = LineReader(fd)
            BrokerWire.write(fd, ["op": "browser_attach"])
        }
        func hello() -> [String: Any]? { reader.next().flatMap { try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any] } }
        func serve(_ handler: @escaping ([String: Any]) -> [String: Any]) {
            Thread.detachNewThread { [self] in
                while let l = reader.next(), let m = try? JSONSerialization.jsonObject(with: Data(l.utf8)) as? [String: Any] {
                    received.append(m)
                    if m["t"] as? String == "cmd" {
                        var r = handler(m); r["t"] = "result"; r["id"] = m["id"]
                        BrokerWire.write(fd, r)
                    }
                }
            }
        }
        func close() { Darwin.close(fd) }
    }

    private func attached(_ handler: @escaping ([String: Any]) -> [String: Any]) throws -> FakeExtension {
        let ext = try XCTUnwrap(FakeExtension())
        XCTAssertEqual(ext.hello()?["text"] as? String, "attached")
        ext.serve(handler)
        for _ in 0..<50 where !broker.bridge.isConnected { Thread.sleep(forTimeInterval: 0.02) }
        return ext
    }

    func testFillSendsValueOnlyToTheExtensionAndAgentGetsNoValue() throws {
        try addKey(hosts: ["dashboard.stripe.com"])
        var seen: [String: Any]?
        let ext = try attached { cmd in seen = cmd; return ["ok": true, "text": "Filled."] }
        defer { ext.close() }
        let r = broker.handle(["op": "browser_fill", "args": ["name": "STRIPE_SECRET_KEY", "host": "dashboard.stripe.com", "selector": "#key", "project": "Shop"]])
        XCTAssertEqual(r["ok"] as? Bool, true, "\(r)")
        XCTAssertEqual(seen?["value"] as? String, fake, "a extensão recebe o valor")
        XCTAssertEqual(seen?["host"] as? String, "dashboard.stripe.com")
        XCTAssertFalse(String(describing: r).contains(fake), "o agente nunca recebe o valor")
        let audit = Audit.recent(limit: 5).map { "\($0.command ?? "") \($0.detail ?? "")" }.joined()
        XCTAssertFalse(audit.contains(fake))
        XCTAssertEqual(freshCalls, 1)
        // segundo preenchimento do mesmo par chave+host na mesma sessão não pede de novo
        _ = broker.handle(["op": "browser_fill", "args": ["name": "STRIPE_SECRET_KEY", "host": "dashboard.stripe.com", "selector": "#key", "project": "Shop"]])
    }

    func testHostWithoutSignedRuleIsDeniedAndNothingIsSent() throws {
        try addKey(hosts: ["api.stripe.com"])
        var sent = false
        let ext = try attached { _ in sent = true; return ["ok": true] }
        defer { ext.close() }
        for host in ["dashboard.stripe.com", "evil.example.com", "api.stripe.com.evil.com"] {
            let r = broker.handle(["op": "browser_fill", "args": ["name": "STRIPE_SECRET_KEY", "host": host, "selector": "#k", "project": "Shop"]])
            XCTAssertEqual(r["ok"] as? Bool, false, host)
            XCTAssertTrue((r["text"] as? String ?? "").hasPrefix("Denied"), host)
        }
        XCTAssertFalse(sent)
        XCTAssertEqual(freshCalls, 0)
    }

    func testUnsignedKeyAndBadArgumentsAreDenied() throws {
        _ = try store.saveSecret(Detection(envName: "STRIPE_SECRET_KEY", service: "Stripe", type: "Secret key", value: fake, confident: true), project: "Shop", source: "t")
        let ext = try attached { _ in ["ok": true] }
        defer { ext.close() }
        func call(_ a: [String: Any]) -> [String: Any] { broker.handle(["op": "browser_fill", "args": a]) }
        XCTAssertEqual(call(["name": "STRIPE_SECRET_KEY", "host": "dashboard.stripe.com", "selector": "#k"])["ok"] as? Bool, false)
        XCTAssertEqual(call(["name": "x y", "host": "dashboard.stripe.com", "selector": "#k"])["ok"] as? Bool, false)
        XCTAssertEqual(call(["name": "STRIPE_SECRET_KEY", "host": "*.stripe.com", "selector": "#k"])["ok"] as? Bool, false)
        XCTAssertEqual(call(["name": "STRIPE_SECRET_KEY", "host": "dashboard.stripe.com", "selector": ""])["ok"] as? Bool, false)
    }

    func testFillWithoutExtensionIsDeniedBeforeAnyPrompt() throws {
        try addKey(hosts: ["dashboard.stripe.com"])
        let r = broker.handle(["op": "browser_fill", "args": ["name": "STRIPE_SECRET_KEY", "host": "dashboard.stripe.com", "selector": "#k", "project": "Shop"]])
        XCTAssertEqual(r["ok"] as? Bool, false)
        XCTAssertEqual(freshCalls, 0)
    }

    func testNonBrowserPeerCannotAttach() throws {
        BrowserBridge.peerCheck = { BrowserPeer.isBrowser(fd: $0) }      // verificação REAL: este processo de teste não é filho de um navegador
        try addKey(hosts: ["dashboard.stripe.com"])
        let ext = try XCTUnwrap(FakeExtension())
        let first = ext.hello()
        XCTAssertEqual(first?["ok"] as? Bool, false)
        XCTAssertFalse(broker.bridge.isConnected)
        let r = broker.handle(["op": "browser_fill", "args": ["name": "STRIPE_SECRET_KEY", "host": "dashboard.stripe.com", "selector": "#k", "project": "Shop"]])
        XCTAssertEqual(r["ok"] as? Bool, false)
        ext.close()
    }

    func testUserSaveFromPageStoresKeyWithoutRulesAndReturnsMaskedMessage() throws {
        let ext = try attached { _ in ["ok": true] }
        defer { ext.close() }
        broker.currentProject = { "Shop" }
        BrokerWire.write(ext.fd, ["t": "capture", "cid": "c1", "host": "dashboard.stripe.com", "candidates": [fake]])
        for _ in 0..<100 where ext.received.isEmpty { Thread.sleep(forTimeInterval: 0.02) }
        let reply = ext.received.first
        XCTAssertEqual(reply?["t"] as? String, "captured")
        XCTAssertEqual(reply?["cid"] as? String, "c1")
        XCTAssertFalse(String(describing: reply).contains(fake))
        let item = try XCTUnwrap(store.items.first { $0.name == "STRIPE_SECRET_KEY" })
        XCTAssertEqual(item.project, "Shop")
        XCTAssertFalse(Policies.rulesVerified(item), "chave capturada nasce sem permissão para o agente")
        XCTAssertFalse(item.preview.contains("FAKE"))
    }

    func testAgentCaptureHarvestsFromPageWithoutSeeingValue() throws {
        let ext = try attached { cmd in
            XCTAssertEqual(cmd["kind"] as? String, "harvest")
            return ["ok": true, "host": "dashboard.stripe.com", "candidates": [self.fake]]
        }
        defer { ext.close() }
        let r = broker.handle(["op": "browser_capture", "args": ["project": "Shop", "name": "STRIPE_SECRET_KEY"]])
        XCTAssertEqual(r["ok"] as? Bool, true, "\(r)")
        XCTAssertFalse(String(describing: r).contains(fake))
        XCTAssertTrue(store.items.contains { $0.name == "STRIPE_SECRET_KEY" && $0.project == "Shop" })
    }

    func testExtensionDisconnectFailsPendingFill() throws {
        try addKey(hosts: ["dashboard.stripe.com"])
        let ext = try XCTUnwrap(FakeExtension()); _ = ext.hello()
        Thread.detachNewThread { _ = ext.reader.next(); ext.close() }   // fecha ao receber o comando
        for _ in 0..<50 where !broker.bridge.isConnected { Thread.sleep(forTimeInterval: 0.02) }
        let r = broker.handle(["op": "browser_fill", "args": ["name": "STRIPE_SECRET_KEY", "host": "dashboard.stripe.com", "selector": "#k", "project": "Shop"]])
        XCTAssertEqual(r["ok"] as? Bool, false)
        XCTAssertFalse(String(describing: r).contains(fake))
    }

    /// O lockdctl REAL como host de mensagens nativas (quadros de 4 bytes + JSON), falando com o broker real.
    func testRealNativeHostRelaysFramesBothWays() throws {
        let ctl = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("lockdctl")
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: ctl.path), "lockdctl não foi construído")
        try addKey(hosts: ["dashboard.stripe.com"])
        let p = Process(); p.executableURL = ctl; p.arguments = ["chrome-extension://aplenjjnldnepbgelmlmnehcajacbpod/"]
        p.environment = ["LOCKD_HOME": home, "PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory()]
        let inPipe = Pipe(), outPipe = Pipe(); p.standardInput = inPipe; p.standardOutput = outPipe; p.standardError = FileHandle.nullDevice
        try p.run(); defer { p.terminate() }
        func frame() -> [String: Any]? {
            let h = outPipe.fileHandleForReading
            guard let hdr = try? h.read(upToCount: 4), hdr.count == 4 else { return nil }
            let n = Int(hdr.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })
            guard let body = try? h.read(upToCount: n) else { return nil }
            return try? JSONSerialization.jsonObject(with: body) as? [String: Any]
        }
        XCTAssertEqual(frame()?["text"] as? String, "attached")
        for _ in 0..<100 where !broker.bridge.isConnected { Thread.sleep(forTimeInterval: 0.02) }
        // agente -> extensão: o comando chega como quadro nativo; a resposta volta ao broker
        let q = DispatchQueue.global()
        var answer: [String: Any]?
        let done = expectation(description: "fill")
        q.async {
            answer = self.broker.handle(["op": "browser_fill", "args": ["name": "STRIPE_SECRET_KEY", "host": "dashboard.stripe.com", "selector": "#k", "project": "Shop"]])
            done.fulfill()
        }
        let cmd = try XCTUnwrap(frame())
        XCTAssertEqual(cmd["kind"] as? String, "fill")
        XCTAssertEqual(cmd["value"] as? String, fake)
        let reply = try JSONSerialization.data(withJSONObject: ["t": "result", "id": cmd["id"] as Any, "ok": true, "text": "Filled."])
        var len = UInt32(reply.count)
        inPipe.fileHandleForWriting.write(Data(bytes: &len, count: 4) + reply)
        wait(for: [done], timeout: 10)
        XCTAssertEqual(answer?["ok"] as? Bool, true, "\(String(describing: answer))")
        XCTAssertFalse(String(describing: answer).contains(fake))
    }
}
