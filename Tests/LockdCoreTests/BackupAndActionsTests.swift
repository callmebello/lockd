import XCTest
@testable import LockdCore

final class BackupAndActionsTests: XCTestCase {
    private var root: URL!
    private var previous: String?
    private let keyA = "sk-ant-api03-FAKEbackupKEY0123456789abcdefGHIJklmnopQRS"

    private func useHome(_ name: String) throws {
        let h = root.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: h, withIntermediateDirectories: true)
        setenv("LOCKD_HOME", h.path, 1)
    }
    override func setUpWithError() throws {
        previous = ProcessInfo.processInfo.environment["LOCKD_HOME"]
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lockd-bk-\(UUID().uuidString)")
        try useHome("a")
    }
    override func tearDownWithError() throws {
        unsetenv("LOCKD_VERCEL_BASE")
        try? FileManager.default.removeItem(at: root)
        if let previous { setenv("LOCKD_HOME", previous, 1) } else { unsetenv("LOCKD_HOME") }
    }

    // MARK: backup

    private func seed(_ store: Store) throws {
        _ = try store.saveSecret(Detection(envName: "ANTHROPIC_API_KEY", service: "Anthropic", type: "API key", value: keyA, confident: true), project: "Priva", source: "t")
        _ = try store.saveSecret(Detection(envName: "DB_PASSWORD", service: "Supabase", type: "Secret", value: "tr0ub4dor&3-horse", confident: true, note: "banco do Priva"), project: "Priva", source: "t")
        store.setProjectColor("Priva", index: 4)
        store.setLink(ProjectLink(path: "/x/priva", vercelProjectId: "prj_1"), for: "Priva")
    }

    func testBackupRoundTripAcrossMacsKeepsEverythingAndHidesValues() throws {
        let store = Store(); try seed(store)
        let file = root.appendingPathComponent("lockd.lockdbackup")
        XCTAssertEqual(try Backup.export(store: store, passphrase: "uma frase longa e boa", to: file), 2)
        let text = try String(contentsOf: file, encoding: .utf8)
        for v in [keyA, "tr0ub4dor", "ANTHROPIC_API_KEY", "Priva"] { XCTAssertFalse(text.contains(v), "o arquivo é só texto cifrado: \(v)") }
        XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int), 0o600)

        try useHome("b")                                   // outro Mac: outra chave do cofre
        let other = Store()
        XCTAssertTrue(other.items.isEmpty)
        let r = try Backup.importBackup(from: file, passphrase: "uma frase longa e boa", store: other)
        XCTAssertEqual(r.keys, 2)
        let byName = Dictionary(uniqueKeysWithValues: other.items.map { ($0.name, $0) })
        XCTAssertEqual(try other.secretValue(byName["ANTHROPIC_API_KEY"]!), keyA)
        XCTAssertEqual(try other.secretValue(byName["DB_PASSWORD"]!), "tr0ub4dor&3-horse")
        XCTAssertEqual(byName["DB_PASSWORD"]?.project, "Priva"); XCTAssertEqual(byName["DB_PASSWORD"]?.note, "banco do Priva")
        XCTAssertNil(byName["ANTHROPIC_API_KEY"]?.ruleSignature, "regras NÃO vão no backup: assinar de novo no Mac novo")
        XCTAssertEqual(other.projectColors["Priva"], 4); XCTAssertEqual(other.link(for: "Priva")?.vercelProjectId, "prj_1")

        let again = try Backup.importBackup(from: file, passphrase: "uma frase longa e boa", store: other)
        XCTAssertEqual(again.keys, 1, "a chave de provedor não duplica; senha fraca entra de novo (sem hash) — por isso o 1")
    }

    func testBackupRejectsWeakWrongAndTamperedInputs() throws {
        let store = Store(); try seed(store)
        let file = root.appendingPathComponent("b.lockdbackup")
        XCTAssertThrowsError(try Backup.export(store: store, passphrase: "curta", to: file)) { XCTAssertEqual($0 as? BackupError, .weakPassphrase) }
        try Backup.export(store: store, passphrase: "passphrase-bem-longa-123", to: file)

        XCTAssertThrowsError(try Backup.importBackup(from: file, passphrase: "passphrase-errada-123", store: Store())) { XCTAssertEqual($0 as? BackupError, .wrongPassphraseOrCorrupt) }

        var env = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: Any]
        var box = Data(base64Encoded: env["box"] as! String)!; box[box.count / 2] ^= 0xFF
        env["box"] = box.base64EncodedString()
        let tampered = root.appendingPathComponent("t.lockdbackup")
        try JSONSerialization.data(withJSONObject: env).write(to: tampered)
        XCTAssertThrowsError(try Backup.importBackup(from: tampered, passphrase: "passphrase-bem-longa-123", store: Store())) { XCTAssertEqual($0 as? BackupError, .wrongPassphraseOrCorrupt) }

        env["box"] = Data(base64Encoded: (try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: Any])["box"] as! String)!.base64EncodedString()
        env["iterations"] = 10                              // enfraquecer o KDF ou travar o app com um valor absurdo
        let weak = root.appendingPathComponent("w.lockdbackup"); try JSONSerialization.data(withJSONObject: env).write(to: weak)
        XCTAssertThrowsError(try Backup.importBackup(from: weak, passphrase: "passphrase-bem-longa-123", store: Store())) { XCTAssertEqual($0 as? BackupError, .unsupported) }
        env["iterations"] = 2_000_000_000
        try JSONSerialization.data(withJSONObject: env).write(to: weak)
        XCTAssertThrowsError(try Backup.importBackup(from: weak, passphrase: "x", store: Store()))
        try useHome("empty")
        XCTAssertThrowsError(try Backup.export(store: Store(), passphrase: "passphrase-bem-longa-123", to: root.appendingPathComponent("e"))) { XCTAssertEqual($0 as? BackupError, .nothingToExport) }
    }

    // MARK: busca por cor

    func testColorSearch() {
        XCTAssertTrue(ColorMatch.isColorToken("#22d3ee")); XCTAssertTrue(ColorMatch.isColorToken("#2de"))
        XCTAssertFalse(ColorMatch.isColorToken("22d3ee")); XCTAssertFalse(ColorMatch.isColorToken("#zzz")); XCTAssertFalse(ColorMatch.isColorToken("#12"))
        func item(_ colors: [String]) -> Item { Item(kind: .asset, name: "logo.svg", type: "Logo", fingerprint: "f", preview: "", colors: colors) }
        XCTAssertTrue(ColorMatch.matches(item(["#22D3EE", "#FFFFFF"]), token: "#22d3ee"))
        XCTAssertTrue(ColorMatch.matches(item(["#28D0E8"]), token: "#22d3ee"), "parecida")
        XCTAssertFalse(ColorMatch.matches(item(["#F97316"]), token: "#22d3ee"), "laranja não casa com ciano")
        XCTAssertFalse(ColorMatch.matches(item([]), token: "#22d3ee"))
    }

    // MARK: lockdctl add

    func testAddSecretStartsWithoutAgentAccessAndNeverEchoesValue() throws {
        let store = Store(); let broker = Broker(store: store)
        let r = broker.handle(["op": "add_secret", "args": ["value": keyA, "project": "Priva"]])
        XCTAssertTrue(r["ok"] as? Bool ?? false, "\(r)")
        XCTAssertFalse((r["text"] as? String ?? "").contains(keyA))
        XCTAssertEqual(store.items.first?.name, "ANTHROPIC_API_KEY")
        XCTAssertFalse(Policies.rulesVerified(store.items[0]), "chave adicionada por linha de comando nasce sem regra: o agente não a usa")
        XCTAssertFalse(broker.handle(["op": "add_secret", "args": ["value": "senhaqualquer1"]])["ok"] as? Bool ?? true, "valor não reconhecido exige --name")
        XCTAssertTrue(broker.handle(["op": "add_secret", "args": ["value": "senhaqualquer1", "name": "DB_PASSWORD"]])["ok"] as? Bool ?? false)
        XCTAssertFalse(broker.handle(["op": "add_secret", "args": ["value": "x", "name": "not valid!"]])["ok"] as? Bool ?? true)
        XCTAssertTrue((broker.handle(["op": "add_secret", "args": ["value": keyA]])["text"] as? String ?? "").contains("already"))
        let audit = (try? String(contentsOf: LockdPaths.auditFile, encoding: .utf8)) ?? ""
        XCTAssertFalse(audit.contains(keyA) || audit.contains("senhaqualquer1"))
    }

    func testAnUnsignedLookalikeCannotShadowASignedKey() throws {
        let store = Store(); let broker = Broker(store: store)
        let real = try store.saveSecret(Detection(envName: "ANTHROPIC_API_KEY", service: "Anthropic", type: "API key", value: keyA, confident: true), project: "Priva", source: "t").item
        try store.authorizeRules([real.id]) { $0.allowHosts = ["api.anthropic.com"] }
        _ = broker.handle(["op": "add_secret", "args": ["value": "sk-ant-api03-IMPOSTOR0123456789abcdefGHIJklmnopQRSTUV", "name": "ANTHROPIC_API_KEY", "project": "Priva"]])
        XCTAssertEqual(store.items.filter { $0.name == "ANTHROPIC_API_KEY" }.count, 2)
        let picked = broker.pick(project: "Priva", names: ["ANTHROPIC_API_KEY"])
        XCTAssertEqual(picked.first?.id, real.id, "a chave com regra assinada vence a mais nova sem assinatura")
    }

    // MARK: enviar à Vercel (ação do usuário)

    private func vercelSetup(_ prompts: Prompts, approve: Bool = true) throws -> (Store, Broker) {
        let store = Store()
        _ = try store.saveSecret(Detection(envName: "VERCEL_TOKEN", service: "Vercel", type: "Token", value: "vercel_FAKE_user_token_0123456789ABCDEF", confident: true), project: "Priva", source: "t")
        _ = try store.saveSecret(Detection(envName: "ANTHROPIC_API_KEY", service: "Anthropic", type: "API key", value: keyA, confident: true), project: "Priva", source: "t")
        _ = try store.saveSecret(Detection(envName: "DB_PASSWORD", service: "Supabase", type: "Secret", value: "tr0ub4dor&3-horse", confident: true), project: "Priva", source: "t")
        let broker = Broker(store: store, freshUnlock: { prompts.add($0); if !approve { throw Vault.VaultError.denied("no") } })
        broker.httpClient = SecureHTTPClient(testAllowLoopback: true)
        return (store, broker)
    }

    func testSendToVercelUsesOneTouchIDAndNeedsNoAgentRules() throws {
        let fake = FakeAPIServer { _ in #"{"ok":true}"# }; try fake.start(); defer { fake.stop() }
        setenv("LOCKD_VERCEL_BASE", "http://127.0.0.1:\(fake.port)", 1)
        let prompts = Prompts(); let (_, broker) = try vercelSetup(prompts)
        let results = try broker.sendToVercel(project: "Priva", names: ["ANTHROPIC_API_KEY", "DB_PASSWORD"], vercelProject: "prj_1", team: "team_t", targets: ["production", "preview"])
        XCTAssertEqual(results.map(\.ok), [true, true], "\(results)")
        XCTAssertEqual(prompts.all.count, 1, "um Touch ID para o envio inteiro")
        XCTAssertTrue(prompts.all[0].contains("Send 2 keys to Vercel (prj_1)"), prompts.all[0])
        let deadline = Date().addingTimeInterval(3)
        while fake.requests.count < 2, Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
        let all = fake.requests.joined()
        XCTAssertTrue(all.contains("/v10/projects/prj_1/env") && all.contains("teamId=team_t"))
        XCTAssertTrue(all.contains(keyA) && all.contains("tr0ub4dor&3-horse"), "a Vercel recebe os valores reais")
        XCTAssertTrue(all.contains("Bearer vercel_FAKE_user_token"))
        XCTAssertTrue(all.contains("production") && all.contains("preview") && !all.contains("development"))
        XCTAssertFalse(results.map(\.detail).joined().contains(keyA))
        let audit = (try? String(contentsOf: LockdPaths.auditFile, encoding: .utf8)) ?? ""
        XCTAssertTrue(audit.contains("vercel_push")); XCTAssertFalse(audit.contains(keyA) || audit.contains("tr0ub4dor"))
    }

    func testSendToVercelRefusesBadInputAndRespectsDeniedTouchID() throws {
        let fake = FakeAPIServer { _ in #"{"ok":true}"# }; try fake.start(); defer { fake.stop() }
        setenv("LOCKD_VERCEL_BASE", "http://127.0.0.1:\(fake.port)", 1)
        let denied = Prompts(); let (_, broker) = try vercelSetup(denied, approve: false)
        XCTAssertThrowsError(try broker.sendToVercel(project: "Priva", names: ["ANTHROPIC_API_KEY"], vercelProject: "prj_1", team: nil, targets: ["production"]))
        XCTAssertTrue(fake.requests.isEmpty, "sem aprovação nada sai")
        XCTAssertThrowsError(try broker.sendToVercel(project: "Priva", names: ["ANTHROPIC_API_KEY"], vercelProject: "../x", team: nil, targets: ["production"]))
        XCTAssertThrowsError(try broker.sendToVercel(project: "Priva", names: ["ANTHROPIC_API_KEY"], vercelProject: "prj_1", team: nil, targets: ["prod"]))
        XCTAssertThrowsError(try broker.sendToVercel(project: "Priva", names: ["NOPE"], vercelProject: "prj_1", team: nil, targets: ["production"]))
        XCTAssertThrowsError(try Broker(store: Store(), freshUnlock: { _ in }).sendToVercel(project: "Priva", names: ["X"], vercelProject: "prj_1", team: nil, targets: ["production"]) , "sem token")
        XCTAssertTrue(denied.all.isEmpty || fake.requests.isEmpty)
    }
}
