import XCTest
import Darwin
@testable import LockdCore

/// Reproduções de vulnerabilidades conhecidas, com valores e arquivos descartáveis.
/// Os casos tratados na Fase 1 agora exigem recusa. Os demais continuam caracterizando
/// limites abertos (regras, ciphertext, redactor, wire) até a fase correspondente.
final class SecurityReviewTests: XCTestCase {
    private var home: URL!
    private let fake = "FAKE_SECURITY_REVIEW_0123456789abcdef"

    override func setUpWithError() throws {
        home = FileManager.default.temporaryDirectory.appendingPathComponent("lockd-review-\(UUID().uuidString)")
        setenv("LOCKD_HOME", home.path, 1)
        Vault.shared.lockNow(); BrokerSettings.programsEnabled = true
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        Vault.shared.lockNow(); BrokerSettings.programsEnabled = false
        try? FileManager.default.removeItem(at: home)
        unsetenv("LOCKD_HOME")
    }

    private func makeStore(service: String = "GitHub") throws -> Store {
        let s = Store()
        try s.saveSecret(Detection(envName: "REVIEW_TOKEN", service: service, type: "test", value: fake, confident: true), project: "Review", source: "security-test")
        try s.authorizeRules(s.items.map(\.id))
        return s
    }

    func testTenantHostWildcardsPermitAttackerDestinations() {
        for (service, preset) in Policies.presets {
            XCTAssertFalse(preset.hosts.contains { $0.contains("*") }, service)
            XCTAssertTrue(preset.commands.allSatisfy { $0 == "curl" }, service)
        }
        for (service, host) in [("Supabase", "attacker.supabase.co"), ("AWS", "attacker.s3.amazonaws.com"), ("GitHub", "raw.githubusercontent.com"), ("Google", "storage.googleapis.com"), ("Vercel", "attacker.vercel.com")] {
            let item = Item(kind: .secret, name: "TOKEN", service: service, type: "test", fingerprint: "fake", preview: "")
            XCTAssertFalse(Policies.hostMatches(host, Policies.effective(item).hosts), service)
        }
    }

    func testGitShellAliasExecutesAndPersistsFakeSecretOutsideVault() throws {
        let store = try makeStore()
        let broker = Broker(store: store, vault: Vault.shared, unlock: { _ in })
        let destination = FileManager.default.temporaryDirectory.appendingPathComponent("lockd-leak-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: destination) }
        let response = broker.handle(["op": "run", "args": ["names": ["REVIEW_TOKEN"], "project": "Review", "argv": ["git", "-c", "alias.review=!printf '%s' \"$REVIEW_TOKEN\" > '\(destination.path)'", "review"]]])
        XCTAssertFalse(response["ok"] as? Bool ?? true)
        XCTAssertTrue((response["text"] as? String ?? "").hasPrefix("Denied:"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
    }

    func testCurlReadsUserFileOutsideLockdDirectory() throws {
        let store = try makeStore()
        let broker = Broker(store: store, vault: Vault.shared, unlock: { _ in })
        let source = FileManager.default.temporaryDirectory.appendingPathComponent("lockd-public-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: source) }
        let marker = "DISPOSABLE_USER_FILE_MARKER"
        try marker.write(to: source, atomically: true, encoding: .utf8)
        let response = broker.handle(["op": "run", "args": ["names": ["REVIEW_TOKEN"], "argv": ["curl", "--silent", "file://\(source.path)"]]])
        XCTAssertFalse(response["ok"] as? Bool ?? true)
        XCTAssertTrue((response["text"] as? String ?? "").hasPrefix("Denied:"))
        XCTAssertFalse((response["text"] as? String ?? "").contains(marker))
    }

    func testRedactorLeaksReversibleSpacingAndUTF16() {
        let spaced = fake.map(String.init).joined(separator: " ")
        XCTAssertEqual(Redactor.redact(spaced, secrets: [("K", fake)]), spaced)
        let utf16 = String(decoding: Data(fake.utf16LittleEndianBytes), as: UTF8.self)
        XCTAssertEqual(Redactor.redact(utf16, secrets: [("K", fake)]), utf16)
    }

    func testRedactorLeaksShortPlaintext() {
        XCTAssertFalse(Redactor.redact("ab", secrets: [("K", "ab")]).contains("ab"))
    }

    func testCiphertextCanBeTransferredToAnotherIdentity() throws {
        let store = try makeStore()
        var moved = store.items[0]
        moved.id = UUID(); moved.name = "OTHER_TOKEN"; moved.project = "Other"; moved.allowHosts = ["attacker.example"]
        XCTAssertFalse(Policies.rulesVerified(moved))
        XCTAssertThrowsError(try store.secretValue(moved))
    }

    func testPlainJSONCanBroadenPoliciesAfterReload() throws {
        let store = try makeStore()
        var raw = try JSONSerialization.jsonObject(with: Data(contentsOf: LockdPaths.itemsFile)) as! [[String: Any]]
        raw[0]["allowCommands"] = ["curl"]
        raw[0]["allowHosts"] = ["attacker.example"]
        try JSONSerialization.data(withJSONObject: raw).write(to: LockdPaths.itemsFile)
        store.reload()
        XCTAssertTrue(Policies.effective(store.items[0]).hosts.isEmpty)
        XCTAssertFalse(Policies.rulesVerified(store.items[0]))
    }

    func testWireLimitIsNotStrictAndNewlineNotRequired() throws {
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { close(pair[0]); close(pair[1]) }
        let payload = Data("{\"op\":\"status\"}".utf8)
        payload.withUnsafeBytes { p in _ = Darwin.write(pair[0], p.baseAddress!, p.count) }
        shutdown(pair[0], SHUT_WR)
        let line = try XCTUnwrap(BrokerWire.readLine(pair[1], limit: 4))
        XCTAssertGreaterThan(line.utf8.count, 4)
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
    }

    func testEnvMaterializationIsReadableBySameUser() throws {
        let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("lockd-review-env-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try makeStore()
        let response = Broker(store: store, vault: Vault.shared, unlock: { _ in }).handle(["op": "write_env", "args": ["names": ["REVIEW_TOKEN"], "cwd": dir.path, "path": ".env"]])
        XCTAssertFalse(response["ok"] as? Bool ?? true, "\(response)")
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent(".env").path))
    }
}

private extension String {
    var utf16LittleEndianBytes: [UInt8] { utf16.flatMap { [UInt8($0 & 0xff), UInt8($0 >> 8)] } }
}
