import XCTest
@testable import LockdCore

/// Códigos FALSOS. Nunca use códigos reais em testes.
final class RecoveryCodesTests: XCTestCase {
    var home: String!
    var store: Store!
    let sample = "Vercel recovery codes\nAccount: dev@example.com\n\naaaa1111-bbbb2222\ncccc3333-dddd4444\neeee5555-ffff6666\n1111aaaa-2222bbbb\n3333cccc-4444dddd\n5555eeee-6666ffff\n"

    override func setUp() {
        home = NSTemporaryDirectory() + "lockd-rc-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        setenv("LOCKD_HOME", home, 1)
        store = Store()
    }
    override func tearDown() { Vault.shared.lockNow(); try? FileManager.default.removeItem(atPath: home) }

    func write(_ name: String, _ text: String) throws -> URL {
        let u = URL(fileURLWithPath: home).appendingPathComponent(name)
        try text.write(to: u, atomically: true, encoding: .utf8); return u
    }

    func testClassifiesByNameAsSecret() {
        let v = FileClassifier.classify(URL(fileURLWithPath: "/tmp/vercel-recovery-codes-dev@example.com.txt"))
        XCTAssertEqual(v.type, RecoveryCodes.type); XCTAssertEqual(v.kind, .secret); XCTAssertTrue(v.confident); XCTAssertFalse(v.ignore)
        XCTAssertTrue(FileClassifier.classify(URL(fileURLWithPath: "/tmp/notes.txt")).ignore)
    }

    func testParsesServiceAccountAndCodes() throws {
        let p = try XCTUnwrap(RecoveryCodes.parse(text: sample, fileName: "vercel-recovery-codes-dev@example.com.txt"))
        XCTAssertEqual(p.service, "Vercel"); XCTAssertEqual(p.account, "dev@example.com"); XCTAssertEqual(p.codes.count, 6)
        XCTAssertEqual(p.codes.first, "aaaa1111-bbbb2222")
    }

    func testServiceFallsBackToFileName() throws {
        let p = try XCTUnwrap(RecoveryCodes.parse(text: "aaaa1111-bbbb2222\ncccc3333-dddd4444\neeee5555-ffff6666\n1111aaaa-2222bbbb\n", fileName: "github-recovery-codes.txt"))
        XCTAssertEqual(p.service, "Github")
    }

    func testRejectsOrdinaryText() {
        XCTAssertNil(RecoveryCodes.parse(text: "Remember to buy milk\nand call mom\n", fileName: "recovery-plan.txt"))
        XCTAssertNil(RecoveryCodes.parse(text: "aaaa1111-bbbb2222\n", fileName: "recovery.txt"))   // poucos códigos
    }

    func testIngestEncryptsHidesFromAgentAndDedupes() throws {
        let u = try write("vercel-recovery-codes-dev@example.com.txt", sample)
        let item = try RecoveryCodes.ingest(u, project: "Devio", copy: true, store: store)
        XCTAssertEqual(item.kind, .secret); XCTAssertEqual(item.type, RecoveryCodes.type); XCTAssertEqual(item.service, "Vercel")
        XCTAssertEqual(item.name, "VERCEL_RECOVERY_CODES"); XCTAssertEqual(item.preview, "6 codes")
        let cipher = try XCTUnwrap(item.cipher)
        XCTAssertFalse(cipher.contains("aaaa1111"))
        XCTAssertFalse(try String(contentsOfFile: LockdPaths.itemsFile.path, encoding: .utf8).contains("aaaa1111"))
        XCTAssertThrowsError(try RecoveryCodes.ingest(u, project: nil, copy: true, store: store))   // duplicado
        let broker = Broker(store: store, vault: Vault.shared, unlock: { _ in })
        XCTAssertFalse((broker.handle(["op": "list_secrets", "args": [:]])["text"] as? String ?? "").contains("RECOVERY"))
    }

    func testIngestorRoutesRecoveryFilesAndUndoRestores() throws {
        let u = try write("vercel-recovery-codes-dev@example.com.txt", sample)
        let item = try Ingestor.ingest(u, project: nil, store: store)
        XCTAssertEqual(item.type, RecoveryCodes.type)
        XCTAssertFalse(FileManager.default.fileExists(atPath: u.path))           // foi para a Lixeira
        let trash = try XCTUnwrap(item.originalPath)
        XCTAssertTrue(FileManager.default.fileExists(atPath: trash))
        RecoveryCodes.undo(store.item(id: item.id) ?? item, store: store)
        XCTAssertTrue(FileManager.default.fileExists(atPath: u.path))            // voltou
        XCTAssertNil(store.item(id: item.id))
    }

    func testUnparseableRecoveryNamedFileFallsBackToCredentialFile() throws {
        let u = try write("my-recovery-plan.txt", "just some prose, no codes here")
        let item = try Ingestor.ingest(u, project: nil, copy: true, store: store)
        XCTAssertEqual(item.kind, .credential)
    }
}
