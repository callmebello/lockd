import XCTest
@testable import LockdCore

/// A lista de chaves nunca pode mostrar caracteres do valor. Antes: 6 do começo + 4 do fim, também gravados em items.json.
final class PreviewSafetyTests: XCTestCase {
    private var home: URL!
    private var previous: String?

    override func setUpWithError() throws {
        previous = ProcessInfo.processInfo.environment["LOCKD_HOME"]
        home = FileManager.default.temporaryDirectory.appendingPathComponent("lockd-prev-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        setenv("LOCKD_HOME", home.path, 1)
    }
    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: home)
        if let previous { setenv("LOCKD_HOME", previous, 1) } else { unsetenv("LOCKD_HOME") }
    }

    func testPreviewShowsOnlyPublicPrefixOrDots() {
        XCTAssertEqual(Detector.preview("XEPs,%abcdefghG4mz"), "••••••")
        XCTAssertEqual(Detector.preview("minhasenha123"), "••••••")
        XCTAssertEqual(Detector.preview("sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx"), "sk-ant-••••")
        XCTAssertEqual(Detector.preview("sk-proj-abcdefghijklmnopqrstuvwxyz012345"), "sk-proj-••••")
        XCTAssertEqual(Detector.preview("AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"), "AIza••••")
        XCTAssertEqual(Detector.preview("sbp_" + String(repeating: "ab12", count: 10)), "sbp_••••")
        XCTAssertEqual(Detector.preview("postgres://user:senha@host:5432/db"), "postgres://••••")
        XCTAssertTrue(Detector.preview("-----BEGIN PRIVATE KEY-----\nMIGT\n-----END PRIVATE KEY-----").hasPrefix("-----BEGIN"))
    }

    func testPreviewNeverContainsAnyThreeCharsOfTheSecretBeyondThePrefix() {
        for value in ["XEPs,%qwertyG4mz", "tr0ub4dor&3-horse-battery", "sk-ant-api03-ZZyyXXwwVVuuTTss99", "312312sdfsdf2312"] {
            let prefix = Detector.publicPrefixes.first { value.hasPrefix($0) } ?? ""
            let rest = Array(value.dropFirst(prefix.count))
            let shown = Detector.preview(value)
            for i in 0..<(rest.count - 2) {
                XCTAssertFalse(shown.contains(String(rest[i..<(i + 3)])), "\(value) → \(shown)")
            }
        }
    }

    func testSanitizeOldFormat() {
        XCTAssertEqual(Detector.sanitizePreview("XEPs,%…G4mz"), "••••••")
        XCTAssertEqual(Detector.sanitizePreview("312312…2312"), "••••••")
        XCTAssertEqual(Detector.sanitizePreview("sbp_fc…fe26"), "sbp_••••")
        XCTAssertEqual(Detector.sanitizePreview("sk-ant…GHIJ"), "sk-ant-••••")
        XCTAssertEqual(Detector.sanitizePreview("AIzaSy…Q"), "AIza••••")
        XCTAssertEqual(Detector.sanitizePreview("sk-ant-••••"), "sk-ant-••••", "já seguro: não muda")
        XCTAssertEqual(Detector.sanitizePreview("••••••"), "••••••")
    }

    func testStoreMigratesLeakyPreviewsAndWeakFingerprintsOnLoad() throws {
        func item(_ name: String, _ preview: String, _ fp: String) -> Item {
            Item(kind: .secret, name: name, service: "Supabase", type: "Secret", project: "P", fingerprint: fp, preview: preview, cipher: "v3:x")
        }
        let leaky = [item("password_supabase", "XEPs,%…G4mz", "aaaabbbbccccddddeeeeffff"),
                     item("SUPABASE_PAT", "sbp_fc…fe26", "111122223333444455556666")]
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        try enc.encode(leaky).write(to: LockdPaths.itemsFile)

        let store = Store()
        let byName = Dictionary(uniqueKeysWithValues: store.items.map { ($0.name, $0) })
        XCTAssertEqual(byName["password_supabase"]?.preview, "••••••")
        XCTAssertEqual(byName["SUPABASE_PAT"]?.preview, "sbp_••••")
        XCTAssertTrue(byName["password_supabase"]?.fingerprint.hasPrefix("weak-") ?? false, "hash de senha fraca some")
        XCTAssertEqual(byName["SUPABASE_PAT"]?.fingerprint, "111122223333444455556666", "chave de provedor mantém o hash p/ não duplicar")

        let onDisk = try String(contentsOf: LockdPaths.itemsFile, encoding: .utf8)
        XCTAssertFalse(onDisk.contains("XEPs") || onDisk.contains("G4mz") || onDisk.contains("fe26") || onDisk.contains("aaaabbbbcccc"), "nada do valor sobra no arquivo")
    }

    func testWeakSecretsGetNoHashAndStrongKeysStillDeduplicate() throws {
        let store = Store()
        let weak = try store.saveSecret(Detection(envName: "DB_PASSWORD", service: "Supabase", type: "Secret", value: "password123", confident: true), project: nil, source: nil).item
        XCTAssertTrue(weak.fingerprint.hasPrefix("weak-"))
        XCTAssertNotEqual(weak.fingerprint, Vault.fingerprint("password123"))
        XCTAssertEqual(weak.preview, "••••••")

        let key = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        let a = try store.saveSecret(Detection(envName: "ANTHROPIC_API_KEY", service: "Anthropic", type: "API key", value: key, confident: true), project: nil, source: nil)
        let b = try store.saveSecret(Detection(envName: "ANTHROPIC_API_KEY", service: "Anthropic", type: "API key", value: key, confident: true), project: nil, source: nil)
        XCTAssertTrue(a.isNew); XCTAssertFalse(b.isNew, "mesma chave de provedor não duplica")
        XCTAssertEqual(a.item.preview, "sk-ant-••••")
    }

    func testProjectColorsAreStoredAsPaletteIndexes() throws {
        let store = Store()
        store.setProjectColor("Priva", index: 3)
        XCTAssertEqual(Store().projectColors["Priva"], 3, "persiste entre aberturas")
        store.setProjectColor("Priva", index: nil)
        XCTAssertNil(Store().projectColors["Priva"])
    }
}
