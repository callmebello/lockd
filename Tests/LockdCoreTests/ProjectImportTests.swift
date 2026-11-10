import XCTest
@testable import LockdCore

final class ProjectImportTests: XCTestCase {
    private var home: URL!, code: URL!
    private var previous: String?
    private let anthropic = "sk-ant-api03-FAKEscanKEY0123456789abcdefGHIJklmnopQRS"
    private let stripe = "sk_" + "live_FAKEscanSTRIPE0123456789abcdef"
    private let openai = "sk-proj-FAKEscanOPENAI0123456789abcdefghijklmnop"

    override func setUpWithError() throws {
        previous = ProcessInfo.processInfo.environment["LOCKD_HOME"]
        home = FileManager.default.temporaryDirectory.appendingPathComponent("lockd-scan-\(UUID().uuidString)")
        code = home.appendingPathComponent("code")
        setenv("LOCKD_HOME", home.appendingPathComponent("data").path, 1)
        try FileManager.default.createDirectory(at: home.appendingPathComponent("data"), withIntermediateDirectories: true)
        func write(_ path: String, _ text: String) throws {
            let u = code.appendingPathComponent(path)
            try FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
            try text.write(to: u, atomically: true, encoding: .utf8)
        }
        let svg = ##"<svg xmlns="http://www.w3.org/2000/svg"><circle r="5" fill="#22D3EE"/></svg>"##
        try write("alpha/package.json", "{}")
        try write("alpha/.env", "ANTHROPIC_API_KEY=\(anthropic)\nPORT=3000\nSTRIPE_SECRET_KEY=\(stripe)\nDATABASE_URL=postgres://u:p@db.example.com:5432/app\n")
        try write("alpha/.env.example", "OPENAI_API_KEY=sk-proj-EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE000\n")
        try write("alpha/.vercel/project.json", #"{"projectId":"prj_abc123","orgId":"team_xyz"}"#)
        try write("alpha/public/logo.svg", svg)
        try write("alpha/public/photo.jpg", "not really a jpg")
        try write("alpha/src/assets/icon.png", "png-bytes")
        try write("alpha/node_modules/dep/logo.svg", svg)
        try write("beta/.git/config", "[remote \"origin\"]\n\turl = https://github.com/x/beta.git\n")
        try write("beta/.env.local", "OPENAI_API_KEY=\(openai)\n")
        try write("notaproject/readme.txt", "hello")
    }
    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: home)
        if let previous { setenv("LOCKD_HOME", previous, 1) } else { unsetenv("LOCKD_HOME") }
    }

    private func scan(_ store: Store = Store()) -> [ScannedProject] { ProjectScanner.scan(roots: [code], store: store) }

    func testScannerFindsProjectsKeysAssetsAndLinks() {
        let projects = scan()
        XCTAssertEqual(Set(projects.map(\.name)), ["alpha", "beta"], "notaproject e node_modules ficam de fora")
        let alpha = projects.first { $0.name == "alpha" }!
        XCTAssertEqual(Set(alpha.keys.map(\.envName)), ["ANTHROPIC_API_KEY", "STRIPE_SECRET_KEY", "DATABASE_URL"], "PORT e .env.example não entram")
        XCTAssertEqual(alpha.vercelProjectId, "prj_abc123"); XCTAssertEqual(alpha.vercelTeamId, "team_xyz")
        XCTAssertEqual(Set(alpha.assets.map(\.name)), ["logo.svg", "icon.png"], "foto.jpg sem nome de marca e node_modules não entram")
        XCTAssertEqual(projects.first { $0.name == "beta" }?.gitRemote, "https://github.com/x/beta.git")
        for k in alpha.keys { XCTAssertTrue(k.preview.contains("•"), "a revisão nunca mostra caracteres do valor: \(k.preview)") }
        XCTAssertTrue(alpha.keys.allSatisfy { $0.selected })
    }

    func testImportCopiesAssetsEncryptsKeysAndSavesLinks() throws {
        let store = Store()
        let projects = scan(store)
        let result = ProjectImporter.importProjects(projects, store: store)
        XCTAssertEqual(result.keys, 4); XCTAssertEqual(result.assets, 2); XCTAssertEqual(result.failed, 0)

        XCTAssertTrue(FileManager.default.fileExists(atPath: code.appendingPathComponent("alpha/public/logo.svg").path), "o arquivo do projeto NÃO é movido")
        let logos = store.items.filter { $0.isFile && $0.project == "alpha" }
        XCTAssertEqual(logos.count, 2)
        XCTAssertTrue(logos.allSatisfy { FileManager.default.fileExists(atPath: $0.path ?? "") && ($0.path ?? "").contains("/library/alpha/") })

        let secrets = store.items.filter { $0.kind == .secret }
        XCTAssertEqual(secrets.count, 4)
        XCTAssertEqual(try store.secretValue(secrets.first { $0.name == "ANTHROPIC_API_KEY" }!), anthropic)
        XCTAssertEqual(secrets.first { $0.name == "ANTHROPIC_API_KEY" }?.project, "alpha")
        let onDisk = try String(contentsOf: LockdPaths.itemsFile, encoding: .utf8)
        for v in [anthropic, stripe, openai, "db.example.com"] { XCTAssertFalse(onDisk.contains(v)) }

        XCTAssertEqual(store.link(for: "alpha")?.vercelProjectId, "prj_abc123")
        XCTAssertEqual(URL(fileURLWithPath: store.link(for: "alpha")!.path).resolvingSymlinksInPath().path,
                       code.appendingPathComponent("alpha").resolvingSymlinksInPath().path)
        XCTAssertNotNil(store.link(for: "beta"))
    }

    func testRescanMarksAlreadyImportedAndSecondImportDoesNothing() throws {
        let store = Store()
        ProjectImporter.importProjects(scan(store), store: store)
        let again = scan(store)
        XCTAssertTrue(again.flatMap(\.keys).allSatisfy { $0.alreadyInLockd && !$0.selected })
        let r = ProjectImporter.importProjects(again, store: store)
        XCTAssertEqual(r.keys, 0); XCTAssertEqual(r.assets, 0)
        XCTAssertEqual(store.items.filter { $0.kind == .secret }.count, 4, "sem duplicar")
        XCTAssertEqual(r.skipped, 2, "os 2 assets já estão (as chaves não são nem tentadas porque vêm desmarcadas)")
    }

    func testRespectsUncheckedItemsAndMissingKeysSuggestion() throws {
        let store = Store()
        var projects = scan(store)
        let ai = projects.firstIndex { $0.name == "alpha" }!
        let stripeIdx = projects[ai].keys.firstIndex { $0.envName == "STRIPE_SECRET_KEY" }!
        projects[ai].keys[stripeIdx].selected = false
        for j in projects[ai].assets.indices { projects[ai].assets[j].selected = false }
        let r = ProjectImporter.importProjects(projects, store: store)
        XCTAssertEqual(r.keys, 3 + 1 - 1 + 0, "alpha sem a Stripe (2) + beta (1) = 3")
        XCTAssertEqual(r.assets, 0)
        XCTAssertNil(store.items.first { $0.name == "STRIPE_SECRET_KEY" })

        // sugestão "enquanto você desenvolve": o que está no .env e não está no Lockd
        let missing = ProjectScanner.missingKeys(project: "alpha", link: store.link(for: "alpha")!, store: store)
        XCTAssertEqual(missing.map(\.envName), ["STRIPE_SECRET_KEY"])
        XCTAssertFalse(missing[0].alreadyInLockd)
    }

    func testEnvFileWithOnlyConfigIsIgnored() throws {
        let dir = code.appendingPathComponent("gamma")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try "PORT=3000\nNODE_ENV=production\nNEXT_PUBLIC_URL=https://x.com\n".write(to: dir.appendingPathComponent(".env"), atomically: true, encoding: .utf8)
        XCTAssertFalse(scan().contains { $0.name == "gamma" })
    }
}
