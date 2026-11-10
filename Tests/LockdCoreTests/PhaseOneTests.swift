import XCTest
@testable import LockdCore

final class PhaseOneTests: XCTestCase {
    private var scratch: URL!
    private var previous: String?
    override func setUpWithError() throws {
        previous = ProcessInfo.processInfo.environment["LOCKD_HOME"]
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("lockd-phase1-\(UUID().uuidString)")
        setenv("LOCKD_HOME", scratch.appendingPathComponent("vault").path, 1)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        Vault.shared.lockNow(); BrokerSettings.programsEnabled = true
    }
    override func tearDownWithError() throws {
        Vault.shared.lockNow(); BrokerSettings.programsEnabled = false
        try? FileManager.default.removeItem(at: scratch)
        if let previous { setenv("LOCKD_HOME", previous, 1) } else { unsetenv("LOCKD_HOME") }
    }
    func testCurlClosedOptionsIncludingClustersAndEquals() throws {
        let url = "https://api.anthropic.com/v1/models"
        let denied: [[String]] = [
            ["-K", "/tmp/fake"], ["-sSK/tmp/fake"], ["--config=/tmp/fake"], ["-xproxy"], ["--proxy=http://localhost"],
            ["--preproxy", "http://localhost"], ["--noproxy", "*"], ["--connect-to", "x:y"], ["--resolve=x:443:127.0.0.1"],
            ["--unix-socket=/tmp/fake"], ["--abstract-unix-socket=x"], ["-Tfake"], ["--upload-file=fake"],
            ["-Ffoo=@fake"], ["--form-string=foo"], ["--data=@fake"], ["--data-raw=@fake"], ["--data-binary=@fake"],
            ["--data-urlencode=x@fake"], ["--json=@fake"], ["-o/tmp/fake"], ["-sSO"], ["--output-dir=/tmp"],
            ["--trace-ascii=/tmp/fake"], ["-D/tmp/fake"], ["-bfake"], ["-cfake"], ["--next"], ["--url", url],
            ["--location"], ["--write-out=%output{/tmp/fake}"], ["--insecure"], ["--hea", "x: y"],
            ["--header=@fake"], ["-H", "x: y\r\nInjected: z"], ["-HHost: attacker.example"], ["--max-time=0"]
        ]
        for options in denied {
            XCTAssertThrowsError(try CurlArguments.validate(options + [url]), options.joined(separator: " "))
        }
        for badURL in ["file:///tmp/fake", "http://example.com", "ftp://example.com", "https://user:pass@example.com", "https://example.com:444"] {
            XCTAssertThrowsError(try CurlArguments.validate([badURL]), badURL)
        }
        XCTAssertNoThrow(try CurlArguments.validate(["--json={\"email\":\"fake@example.com\"}", url]))
        XCTAssertNoThrow(try CurlArguments.validate(["--data-urlencode=email=fake@example.com", url]))
        let parsed = try CurlArguments.validate(["-sSv", "--request=POST", "-Hx-test: {{K}}", "--json={\"inline\":true}", url])
        let config = String(decoding: try CurlArguments.configuration(parsed, secrets: ["K": "FAKE_TOKEN_1234567890"]), as: UTF8.self)
        XCTAssertTrue(config.contains("x-test: FAKE_TOKEN_1234567890"))
        XCTAssertEqual(CurlArguments.processArguments.first, "-q")
        XCTAssertFalse(CurlArguments.processArguments.joined().contains("FAKE_TOKEN"))
        XCTAssertTrue(CurlArguments.processArguments.contains("=https"))
        XCTAssertThrowsError(try CurlArguments.configuration(parsed, secrets: ["K": "x\r\nInjected: y"]))
        let data = try CurlArguments.validate(["-d{{K}}", url])
        XCTAssertThrowsError(try CurlArguments.configuration(data, secrets: ["K": "@/tmp/fake"]))
    }
    func testCustomWildcardRequiresExplicitConfirmationMarker() {
        var item = Item(kind: .secret, name: "TOKEN", type: "test", fingerprint: "fake", preview: "",
                        allowCommands: ["curl"], allowHosts: ["api.example.com", "*.example.com"])
        XCTAssertEqual(Policies.proposed(item).hosts, ["api.example.com"])
        item.confirmedWildcardHosts = ["*.example.com"]
        XCTAssertEqual(Policies.proposed(item).hosts, ["api.example.com", "*.example.com"])
        item.allowHosts = ["*.other.example"]
        XCTAssertTrue(Policies.proposed(item).hosts.isEmpty)
    }
    func testOnlyTrustedExecutableIsResolved() throws {
        XCTAssertEqual(Policies.resolve(program: "curl"), Sandbox.realPath("/usr/bin/curl"))
        let fakeBinary = scratch.appendingPathComponent("curl")
        try Data("fake".utf8).write(to: fakeBinary)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fakeBinary.path)
        XCTAssertFalse(Policies.trustedExecutable(fakeBinary.path))
        let link = scratch.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: fakeBinary.path)
        XCTAssertFalse(Policies.trustedExecutable(link.path))
        XCTAssertNil(Policies.resolve(program: "../curl"))
    }
    func testSandboxProtectedReadAndWriteBoundary() throws {
        let fm = FileManager.default
        let cwd = scratch.appendingPathComponent("cwd")
        let protected = cwd.appendingPathComponent("fake-home/.ssh")
        try fm.createDirectory(at: protected, withIntermediateDirectories: true)
        let source = protected.appendingPathComponent("fake-key")
        let marker = "DISPOSABLE_PROTECTED_MARKER"
        try marker.write(to: source, atomically: true, encoding: .utf8)
        let link = cwd.appendingPathComponent("link")
        try fm.createSymbolicLink(atPath: link.path, withDestinationPath: protected.path)
        for path in [source.path, link.appendingPathComponent("fake-key").path] {
            let result = Sandbox.run(program: "/usr/bin/curl", args: ["-q", "--silent", "--show-error", "file://" + path], env: [:], cwd: cwd, allowedHosts: [], additionalProtectedPaths: [protected.path])
            XCTAssertNotEqual(result.status, 0, result.output)
            XCTAssertFalse(result.output.contains(marker))
        }
        let outside = scratch.appendingPathComponent("outside")
        let rejected = Sandbox.run(program: "/usr/bin/touch", args: [outside.path], env: [:], cwd: cwd, allowedHosts: [])
        XCTAssertNotEqual(rejected.status, 0, rejected.output)
        XCTAssertFalse(fm.fileExists(atPath: outside.path))
        let inside = cwd.appendingPathComponent("inside")
        let accepted = Sandbox.run(program: "/usr/bin/touch", args: [inside.path], env: [:], cwd: cwd, allowedHosts: [])
        XCTAssertEqual(accepted.status, 0, accepted.output)
        XCTAssertTrue(fm.fileExists(atPath: inside.path))
        let protectedWrite = Sandbox.run(program: "/usr/bin/touch", args: [protected.appendingPathComponent("blocked").path], env: [:], cwd: cwd, allowedHosts: [], additionalProtectedPaths: [protected.path])
        XCTAssertNotEqual(protectedWrite.status, 0, protectedWrite.output)
    }
    func testWriteEnvFreshApprovalPerDestinationAndRevocation() throws {
        let store = Store()
        let item = try store.saveSecret(Detection(envName: "FAKE_TOKEN", service: "Anthropic", type: "test", value: "FAKE_ENV_TOKEN_123456789", confident: true), project: "Phase1", source: "test").item
        XCTAssertFalse(Policies.effective(item).allowEnv)
        store.update(id: item.id) { $0.allowEnv = true }
        try store.authorizeRules([item.id])
        // EnvFile exige home: diretório descartável dentro do repositório, sem dados reais.
        let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("lockd-phase1-env-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        var fresh = 0, session = 0
        let broker = Broker(store: store, vault: Vault.shared, unlock: { _ in session += 1 }, freshUnlock: { _ in fresh += 1 })
        func write(_ path: String) -> [String: Any] {
            broker.handle(["op": "write_env", "args": ["path": path, "cwd": dir.path, "names": ["FAKE_TOKEN"]]])
        }
        XCTAssertTrue(write(".env")["ok"] as? Bool ?? false)
        XCTAssertEqual(fresh, 1)
        XCTAssertTrue(write(".env")["ok"] as? Bool ?? false)
        XCTAssertEqual(fresh, 1)
        let next = write(".env.local")
        XCTAssertTrue(next["ok"] as? Bool ?? false)
        XCTAssertEqual(fresh, 2)
        XCTAssertEqual(session, 0)
        XCTAssertTrue((next["text"] as? String ?? "").contains("estes valores agora ficam legíveis por qualquer processo do seu usuário (incluindo o agente)"))
        Vault.shared.lockNow()
        XCTAssertTrue(write(".env")["ok"] as? Bool ?? false)
        XCTAssertEqual(fresh, 3)
        let denied = Broker(store: store, vault: Vault.shared, freshUnlock: { _ in throw Vault.VaultError.denied("test cancellation") })
        let r = denied.handle(["op": "write_env", "args": ["path": ".env.denied", "cwd": dir.path]])
        XCTAssertFalse(r["ok"] as? Bool ?? true)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent(".env.denied").path))
    }
    func testResolvedProgramIsAuditedWithoutSecret() throws {
        let store = Store()
        try store.saveSecret(Detection(envName: "FAKE_TOKEN", service: "Anthropic", type: "test", value: "FAKE_AUDIT_TOKEN_123456789", confident: true), project: nil, source: "test")
        try store.authorizeRules(store.items.map(\.id))
        let broker = Broker(store: store)
        // Destino recusado pelo proxy, sem depender de resposta de API.
        _ = broker.handle(["op": "run", "args": ["argv": ["curl", "-sS", "-m2", "https://example.com", "-H", "x-test: {{FAKE_TOKEN}}"]]])
        let entry = try XCTUnwrap(Audit.recent().first { $0.resolvedProgram != nil })
        XCTAssertEqual(entry.resolvedProgram, Sandbox.realPath("/usr/bin/curl"))
        XCTAssertTrue(entry.command?.contains("{{FAKE_TOKEN}}") ?? false)
        XCTAssertFalse((try String(contentsOf: LockdPaths.auditFile, encoding: .utf8)).contains("FAKE_AUDIT_TOKEN_123456789"))
    }
}
