import Foundation

/// Único caminho pelo qual o Claude usa uma chave. Ele pede; o Broker confere a política, exige Touch ID,
/// roda tudo num sandbox sem rede (exceto o proxy filtrado) e devolve só texto já mascarado.
public final class Broker: @unchecked Sendable {
    public let store: Store
    public let vault: Vault
    /// Bloqueia até o usuário aprovar (Touch ID). No app = diálogo do sistema; em testes = no-op.
    public var unlockHandler: (String) throws -> Void
    private let unlockLock = NSLock()
    let freshUnlockHandler: (String) throws -> Void
    private var approvedEnvDestinations = Set<String>()
    private var envSession: UInt64?
    internal var httpClient = SecureHTTPClient()
    private var approvedHTTP = Set<String>()
    private var httpSession: UInt64?
    public var onAudit: ((AuditEntry) -> Void)?
    /// Canal com a extensão do navegador (preencher campos e capturar chaves sem passar pelo agente).
    public let bridge = BrowserBridge()
    /// Projeto em que o usuário está trabalhando agora (o app preenche). Usado quando ele salva uma chave direto da página.
    public var currentProject: () -> String? = { nil }
    private var approvedFill = Set<String>()
    private var fillSession: UInt64?

    public init(store: Store = .shared, vault: Vault = .shared, unlock: ((String) throws -> Void)? = nil, freshUnlock: ((String) throws -> Void)? = nil) {
        self.store = store; self.vault = vault
        self.unlockHandler = unlock ?? { reason in try vault.unlock(reason: reason) }
        self.freshUnlockHandler = freshUnlock ?? { reason in try vault.unlock(reason: reason, fresh: true) }
        wireBridge()
    }

    // MARK: - Entrada

    public func handle(_ req: [String: Any]) -> [String: Any] {
        let op = req["op"] as? String ?? ""
        let a = req["args"] as? [String: Any] ?? [:]
        switch op {
        case "status": return ok(status())
        case "list_secrets": return ok(listSecrets(project: a["project"] as? String))
        case "list_assets": return ok(listAssets(project: a["project"] as? String, type: a["type"] as? String))
        case "capabilities": return ["ok": true, "allow_programs": BrokerSettings.programsEnabled]
        case "http": return http(a)
        case "run": return run(a)
        case "write_env": return writeEnv(a)
        case "vercel_env": return vercelEnv(a)
        case "add_secret": return addSecret(a)
        case "vercel_read": return vercelRead(a)
        case "supabase_sql": return supabaseSQL(a)
        case "audit": return ok(auditText(limit: a["limit"] as? Int ?? 15))
        case "browser_status": return ok(bridge.isConnected ? "Browser extension connected." : "Browser extension not connected.")
        case "browser_fill": return browserFill(a)
        case "browser_capture": return browserCapture(a)
        default: return fail("unknown operation \(op)")
        }
    }

    func ok(_ text: String) -> [String: Any] { ["ok": true, "text": text] }
    func fail(_ text: String) -> [String: Any] { ["ok": false, "text": text] }

    @discardableResult
    func record(_ e: AuditEntry) -> AuditEntry { Audit.write(e); onAudit?(e); return e }

    // MARK: - Seleção e aprovação

    func pick(project: String?, names: [String]?) -> [Item] {
        var seen = Set<String>(), out: [Item] = []
        // Chave com regra assinada vence uma mais nova sem assinatura: ninguém sobrepõe a sua chave só criando outra com o mesmo nome.
        let ranked = store.items.sorted { a, b in
            let av = Policies.rulesVerified(a), bv = Policies.rulesVerified(b)
            return av != bv ? av : a.createdAt > b.createdAt
        }
        for i in ranked where i.kind == .secret && isEnvName(i.name) && i.type != RecoveryCodes.type {
            if let p = project, !p.isEmpty, i.project?.caseInsensitiveCompare(p) != .orderedSame { continue }
            if let n = names, !n.contains(i.name) { continue }
            if seen.insert(i.name).inserted { out.append(i) }
        }
        return out
    }

    /// Retorna "session" se já estava liberado, "touch-id" se precisou pedir agora.
    func approve(_ reason: String) throws -> String {
        if vault.isUnlocked { return "session" }
        unlockLock.lock(); defer { unlockLock.unlock() }
        if vault.isUnlocked { return "session" }
        try unlockHandler(String(reason.prefix(150)))
        return "touch-id"
    }

    func status() -> String {
        vault.isUnlocked ? "unlocked (\(Int(vault.unlockedRemaining / 60)) min left)" : "locked (Touch ID needed on first use)"
    }

    func listSecrets(project: String?) -> String {
        let items = pick(project: project, names: nil)
        if items.isEmpty { return "No secrets." }
        return items.map { i in
            let p = Policies.effective(i)
            let rules = p.commands.isEmpty ? "NO RULES (Claude can't run commands with it)" :
                "programs: \(p.commands.joined(separator: ","))  hosts: \(p.hosts.joined(separator: ","))"
            return "\(i.name)\t\(i.service ?? "-")\t\(i.project ?? "Inbox")\t\(rules)" + (i.daysUntilExpiry.map { "\texpires in \($0)d" } ?? "")
        }.joined(separator: "\n")
    }

    func listAssets(project: String?, type: String?) -> String {
        var items = store.items.filter { $0.kind != .secret }
        if let p = project, !p.isEmpty { items = items.filter { $0.project?.caseInsensitiveCompare(p) == .orderedSame } }
        if let t = type, !t.isEmpty { items = items.filter { $0.type.caseInsensitiveCompare(t) == .orderedSame } }
        if items.isEmpty { return "No assets." }
        return items.map { i in
            "\(i.path ?? i.name)\t\(i.type)\t\(i.project ?? "Inbox")" + ((i.colors ?? []).isEmpty ? "" : "\tcolors: " + i.colors!.joined(separator: " "))
        }.joined(separator: "\n")
    }

    func auditText(limit: Int) -> String {
        let df = DateFormatter(); df.dateFormat = "MM-dd HH:mm:ss"
        let rows = Audit.recent(limit: max(1, min(limit, 100)))
        if rows.isEmpty { return "No activity yet." }
        return rows.map { e in
            "\(df.string(from: e.date))  \(e.status.uppercased())  \(e.tool)  [\(e.secrets.joined(separator: ","))]  \(e.command ?? e.detail ?? "")"
        }.joined(separator: "\n")
    }

    // MARK: - run

    static let placeholder = try! NSRegularExpression(pattern: #"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}"#)

    func run(_ a: [String: Any]) -> [String: Any] {
        guard BrokerSettings.programsEnabled else { return fail("Denied: programs are disabled. Enable Permitir programas (avançado) in Lockd Settings only if you accept the risk. Use lockd_http instead.") }
        guard let argv = a["argv"] as? [String], let exe = argv.first, argv.count <= 64, argv.allSatisfy({ $0.count <= 8000 }) else {
            return fail("argv must be a list of up to 64 strings (no shell). Example: [\"curl\",\"-s\",\"https://api.example.com\"]")
        }
        let project = a["project"] as? String
        var names = a["names"] as? [String] ?? []
        for arg in argv {
            for m in Self.placeholder.matches(in: arg, range: NSRange(arg.startIndex..., in: arg)) {
                if let r = Range(m.range(at: 1), in: arg), !names.contains(String(arg[r])) { names.append(String(arg[r])) }
            }
        }
        let shown = argv.joined(separator: " ")
        func deny(_ why: String, secrets: [String] = names) -> [String: Any] {
            record(AuditEntry(tool: "run", status: "denied", project: project, secrets: secrets, command: shown, detail: why))
            return fail("Denied: \(why)")
        }
        guard !names.isEmpty else { return deny("no secrets requested — pass names or use {{NAME}} in an argument") }
        let items = pick(project: project, names: names)
        let missing = names.filter { n in !items.contains { $0.name == n } }
        guard missing.isEmpty else { return deny("no such key\(missing.count > 1 ? "s" : "") in \(project ?? "any project"): \(missing.joined(separator: ", "))") }

        guard !exe.contains("/") else { return deny("use a bare program name (e.g. curl), not a path") }
        guard !Policies.blockedPrograms.contains(exe.lowercased()) else {
            return deny("`\(exe)` is never allowed with keys — shells, interpreters and encoders can leak them")
        }
        // Até a arquitetura HTTP interna, somente curl com linguagem fechada.
        guard exe == "curl" else { return deny("`\(exe)` is disabled in Phase 1; only validated curl is available") }
        let validatedCurl: [(String, String?)]
        do { validatedCurl = try CurlArguments.validate(Array(argv.dropFirst())) }
        catch { return deny(error.localizedDescription) }
        var hostLists: [[String]] = []
        for i in items {
            let p = Policies.effective(i)
            guard p.commands.contains(exe) else {
                return deny("\(i.name) can't be used with `\(exe)`. Allowed programs: \(p.commands.isEmpty ? "none yet" : p.commands.joined(separator: ", ")). Change it in Lockd → \(i.name) → Claude access.")
            }
            hostLists.append(p.hosts)
        }
        let hosts = Policies.intersectHosts(hostLists)
        guard let path = Policies.resolve(program: exe) else { return deny("`\(exe)` isn't installed in a standard location") }

        var cwd: URL?
        if let c = a["cwd"] as? String, !c.isEmpty {
            let u = URL(fileURLWithPath: (c as NSString).expandingTildeInPath)
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: u.path, isDirectory: &isDir), isDir.boolValue else { return deny("cwd doesn't exist") }
            cwd = u
        }

        let by: String
        do { by = try approve("Claude wants to run “\(shown)” using \(names.joined(separator: ", "))") }
        catch { return deny("not approved (\(error.localizedDescription))") }

        var values: [(name: String, value: String)] = []
        for i in items {
            guard let v = try? store.secretValue(i) else { return deny("couldn't unlock \(i.name)") }
            values.append((i.name, v))
        }
        let map = Dictionary(uniqueKeysWithValues: values.map { ($0.name, $0.value) })
        let input: Data
        do { input = try CurlArguments.configuration(validatedCurl, secrets: map) }
        catch { return deny("curl configuration rejected after key substitution") }
        let r = Sandbox.run(program: path, args: CurlArguments.processArguments, env: map, cwd: cwd, allowedHosts: hosts, input: input)
        let clean = Redactor.redact(r.output, secrets: values)

        var e = AuditEntry(tool: "run", status: r.status == 0 ? "ok" : "error", project: project, secrets: names, command: shown)
        e.resolvedProgram = path
        e.hosts = hosts; e.contacted = r.contacted; e.blocked = r.blocked; e.exitCode = r.status; e.approvedBy = by
        record(e)

        var tail = "[exit \(r.status)"
        if !r.contacted.isEmpty { tail += " · reached: \(r.contacted.joined(separator: ", "))" }
        if !r.blocked.isEmpty { tail += " · BLOCKED: \(r.blocked.joined(separator: ", "))" }
        tail += "]"
        return ["ok": r.status == 0, "text": (clean.isEmpty ? "(no output)" : clean) + "\n" + tail]
    }

    /// Quando o USUÁRIO clica "Salvar no Lockd" na página.
    func wireBridge() {
        bridge.onCapture = { [weak self] host, cands in
            self?.saveFromBrowser(host: host, candidates: cands, project: nil, name: nil, tool: "browser_save") ?? "Lockd isn't ready."
        }
    }

    func approveHTTP(_ items: [Item], host: String, method: String) throws -> String {
        unlockLock.lock(); defer { unlockLock.unlock() }
        let current = vault.sessionIdentifier
        if current == nil || current != httpSession { approvedHTTP.removeAll() }
        let grants = items.map { $0.id.uuidString + "|" + host + "|" + ($0.ruleSignature ?? "") }
        let by: String
        if grants.contains(where: { !approvedHTTP.contains($0) }) {
            try freshUnlockHandler("Agent requests \(method) to \(host) using \(items.map(\.name).joined(separator: ", "))")
            by = "touch-id"; approvedHTTP.formUnion(grants)
        } else { by = "session" }
        httpSession = vault.sessionIdentifier
        return by
    }

    // MARK: - HTTP sem processo filho

    func http(_ args: [String: Any]) -> [String: Any] {
        let plan: HTTPPlan
        do { plan = try HTTPPlan(args, client: httpClient) }
        catch { return fail("Denied: " + error.localizedDescription) }
        let items = pick(project: args["project"] as? String, names: plan.names)
        func deny(_ detail: String) -> [String: Any] {
            record(AuditEntry(tool: "http", status: "denied", secrets: plan.names, command: plan.method + " " + plan.host, detail: detail))
            return fail("Denied: " + detail)
        }
        guard items.count == plan.names.count else { return deny("Requested key is missing") }
        for item in items {
            let policy = Policies.effective(item)
            guard Policies.rulesVerified(item), Policies.permitsHTTP(policy, host: plan.host, method: plan.method, path: plan.path) else { return deny("No verified policy for this key, exact host, method or path") }
        }
        let approvedBy: String
        do { approvedBy = try approveHTTP(items, host: plan.host, method: plan.method) }
        catch { return deny("Fresh authentication was not approved") }
        var secrets: [(name: String, value: String)] = []
        do {
            for item in items { secrets.append((item.name, try store.secretValue(item))) }
            let values = Dictionary(uniqueKeysWithValues: secrets.map { ($0.name, $0.value) })
            let (url, headers, body) = try plan.materialized(values)
            let response = try httpClient.perform(method: plan.method, url: url, headers: headers, body: body, hosts: [plan.host], timeout: plan.timeout)
            var entry = AuditEntry(tool: "http", status: "ok", project: args["project"] as? String,
                secrets: plan.names, command: Redactor.redactTemplate(plan.auditTemplate, secrets: secrets))
            entry.hosts = [plan.host]; entry.contacted = [plan.host]; entry.approvedBy = approvedBy; record(entry)
            let filteredType = Redactor.redact(response.contentType, secrets: secrets)
            let filteredBody = response.binary ? "(binary response omitted; \(response.data.count) bytes retained)" : Redactor.redact(String(decoding: response.data, as: UTF8.self), secrets: secrets)
            let note = response.truncated ? "\n[response truncated at 1 MB]" : ""
            return ["ok": true, "status": response.status, "content_type": filteredType, "body": filteredBody,
                "truncated": response.truncated, "text": "HTTP \(response.status) · \(filteredType)\nUntrusted server content:\n\(filteredBody)\(note)"]
        } catch {
            // Erros de transporte não incluem request/URL com valores substituídos.
            return deny(Redactor.redact(error.localizedDescription, secrets: secrets))
        }
    }

    // MARK: - write_env

    func writeEnv(_ a: [String: Any]) -> [String: Any] {
        let project = a["project"] as? String
        let names = a["names"] as? [String]
        let pathArg = a["path"] as? String ?? ""
        func deny(_ why: String, _ sec: [String] = names ?? []) -> [String: Any] {
            record(AuditEntry(tool: "write_env", status: "denied", project: project, secrets: sec, command: pathArg, detail: why))
            return fail("Denied: \(why)")
        }
        let target: URL
        do { target = try EnvFile.validate(pathArg, cwd: a["cwd"] as? String) } catch { return deny("\(error.localizedDescription)") }

        let items = pick(project: project, names: names).filter { Policies.effective($0).allowEnv }
        guard !items.isEmpty else { return deny("no keys to write (name them, or check “allow .env / hosting” on the key)") }
        if let n = names, let miss = n.first(where: { x in !items.contains { $0.name == x } }) { return deny("\(miss) isn't available or isn't allowed in .env files") }

        let by: String
        do {
            // Aprovações são locais a este Broker e ligadas a destino + conjunto de chaves.
            // Reinício ou bloqueio observado exige nova presença. Nunca persistir consentimento em JSON.
            unlockLock.lock(); defer { unlockLock.unlock() }
            let session = vault.sessionIdentifier
            if session == nil || session != envSession { approvedEnvDestinations.removeAll() }
            envSession = session
            let destination = Sandbox.realPath(target.deletingLastPathComponent().path) + "/" + target.lastPathComponent
            let grant = destination + "|" + items.map { $0.id.uuidString }.sorted().joined(separator: ",")
            if !approvedEnvDestinations.contains(grant) {
                try freshUnlockHandler("Write keys to \(destination). Any process of your user can read them, including the agent.")
                envSession = vault.sessionIdentifier
                approvedEnvDestinations.insert(grant)
                by = "touch-id"
            } else {
                // Não chamar approve aqui: ele também adquire unlockLock.
                by = "session"
            }
        }
        catch { return deny("not approved (\(error.localizedDescription))", items.map(\.name)) }

        var vars: [(String, String)] = []
        for i in items {
            guard let v = try? store.secretValue(i) else { return deny("couldn't unlock \(i.name)", items.map(\.name)) }
            vars.append((i.name, v))
        }
        do {
            let warn = try EnvFile.write(vars, to: target)
            var e = AuditEntry(tool: "write_env", status: "ok", project: project, secrets: items.map(\.name), command: target.path)
            let exposure = "estes valores agora ficam legíveis por qualquer processo do seu usuário (incluindo o agente)"
            e.approvedBy = by; e.detail = exposure + (warn.map { "; " + $0 } ?? "")
            record(e)
            return ok("Warning: \(exposure)\nWrote \(vars.count) variable\(vars.count == 1 ? "" : "s") to \(target.path): \(vars.map(\.0).joined(separator: ", "))" + (warn.map { "\n⚠ \($0)" } ?? ""))
        } catch { return deny("write failed: \(error.localizedDescription)", items.map(\.name)) }
    }

    // MARK: - vercel_env

    func vercelEnv(_ a: [String: Any]) -> [String: Any] {
        let project = a["project"] as? String
        let cwd = a["cwd"] as? String
        let names = a["names"] as? [String]
        let targets = (a["targets"] as? [String]) ?? ["production", "preview", "development"]
        func deny(_ why: String, _ sec: [String] = names ?? []) -> [String: Any] {
            record(AuditEntry(tool: "vercel_env", status: "denied", project: project, secrets: sec, detail: why))
            return fail("Denied: \(why)")
        }
        guard targets.allSatisfy({ ["production", "preview", "development"].contains($0) }) else { return deny("targets must be production, preview or development") }

        // token da Vercel: item VERCEL_TOKEN (do projeto ou qualquer um)
        let all = store.items.filter { $0.kind == .secret && ($0.name.uppercased().contains("VERCEL") || ($0.service ?? "").lowercased() == "vercel") }
            .sorted { ($0.project == project ? 0 : 1, $1.createdAt) < ($1.project == project ? 0 : 1, $0.createdAt) }
        guard let tokenItem = all.first else { return deny("no Vercel token in Lockd — copy one from vercel.com/account/tokens first") }
        guard Policies.hostMatches("api.vercel.com", Policies.effective(tokenItem).hosts) else { return deny("\(tokenItem.name) isn't allowed to reach api.vercel.com") }

        var projectId = a["vercel_project"] as? String, teamId: String?
        if projectId == nil, let cwd {
            let f = URL(fileURLWithPath: (cwd as NSString).expandingTildeInPath).appendingPathComponent(".vercel/project.json")
            if let d = try? Data(contentsOf: f), let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
                projectId = j["projectId"] as? String
                if let org = j["orgId"] as? String, org.hasPrefix("team_") { teamId = org }
            }
        }
        guard let pid = projectId, !pid.isEmpty, pid.range(of: #"^[A-Za-z0-9_\-\.]+$"#, options: .regularExpression) != nil else {
            return deny("tell me the Vercel project (vercel_project) or a cwd with .vercel/project.json")
        }
        if let t = a["team"] as? String, t.hasPrefix("team_") { teamId = t }
        guard Policies.permitsHTTP(Policies.effective(tokenItem), host: "api.vercel.com", method: "POST", path: "/v10/projects/\(pid)/env") else {
            return deny("Vercel token policy does not allow POST to this exact project endpoint")
        }

        let items = pick(project: project, names: names).filter { $0.name != tokenItem.name && Policies.effective($0).allowEnv }
        guard !items.isEmpty else { return deny("no keys to push (name them, or check “allow .env / hosting” on the key)") }

        let by: String
        do { by = try approveHTTP(items + [tokenItem], host: "api.vercel.com", method: "POST") }
        catch { return deny("not approved (\(error.localizedDescription))", items.map(\.name)) }

        guard let token = try? store.secretValue(tokenItem) else { return deny("couldn't unlock the Vercel token") }
        var lines: [String] = [], failures = 0
        for i in items {
            guard let v = try? store.secretValue(i) else { lines.append("✗ \(i.name): couldn't unlock"); failures += 1; continue }
            let r = VercelPush.upsert(token: token, project: pid, team: teamId, name: i.name, value: v, targets: targets, client: httpClient)
            lines.append(r.ok ? "✓ \(i.name) → \(targets.joined(separator: "/"))" : "✗ \(i.name): \(Redactor.redact(r.detail, secrets: [(i.name, v), (tokenItem.name, token)]))")
            if !r.ok { failures += 1 }
        }
        var e = AuditEntry(tool: "vercel_env", status: failures == 0 ? "ok" : "error", project: project, secrets: items.map(\.name) + [tokenItem.name], command: "vercel project \(pid)")
        e.hosts = ["api.vercel.com"]; e.contacted = ["api.vercel.com"]; e.approvedBy = by
        record(e)
        return ["ok": failures == 0, "text": lines.joined(separator: "\n")]
    }

    // MARK: - add_secret (lockdctl add): guarda sem valor na linha de comando; nasce SEM regra assinada, então o agente não pode usá-la

    func addSecret(_ a: [String: Any]) -> [String: Any] {
        guard let raw = a["value"] as? String, !raw.isEmpty, raw.utf8.count <= 20_000 else { return fail("value is required (send it on stdin)") }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let name = (a["name"] as? String).flatMap { isEnvName($0) ? $0 : nil }
        let project = (a["project"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        var det = Detector.detect(in: value).first
        if det == nil {
            guard let n = name else { return fail("Couldn't recognize this value. Pass --name NAME (letters, digits, _).") }
            det = Detection(envName: n, service: (a["service"] as? String) ?? "Manual", type: "Secret", value: value, confident: true)
        } else if let n = name { det!.envName = n }
        guard let d = det else { return fail("nothing to save") }
        do {
            let r = try store.saveSecret(d, project: project, source: "lockdctl add")
            record(AuditEntry(tool: "add_secret", status: "ok", project: project, secrets: [d.envName], detail: r.isNew ? "saved (rules not signed yet)" : "already in Lockd"))
            return ok(r.isNew ? "Saved \(d.envName)\(project.map { " in \($0)" } ?? "") — \(d.service). Agent access stays off until you sign its rules in Lockd."
                              : "\(d.envName) is already in Lockd.")
        } catch { return fail("couldn't save: \(error.localizedDescription)") }
    }

    // MARK: - Enviar à Vercel (ação do USUÁRIO na interface; um Touch ID por envio; não passa pelas regras do agente)

    public struct VercelSendResult: Identifiable, Sendable { public let id = UUID(); public var name: String; public var ok: Bool; public var detail: String }
    public struct UserActionError: Error, LocalizedError { public let message: String; public var errorDescription: String? { message } }

    public func sendToVercel(project: String, names: [String], vercelProject: String, team: String?, targets: [String]) throws -> [VercelSendResult] {
        guard vercelProject.range(of: #"^[A-Za-z0-9_\-\.]+$"#, options: .regularExpression) != nil else { throw UserActionError(message: "Invalid Vercel project name or id.") }
        guard !targets.isEmpty, targets.allSatisfy({ ["production", "preview", "development"].contains($0) }) else { throw UserActionError(message: "Pick production, preview and/or development.") }
        let tokens = store.items.filter { $0.kind == .secret && ($0.name.uppercased().contains("VERCEL") || ($0.service ?? "").lowercased() == "vercel") }
            .sorted { ($0.project == project ? 0 : 1, $1.createdAt) < ($1.project == project ? 0 : 1, $0.createdAt) }
        guard let tokenItem = tokens.first else { throw UserActionError(message: "No Vercel token in Lockd. Copy one from vercel.com/account/tokens first.") }
        let items = pick(project: project, names: names).filter { $0.name != tokenItem.name }
        guard !items.isEmpty else { throw UserActionError(message: "No keys selected.") }

        do { try freshUnlockHandler("Send \(items.count) key\(items.count == 1 ? "" : "s") to Vercel (\(vercelProject)). You pressed Send.") }
        catch { throw UserActionError(message: "Not approved.") }
        guard let token = try? store.secretValue(tokenItem) else { throw UserActionError(message: "Couldn't unlock the Vercel token.") }

        var results: [VercelSendResult] = []
        for i in items {
            guard let v = try? store.secretValue(i) else { results.append(VercelSendResult(name: i.name, ok: false, detail: "couldn't unlock")); continue }
            let r = VercelPush.upsert(token: token, project: vercelProject, team: team, name: i.name, value: v, targets: targets, client: httpClient)
            results.append(VercelSendResult(name: i.name, ok: r.ok, detail: r.ok ? "sent to \(targets.joined(separator: "/"))" : Redactor.redact(r.detail, secrets: [(i.name, v), (tokenItem.name, token)])))
        }
        var e = AuditEntry(tool: "vercel_push", status: results.allSatisfy(\.ok) ? "ok" : "error", project: project, secrets: items.map(\.name) + [tokenItem.name],
                           command: "vercel project \(vercelProject)", detail: "sent by you from the Lockd window")
        e.hosts = ["api.vercel.com"]; e.contacted = ["api.vercel.com"]; e.approvedBy = "touch-id"
        record(e)
        return results
    }

    // MARK: - Navegador (extensão): o valor vai do cofre para o campo da página; o agente só recebe "preenchido"

    static let hostPattern = try! NSRegularExpression(pattern: #"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$"#)

    func browserFill(_ a: [String: Any]) -> [String: Any] {
        let project = a["project"] as? String
        let name = (a["name"] as? String) ?? ""
        let host = ((a["host"] as? String) ?? "").lowercased()
        let selector = (a["selector"] as? String) ?? ""
        let submit = (a["submit_selector"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        func deny(_ why: String) -> [String: Any] {
            record(AuditEntry(tool: "browser_fill", status: "denied", project: project, secrets: name.isEmpty ? [] : [name], command: host, detail: why))
            return fail("Denied: " + why)
        }
        guard isEnvName(name) else { return deny("name must be the key's name (e.g. STRIPE_SECRET_KEY)") }
        guard Self.hostPattern.firstMatch(in: host, range: NSRange(host.startIndex..., in: host)) != nil else { return deny("host must be an exact hostname like dashboard.stripe.com") }
        guard !selector.isEmpty, selector.count <= 300, (submit?.count ?? 0) <= 300 else { return deny("selector must be a CSS selector up to 300 characters") }
        guard let item = pick(project: project, names: [name]).first else { return deny("no such key in \(project ?? "any project")") }
        let policy = Policies.effective(item)
        guard Policies.rulesVerified(item), Policies.hostMatches(host, policy.hosts) else {
            return deny("\(name) has no signed rule for \(host). Add that host in Lockd → \(name) → Claude access, then sign (Touch ID).")
        }
        guard policy.methods == nil else { return deny("\(name) is limited to specific HTTP methods, so it can't be typed into a page") }
        guard bridge.isConnected else {
            return deny("the Lockd browser extension isn't connected. Open Chrome with the extension installed (Lockd → Settings → Browser).")
        }
        let by: String
        do {
            unlockLock.lock(); defer { unlockLock.unlock() }
            let current = vault.sessionIdentifier
            if current == nil || current != fillSession { approvedFill.removeAll() }
            let grant = item.id.uuidString + "|" + host + "|" + (item.ruleSignature ?? "")
            if approvedFill.contains(grant) { by = "session" }
            else {
                try freshUnlockHandler("Agent wants to type \(name) into \(host)")
                approvedFill.insert(grant); by = "touch-id"
            }
            fillSession = vault.sessionIdentifier
        } catch { return deny("Fresh authentication was not approved") }
        guard let value = try? store.secretValue(item) else { return deny("couldn't unlock \(name)") }
        var cmd: [String: Any] = ["kind": "fill", "host": host, "selector": selector, "value": value]
        if let submit { cmd["submit"] = submit }
        let r = bridge.request(cmd)
        let okFill = r["ok"] as? Bool ?? false
        let detail = Redactor.redact((r["text"] as? String) ?? "", secrets: [(name, value)])
        var e = AuditEntry(tool: "browser_fill", status: okFill ? "ok" : "error", project: project, secrets: [name], command: "\(host) \(selector)", detail: detail)
        e.hosts = [host]; e.approvedBy = by; record(e)
        return okFill ? ok("Filled \(selector) on \(host) with \(name)." + (submit != nil ? " Clicked \(submit!)." : "") + " The value was never shown to you.")
                      : fail("Couldn't fill: \(detail.isEmpty ? "unknown error" : detail)")
    }

    /// Agente pede: "salve a chave que está aparecendo na página". A extensão devolve os valores; eles vão direto ao cofre.
    func browserCapture(_ a: [String: Any]) -> [String: Any] {
        let r = bridge.request(["kind": "harvest"])
        guard r["ok"] as? Bool ?? false else { return fail((r["text"] as? String) ?? "browser did not answer") }
        let host = (r["host"] as? String) ?? "page"
        let cands = (r["candidates"] as? [String]) ?? []
        return ok(saveFromBrowser(host: host, candidates: cands, project: a["project"] as? String, name: a["name"] as? String, tool: "browser_capture"))
    }

    /// Salva o que a extensão achou. Chaves entram SEM regra assinada: o agente não pode usá-las até o usuário assinar no app.
    func saveFromBrowser(host: String, candidates: [String], project: String?, name: String?, tool: String) -> String {
        let proj = (project.flatMap { $0.isEmpty ? nil : $0 }) ?? currentProject()
        var saved: [String] = [], dupes = 0, unsure = 0
        var seen = Set<String>()
        for c in candidates.prefix(20) where seen.insert(c).inserted {
            for var d in Detector.detect(in: c) {
                guard d.confident else { unsure += 1; continue }
                if let n = name, isEnvName(n), candidates.count == 1 { d.envName = n }
                if let r = try? store.saveSecret(d, project: proj, source: "browser: \(host)") {
                    if r.isNew { saved.append(d.envName + " (" + Detector.preview(d.value) + ")") } else { dupes += 1 }
                }
            }
        }
        record(AuditEntry(tool: tool, status: saved.isEmpty ? "error" : "ok", project: proj, secrets: saved.map { String($0.split(separator: " ").first ?? "") },
                          command: host, detail: "saved \(saved.count), already there \(dupes), unsure \(unsure); rules not signed yet"))
        if saved.isEmpty {
            if dupes > 0 { return "Already in Lockd." }
            return unsure > 0 ? "Found something that looks like a key but I'm not sure. Copy it and use Lockd → Add secret." : "No API key found on the page."
        }
        return "Saved \(saved.joined(separator: ", "))\(proj.map { " in \($0)" } ?? ""). Agent access stays off until you sign its rules in Lockd."
    }
}
