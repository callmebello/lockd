import Foundation

/// Supabase e Vercel falam com o Lockd por HTTPS, dentro do app. O agente nunca recebe a chave e não precisa de
/// `psql`: `psql` é recusado de propósito (tem `\!` que abre shell, e a porta 5432 não passa pelo filtro de hosts).
/// O equivalente seguro é a Management API do Supabase, que roda SQL por HTTPS com um access token.

public enum SupabaseAPI {
    static var base: String {
        #if DEBUG
        if ProcessInfo.processInfo.environment["LOCKD_HOME"] != nil, let b = ProcessInfo.processInfo.environment["LOCKD_SUPABASE_BASE"] { return b }
        #endif
        return "https://api.supabase.com"
    }

    /// Ref do projeto Supabase: 20 letras minúsculas (ex.: abcdefghijklmnopqrst).
    public static func validRef(_ s: String) -> Bool { s.range(of: #"^[a-z]{20}$"#, options: .regularExpression) != nil }

    /// A regra do token precisa estar presa a ESTE projeto: o token `sbp_` é da conta inteira.
    static func pins(_ prefix: String, ref: String) -> Bool {
        prefix == "/v1/projects/\(ref)" || prefix.hasPrefix("/v1/projects/\(ref)/")
    }

    /// Leitura = uma única instrução que começa com SELECT/WITH/SHOW/EXPLAIN/VALUES/TABLE, sem nenhuma palavra que escreva
    /// ou bloqueie e chamando apenas funções da lista segura. Lê o SQL como o Postgres lê (textos, comentários aninhados,
    /// $$…$$, E'…'), não por expressões regulares. Qualquer dúvida = tratado como escrita (Touch ID a cada chamada).
    public static func isReadOnly(_ sql: String) -> Bool { analyze(sql).readOnly }

    public static func analyze(_ sql: String) -> SQLShape {
        var shape = SQLShape()
        guard sql.utf8.count <= 100_000 else { shape.valid = false; return shape }
        let (tokens, valid) = SQLLexer.lex(sql)
        shape.valid = valid
        var statements: [[SQLLexer.Token]] = [[]]
        for t in tokens { if t.kind == .semicolon { statements.append([]) } else { statements[statements.count - 1].append(t) } }
        let filled = statements.filter { !$0.isEmpty }
        shape.statements = filled.count
        if let t = filled.first?.first, t.kind == .word { shape.firstKeyword = t.text.lowercased() }
        shape.normalized = tokens.map { $0.kind == .semicolon ? ";" : $0.text }.joined(separator: " ")

        for (i, t) in tokens.enumerated() {
            let next = i + 1 < tokens.count ? tokens[i + 1] : nil
            let callsNext = next?.kind == .symbol && next?.text == "("
            if t.kind == .word {
                let w = t.text.lowercased()
                if SQLShape.dangerousWords.contains(w), !shape.dangerous.contains(w) { shape.dangerous.append(w) }
                if callsNext, !SQLShape.notFunctions.contains(w) {
                    var name = w, k = i
                    while k >= 2, tokens[k - 1].kind == .symbol, tokens[k - 1].text == ".", tokens[k - 2].kind == .word || tokens[k - 2].kind == .quoted {
                        name = tokens[k - 2].text.lowercased() + "." + name; k -= 2
                    }
                    shape.functions.append(name)
                    if name.contains(".") || !SQLShape.safeFunctions.contains(name) { shape.unapprovedFunctions.append(name) }
                }
            } else if t.kind == .quoted, callsNext {
                shape.functions.append(t.text); shape.unapprovedFunctions.append(t.text)
            }
        }
        return shape
    }

    /// Texto do pedido de Touch ID para escrita: o que importa (verbos, quantas instruções, tamanho) vem ANTES do trecho do SQL.
    static func writePrompt(ref: String, shape: SQLShape, bytes: Int) -> String {
        var parts = ["Agent wants to CHANGE database \(ref)"]
        if !shape.valid { parts.append("UNREADABLE SQL (may hide statements)") }
        parts.append("\(shape.statements) statement\(shape.statements == 1 ? "" : "s")")
        if !shape.dangerous.isEmpty { parts.append(shape.dangerous.prefix(6).map { $0.uppercased() }.joined(separator: ",")) }
        if let f = shape.unapprovedFunctions.first { parts.append("calls \(f)") }
        parts.append(bytes >= 1024 ? "\(bytes / 1024) KB" : "\(bytes) B")
        return parts.joined(separator: " · ") + ": " + String(shape.normalized.prefix(60))
    }
}

public struct SQLShape: Equatable {
    public var valid = true                   // false: string ou comentário aberto, SQL grande demais
    public var statements = 0
    public var firstKeyword = ""
    public var dangerous: [String] = []        // palavras que escrevem/bloqueiam, fora de textos e comentários
    public var functions: [String] = []
    public var unapprovedFunctions: [String] = []
    public var normalized = ""                 // sem comentários, espaços colapsados

    public var readOnly: Bool {
        valid && statements == 1 && Self.readStarts.contains(firstKeyword) && dangerous.isEmpty && unapprovedFunctions.isEmpty
    }

    static let readStarts: Set<String> = ["select", "with", "show", "explain", "values", "table"]
    static let dangerousWords: Set<String> = [
        "insert", "update", "delete", "merge", "into", "truncate", "drop", "alter", "create", "grant", "revoke", "copy", "call", "do",
        "set", "reset", "vacuum", "refresh", "lock", "share", "comment", "analyze", "notify", "listen", "unlisten", "execute",
        "prepare", "security", "load", "cluster", "reindex", "discard", "checkpoint", "begin", "commit", "rollback", "savepoint",
    ]
    /// Palavras que podem vir antes de "(" sem serem função.
    static let notFunctions: Set<String> = [
        "in", "exists", "over", "any", "all", "some", "values", "as", "and", "or", "not", "from", "where", "join", "on", "using", "when",
        "then", "else", "case", "select", "distinct", "by", "having", "limit", "offset", "union", "intersect", "except", "between",
        "like", "ilike", "similar", "to", "is", "filter", "within", "group", "order", "partition", "rows", "range", "array", "row",
        "lateral", "with", "recursive", "cross", "inner", "outer", "natural", "materialized", "unnest", "table", "only", "fetch", "first", "explain", "show",
    ]
    /// Funções puras (sem efeito colateral nem acesso a arquivos/rede). Qualquer outra, ou qualquer função com schema, vira escrita.
    static let safeFunctions: Set<String> = [
        "count", "sum", "avg", "min", "max", "coalesce", "nullif", "greatest", "least", "lower", "upper", "length", "char_length",
        "substring", "substr", "concat", "concat_ws", "left", "right", "trim", "ltrim", "rtrim", "replace", "split_part", "position",
        "lpad", "rpad", "initcap", "md5", "abs", "round", "ceil", "ceiling", "floor", "trunc", "mod", "power", "sqrt", "now",
        "date_trunc", "date_part", "extract", "age", "to_char", "to_date", "to_timestamp", "to_number", "cast",
        "array_agg", "string_agg", "json_agg", "jsonb_agg", "json_build_object", "jsonb_build_object", "json_build_array",
        "jsonb_build_array", "to_json", "to_jsonb", "row_to_json", "json_extract_path_text", "jsonb_extract_path_text",
        "jsonb_array_length", "json_array_length", "array_length", "cardinality", "array_to_string", "string_to_array",
        "row_number", "rank", "dense_rank", "lag", "lead", "first_value", "last_value", "ntile", "bool_and", "bool_or", "every",
        "regexp_replace", "format", "pg_typeof", "version", "current_database", "current_setting",
        "varchar", "character", "char", "numeric", "decimal", "timestamp", "timestamptz", "time", "timetz", "interval", "bit", "varbit", "float",
    ]
}

/// Leitor de SQL do Postgres: textos '…', E'…', U&'…', $tag$…$tag$, "identificadores", comentários -- e /* /* aninhados */ */.
enum SQLLexer {
    enum Kind { case word, quoted, string, number, symbol, param, semicolon }
    struct Token { let kind: Kind; let text: String }

    static func lex(_ sql: String) -> (tokens: [Token], valid: Bool) {
        let b = Array(sql.utf8), n = b.count
        var tokens: [Token] = [], i = 0
        func text(_ s: Int, _ e: Int) -> String { String(decoding: b[s..<e], as: UTF8.self) }
        func isStart(_ c: UInt8) -> Bool { (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == 95 || c >= 0x80 }
        func isDigit(_ c: UInt8) -> Bool { c >= 48 && c <= 57 }
        /// Fim de um texto '…' começando em `from` (aspas de abertura já em b[from-1]). nil = sem fechamento.
        func endOfString(_ from: Int, escapes: Bool) -> Int? {
            var j = from
            while j < n {
                if escapes && b[j] == 92 { j += 2; continue }
                if b[j] == 39 { if j + 1 < n && b[j + 1] == 39 { j += 2; continue }; return j + 1 }
                j += 1
            }
            return nil
        }
        while i < n {
            let c = b[i]
            if c == 32 || c == 9 || c == 10 || c == 13 || c == 12 || c == 11 { i += 1; continue }
            if c == 45, i + 1 < n, b[i + 1] == 45 { while i < n, b[i] != 10 { i += 1 }; continue }
            if c == 47, i + 1 < n, b[i + 1] == 42 {
                var depth = 1; i += 2
                while i < n, depth > 0 {
                    if b[i] == 47, i + 1 < n, b[i + 1] == 42 { depth += 1; i += 2 }
                    else if b[i] == 42, i + 1 < n, b[i + 1] == 47 { depth -= 1; i += 2 }
                    else { i += 1 }
                }
                if depth > 0 { return (tokens, false) }
                continue
            }
            if c == 39 {
                guard let e = endOfString(i + 1, escapes: false) else { return (tokens, false) }
                tokens.append(Token(kind: .string, text: text(i, e))); i = e; continue
            }
            if c == 34 {
                var j = i + 1
                while j < n { if b[j] == 34 { if j + 1 < n, b[j + 1] == 34 { j += 2; continue }; break }; j += 1 }
                guard j < n else { return (tokens, false) }
                tokens.append(Token(kind: .quoted, text: text(i, j + 1))); i = j + 1; continue
            }
            if isStart(c) {
                var j = i + 1
                while j < n, isStart(b[j]) || isDigit(b[j]) || b[j] == 36 { j += 1 }
                let w = text(i, j)
                if (w == "e" || w == "E"), j < n, b[j] == 39 {                    // E'…' aceita \' como escape
                    guard let e = endOfString(j + 1, escapes: true) else { return (tokens, false) }
                    tokens.append(Token(kind: .string, text: text(i, e))); i = e; continue
                }
                if (w == "u" || w == "U"), j + 1 < n, b[j] == 38, b[j + 1] == 39 { // U&'…'
                    guard let e = endOfString(j + 2, escapes: false) else { return (tokens, false) }
                    tokens.append(Token(kind: .string, text: text(i, e))); i = e; continue
                }
                tokens.append(Token(kind: .word, text: w)); i = j; continue
            }
            if isDigit(c) {
                var j = i + 1
                while j < n, isStart(b[j]) || isDigit(b[j]) || b[j] == 46 { j += 1 }
                tokens.append(Token(kind: .number, text: text(i, j))); i = j; continue
            }
            if c == 36 {
                var j = i + 1
                if j < n, isDigit(b[j]) {
                    while j < n, isDigit(b[j]) { j += 1 }
                    tokens.append(Token(kind: .param, text: text(i, j))); i = j; continue
                }
                if j < n, isStart(b[j]) { j += 1; while j < n, (isStart(b[j]) || isDigit(b[j])) && b[j] != 36 { j += 1 } }
                if j < n, b[j] == 36 {                                             // $tag$ … $tag$
                    let tag = Array(b[i...j]); var k = j + 1, found: Int?
                    while k + tag.count <= n { if Array(b[k..<(k + tag.count)]) == tag { found = k + tag.count; break }; k += 1 }
                    guard let e = found else { return (tokens, false) }
                    tokens.append(Token(kind: .string, text: text(i, e))); i = e; continue
                }
                tokens.append(Token(kind: .symbol, text: "$")); i += 1; continue
            }
            if c == 59 { tokens.append(Token(kind: .semicolon, text: ";")); i += 1; continue }
            if c == 0 { return (tokens, false) }
            tokens.append(Token(kind: .symbol, text: text(i, i + 1))); i += 1
        }
        return (tokens, true)
    }
}

extension Broker {
    // MARK: - supabase_sql

    func supabaseSQL(_ a: [String: Any]) -> [String: Any] {
        let project = a["project"] as? String
        let query = (a["query"] as? String ?? "")
        let ref = (a["project_ref"] as? String ?? "").lowercased()
        let keyName = a["key"] as? String
        func deny(_ why: String, _ sec: [String] = []) -> [String: Any] {
            record(AuditEntry(tool: "supabase_sql", status: "denied", project: project, secrets: sec, command: "ref=\(ref)", detail: why))
            return fail("Denied: \(why)")
        }
        guard SupabaseAPI.validRef(ref) else { return deny("project_ref must be the 20-letter Supabase project ref (the abcd… part of abcd….supabase.co)") }
        guard !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, query.utf8.count <= 100_000 else { return deny("query is empty or larger than 100 KB") }

        // token de acesso do Supabase (sbp_…): chave do serviço Supabase cujo nome indica token/access
        let candidates = store.items.filter { i in
            i.kind == .secret && (i.service ?? "").lowercased() == "supabase" && (keyName == nil || i.name == keyName) &&
                (keyName != nil || ["TOKEN", "ACCESS", "PAT"].contains { i.name.uppercased().contains($0) })
        }.sorted { ($0.project == project ? 0 : 1, $1.createdAt) < ($1.project == project ? 0 : 1, $0.createdAt) }
        guard let tokenItem = candidates.first else {
            return deny("no Supabase access token in Lockd. Create one at supabase.com/dashboard/account/tokens and copy it (starts with sbp_). A service_role key or the database password can't run SQL through this tool.")
        }
        let path = "/v1/projects/\(ref)/database/query"
        guard Policies.rulesVerified(tokenItem), Policies.permitsHTTP(Policies.effective(tokenItem), host: "api.supabase.com", method: "POST", path: path) else {
            return deny("\(tokenItem.name) has no signed rule for POST api.supabase.com\(path). Open it in Lockd → Agent access and sign the rules.", [tokenItem.name])
        }

        guard (tokenItem.allowedPathPrefixes ?? []).contains(where: { SupabaseAPI.pins($0, ref: ref) }) else {
            return deny("\(tokenItem.name) must be pinned to this project. In Lockd → Agent access set \"HTTP path prefixes\" to /v1/projects/\(ref) and sign the rule. The sbp_ token covers your whole account.", [tokenItem.name])
        }

        let shape = SupabaseAPI.analyze(query)
        let readOnly = shape.readOnly
        let preview = String(shape.normalized.prefix(100))
        let by: String
        do {
            if readOnly { by = try approveHTTP([tokenItem], host: "api.supabase.com", method: "POST") }
            else {
                // Escrita: Touch ID a CADA chamada, mostrando o início do SQL.
                try freshUnlockHandler(SupabaseAPI.writePrompt(ref: ref, shape: shape, bytes: query.utf8.count))
                by = "touch-id"
            }
        } catch { return deny("not approved (\(error.localizedDescription))", [tokenItem.name]) }

        guard let token = try? store.secretValue(tokenItem) else { return deny("couldn't unlock \(tokenItem.name)", [tokenItem.name]) }
        let secrets = [(tokenItem.name, token)]
        do {
            let body = try JSONSerialization.data(withJSONObject: ["query": query])
            let url = SupabaseAPI.base + path
            let response = try httpClient.perform(method: "POST", url: url,
                headers: ["Authorization": "Bearer \(token)", "Content-Type": "application/json"], body: body,
                hosts: [URL(string: url)?.host ?? "api.supabase.com"], timeout: 60)
            let text = response.binary ? "(binary response omitted)" : Redactor.redact(String(decoding: response.data, as: UTF8.self), secrets: secrets)
            let ok = (200..<300).contains(response.status)
            var e = AuditEntry(tool: "supabase_sql", status: ok ? "ok" : "error", project: project, secrets: [tokenItem.name],
                               command: "\(readOnly ? "read" : "WRITE") ref=\(ref) · \(Redactor.redact(preview, secrets: secrets))")
            e.hosts = ["api.supabase.com"]; e.contacted = ["api.supabase.com"]; e.approvedBy = by; record(e)
            let note = response.truncated ? "\n[response truncated at 1 MB]" : ""
            return ["ok": ok, "status": response.status, "text": "HTTP \(response.status) · \(readOnly ? "read-only query" : "write query") on \(ref)\nUntrusted database content:\n\(text)\(note)"]
        } catch {
            return deny(Redactor.redact(error.localizedDescription, secrets: secrets), [tokenItem.name])
        }
    }

    // MARK: - vercel_read (somente leitura)

    func vercelRead(_ a: [String: Any]) -> [String: Any] {
        let project = a["project"] as? String
        let resource = a["resource"] as? String ?? ""
        func deny(_ why: String, _ sec: [String] = []) -> [String: Any] {
            record(AuditEntry(tool: "vercel_read", status: "denied", project: project, secrets: sec, command: resource, detail: why))
            return fail("Denied: \(why)")
        }
        guard ["projects", "deployments", "env", "domains"].contains(resource) else { return deny("resource must be projects, deployments, env or domains") }

        let all = store.items.filter { $0.kind == .secret && ($0.name.uppercased().contains("VERCEL") || ($0.service ?? "").lowercased() == "vercel") }
            .sorted { ($0.project == project ? 0 : 1, $1.createdAt) < ($1.project == project ? 0 : 1, $0.createdAt) }
        guard let tokenItem = all.first else { return deny("no Vercel token in Lockd — copy one from vercel.com/account/tokens first") }

        var projectId = a["vercel_project"] as? String, teamId = (a["team"] as? String).flatMap { $0.hasPrefix("team_") ? $0 : nil }
        if projectId == nil, let cwd = a["cwd"] as? String {
            let f = URL(fileURLWithPath: (cwd as NSString).expandingTildeInPath).appendingPathComponent(".vercel/project.json")
            if let d = try? Data(contentsOf: f), let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
                projectId = j["projectId"] as? String
                if teamId == nil, let org = j["orgId"] as? String, org.hasPrefix("team_") { teamId = org }
            }
        }
        let idPattern = #"^[A-Za-z0-9_\-\.]+$"#
        var path: String
        var query: [URLQueryItem] = []
        let limit = max(1, min((a["limit"] as? Int) ?? 20, 100))
        switch resource {
        case "projects": path = "/v9/projects"; query = [URLQueryItem(name: "limit", value: String(limit))]
        default:
            guard let pid = projectId, pid.range(of: idPattern, options: .regularExpression) != nil else {
                return deny("tell me the Vercel project (vercel_project) or a cwd with .vercel/project.json", [tokenItem.name])
            }
            switch resource {
            case "deployments": path = "/v6/deployments"; query = [URLQueryItem(name: "projectId", value: pid), URLQueryItem(name: "limit", value: String(limit))]
            case "env": path = "/v10/projects/\(pid)/env"
            default: path = "/v9/projects/\(pid)/domains"
            }
        }
        guard Policies.rulesVerified(tokenItem), Policies.permitsHTTP(Policies.effective(tokenItem), host: "api.vercel.com", method: "GET", path: path) else {
            return deny("\(tokenItem.name) has no signed rule for GET api.vercel.com\(path). Sign it in Lockd → Agent access.", [tokenItem.name])
        }
        if let t = teamId { query.append(URLQueryItem(name: "teamId", value: t)) }
        var comps = URLComponents(string: VercelPush.base + path)!
        comps.queryItems = query.isEmpty ? nil : query
        guard let url = comps.url, let host = url.host else { return deny("bad URL", [tokenItem.name]) }

        let by: String
        do { by = try approveHTTP([tokenItem], host: "api.vercel.com", method: "GET") }
        catch { return deny("not approved (\(error.localizedDescription))", [tokenItem.name]) }
        guard let token = try? store.secretValue(tokenItem) else { return deny("couldn't unlock \(tokenItem.name)", [tokenItem.name]) }
        let secrets = [(tokenItem.name, token)]
        do {
            let r = try httpClient.perform(method: "GET", url: url.absoluteString, headers: ["Authorization": "Bearer \(token)"], body: nil, hosts: [host], timeout: 30)
            var e = AuditEntry(tool: "vercel_read", status: (200..<300).contains(r.status) ? "ok" : "error", project: project, secrets: [tokenItem.name], command: "GET \(path)")
            e.hosts = ["api.vercel.com"]; e.contacted = ["api.vercel.com"]; e.approvedBy = by; record(e)
            guard (200..<300).contains(r.status) else { return fail("HTTP \(r.status)") }
            let summary = Self.summarizeVercel(resource, r.data)
            return ok("Untrusted Vercel content (values are never returned):\n" + Redactor.redact(summary, secrets: secrets))
        } catch { return deny(Redactor.redact(error.localizedDescription, secrets: secrets), [tokenItem.name]) }
    }

    /// Só campos úteis e sem valores: variáveis de ambiente voltam apenas com nome, tipo e alvos.
    static func summarizeVercel(_ resource: String, _ data: Data) -> String {
        guard let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return "(unreadable response)" }
        func date(_ v: Any?) -> String {
            guard let ms = v as? Double ?? (v as? Int).map(Double.init) else { return "-" }
            return ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: ms / 1000))
        }
        switch resource {
        case "projects":
            return ((j["projects"] as? [[String: Any]]) ?? []).map { p in
                "\(p["name"] ?? "?")\t\(p["id"] ?? "")\t\(p["framework"] as? String ?? "-")\tupdated \(date(p["updatedAt"]))"
            }.joined(separator: "\n")
        case "deployments":
            return ((j["deployments"] as? [[String: Any]]) ?? []).map { d in
                "\(d["uid"] ?? "?")\t\(d["state"] ?? d["readyState"] ?? "-")\t\(d["target"] as? String ?? "preview")\t\(d["url"] as? String ?? "-")\t\(date(d["created"]))"
            }.joined(separator: "\n")
        case "env":
            return ((j["envs"] as? [[String: Any]]) ?? []).map { v in
                "\(v["key"] ?? "?")\t\(v["type"] ?? "-")\t\((v["target"] as? [String])?.joined(separator: "/") ?? "-")"
            }.joined(separator: "\n")
        default:
            return ((j["domains"] as? [[String: Any]]) ?? []).map { d in "\(d["name"] ?? "?")\tverified=\(d["verified"] ?? "-")" }.joined(separator: "\n")
        }
    }
}
