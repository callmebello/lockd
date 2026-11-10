import Foundation

public struct Detection: Sendable, Equatable {
    public var envName: String
    public var service: String
    public var type: String
    public var value: String
    public var confident: Bool       // false → pede confirmação em vez de salvar sozinho
    public var expiresAt: Date?
    public var note: String?

    public init(envName: String, service: String, type: String, value: String, confident: Bool,
                expiresAt: Date? = nil, note: String? = nil) {
        self.envName = envName; self.service = service; self.type = type; self.value = value
        self.confident = confident; self.expiresAt = expiresAt; self.note = note
    }
}

/// Reconhece chaves/tokens copiados. Padrões inspirados nas regras do gitleaks (MIT).
public enum Detector {
    struct Rule { let service: String; let type: String; let env: String; let regex: NSRegularExpression }

    // Ordem importa: os mais específicos primeiro (sk-ant antes de sk-).
    static let rules: [Rule] = {
        let defs: [(String, String, String, String)] = [
            ("Anthropic", "API key", "ANTHROPIC_API_KEY", #"sk-ant-[A-Za-z0-9_\-]{20,}"#),
            ("OpenRouter", "API key", "OPENROUTER_API_KEY", #"sk-or-v1-[a-f0-9]{40,}"#),
            ("OpenAI", "API key", "OPENAI_API_KEY", #"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}"#),
            ("Google Gemini", "API key", "GEMINI_API_KEY", #"AIza[0-9A-Za-z_\-]{35}"#),
            ("Google", "OAuth client secret", "GOOGLE_CLIENT_SECRET", #"GOCSPX-[A-Za-z0-9_\-]{20,}"#),
            ("GitHub", "Token", "GITHUB_TOKEN", #"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})"#),
            ("Stripe", "Secret key", "STRIPE_SECRET_KEY", #"[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"#),
            ("Stripe", "Publishable key", "STRIPE_PUBLISHABLE_KEY", #"pk_(?:live|test)_[A-Za-z0-9]{16,}"#),
            ("Stripe", "Webhook secret", "STRIPE_WEBHOOK_SECRET", #"whsec_[A-Za-z0-9]{20,}"#),
            ("ElevenLabs", "API key", "ELEVENLABS_API_KEY", #"sk_[a-f0-9]{40,}"#),
            ("AWS", "Access key ID", "AWS_ACCESS_KEY_ID", #"(?:AKIA|ASIA)[0-9A-Z]{16}"#),
            ("Slack", "Token", "SLACK_TOKEN", #"xox[baprs]-[A-Za-z0-9\-]{10,}"#),
            ("Supabase", "Access token", "SUPABASE_ACCESS_TOKEN", #"sbp_[a-f0-9]{40}"#),
            ("Supabase", "API key", "SUPABASE_KEY", #"sb_(?:secret|publishable)_[A-Za-z0-9_\-]{20,}"#),
            ("Resend", "API key", "RESEND_API_KEY", #"re_[A-Za-z0-9_]{20,}"#),
            ("Hugging Face", "Token", "HF_TOKEN", #"hf_[A-Za-z0-9]{30,}"#),
            ("Groq", "API key", "GROQ_API_KEY", #"gsk_[A-Za-z0-9]{40,}"#),
            ("xAI", "API key", "XAI_API_KEY", #"xai-[A-Za-z0-9]{40,}"#),
            ("Perplexity", "API key", "PERPLEXITY_API_KEY", #"pplx-[A-Za-z0-9]{40,}"#),
            ("Replicate", "API token", "REPLICATE_API_TOKEN", #"r8_[A-Za-z0-9]{30,}"#),
            ("SendGrid", "API key", "SENDGRID_API_KEY", #"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"#),
            ("npm", "Token", "NPM_TOKEN", #"npm_[A-Za-z0-9]{36}"#),
            ("Brevo", "API key", "BREVO_API_KEY", #"xkeysib-[a-f0-9]{40,}-[A-Za-z0-9]+"#),
            ("Mercado Pago", "Access token", "MP_ACCESS_TOKEN", #"APP_USR-[0-9]{8,}-[0-9]{6}-[a-f0-9]{32}-[0-9]+"#),
            ("Mercado Pago", "Public key", "MP_PUBLIC_KEY", #"APP_USR-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#),
            ("fal.ai", "API key", "FAL_KEY", #"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[0-9a-f]{32}"#),
            ("Database", "Connection URL", "DATABASE_URL", #"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqp)://[^\s:/@]+:[^\s@]+@\S+"#),
        ]
        return defs.compactMap { d in
            (try? NSRegularExpression(pattern: "^(?:" + d.3 + ")$")).map { Rule(service: d.0, type: d.1, env: d.2, regex: $0) }
        }
    }()

    static let assignment = try! NSRegularExpression(pattern: #"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]{2,})\s*[=:]\s*(.+?)\s*$"#)
    static let envName = try! NSRegularExpression(pattern: #"^[A-Z][A-Z0-9_]{2,}$"#)

    public static func detect(in raw: String) -> [Detection] {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.count <= 20_000 else { return [] }
        if text.contains("-----BEGIN"), let pem = privateKey(text) { return [pem] }

        let lines = text.split(whereSeparator: \.isNewline).map(String.init)
        if lines.count == 1 {
            if let kv = parseAssignment(lines[0]) { return detectValue(kv.value, name: kv.name).map { [$0] } ?? [] }
            return detectValue(text, name: nil).map { [$0] } ?? []
        }
        guard lines.count <= 80 else { return [] }
        var seen = Set<String>(), out: [Detection] = []
        for line in lines {
            guard let kv = parseAssignment(line), let d = detectValue(kv.value, name: kv.name), seen.insert(d.value).inserted else { continue }
            out.append(d)
        }
        return out
    }

    static func parseAssignment(_ line: String) -> (name: String, value: String)? {
        let r = NSRange(line.startIndex..., in: line)
        guard let m = assignment.firstMatch(in: line, range: r),
              let n = Range(m.range(at: 1), in: line), let v = Range(m.range(at: 2), in: line) else { return nil }
        return (String(line[n]), String(line[v]))
    }

    static func unquote(_ s: String) -> String {
        var t = s.trimmingCharacters(in: .whitespaces)
        while let l = t.last, ",;".contains(l) { t.removeLast() }
        if t.count >= 2, let f = t.first, "\"'`".contains(f), t.last == f { t = String(t.dropFirst().dropLast()) }
        return t
    }

    static func matchRule(_ s: String) -> Rule? {
        let r = NSRange(s.startIndex..., in: s)
        return rules.first { $0.regex.firstMatch(in: s, range: r) != nil }
    }

    static func looksLikeEnvName(_ n: String?) -> Bool {
        guard let n else { return false }
        return envName.firstMatch(in: n, range: NSRange(n.startIndex..., in: n)) != nil
    }

    static func secretishName(_ n: String) -> Bool {
        let u = n.uppercased()
        return ["KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "PWD", "CREDENTIAL", "PRIVATE", "DSN", "AUTH"].contains { u.contains($0) }
    }

    static func detectValue(_ value: String, name: String?) -> Detection? {
        let v = unquote(value)
        guard v.count >= 8, v.count <= 4096, !v.contains(where: \.isWhitespace) else { return nil }
        let nm = looksLikeEnvName(name) ? name : nil

        if v.hasPrefix("eyJ"), let j = jwt(v, name: nm) { return j }

        if let rule = matchRule(v) {
            return Detection(envName: nm ?? rule.env, service: rule.service, type: rule.type, value: v, confident: true)
        }
        if let n = name, secretishName(n), v.count >= 12, entropy(v) >= 2.5, !v.hasPrefix("http") {
            let svc = n.split(separator: "_").first.map { String($0).capitalized } ?? "Secret"
            return Detection(envName: nm ?? n.uppercased(), service: svc, type: "Secret", value: v, confident: true)
        }
        // Genérico: parece aleatório, mas não temos certeza → só com confirmação.
        if name == nil, (24...256).contains(v.count), entropy(v) >= 3.6,
           v.contains(where: \.isLetter), v.contains(where: \.isNumber),
           !v.contains("://"), v.filter({ $0 == "/" }).count < 3, !v.contains("."), !isHex(v) {
            return Detection(envName: "UNKNOWN_KEY", service: "Unknown", type: "Possible key", value: v, confident: false)
        }
        return nil
    }

    static func isHex(_ s: String) -> Bool { s.allSatisfy { $0.isHexDigit } }

    public static func entropy(_ s: String) -> Double {
        var counts: [Character: Int] = [:]
        for c in s { counts[c, default: 0] += 1 }
        let n = Double(s.count)
        return counts.values.reduce(0) { $0 - (Double($1) / n) * log2(Double($1) / n) }
    }

    static func jwt(_ v: String, name: String?) -> Detection? {
        let parts = v.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, let payload = base64url(String(parts[1])),
              let obj = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else { return nil }
        let iss = (obj["iss"] as? String) ?? ""
        var exp: Date?
        if let e = obj["exp"] as? Double {
            let d = Date(timeIntervalSince1970: e)
            if d.timeIntervalSinceNow > 7 * 86_400 { exp = d }
        }
        if iss.contains("supabase") {
            let role = (obj["role"] as? String) ?? "anon"
            let ref = obj["ref"] as? String
            let env = role == "service_role" ? "SUPABASE_SERVICE_ROLE_KEY" : "SUPABASE_ANON_KEY"
            return Detection(envName: name ?? env, service: "Supabase", type: role == "service_role" ? "service_role key" : "anon key",
                             value: v, confident: true, expiresAt: exp, note: ref.map { "ref \($0)" })
        }
        return Detection(envName: name ?? "JWT_TOKEN", service: (iss.isEmpty ? "JWT" : iss), type: "JWT",
                         value: v, confident: name != nil, expiresAt: exp)
    }

    static func base64url(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    static func privateKey(_ text: String) -> Detection? {
        guard let r = text.range(of: #"-----BEGIN ([A-Z ]*)PRIVATE KEY-----"#, options: .regularExpression) else { return nil }
        let header = String(text[r])
        let kind: (String, String)
        if header.contains("OPENSSH") { kind = ("SSH", "OpenSSH private key") }
        else if header.contains("RSA") { kind = ("RSA", "RSA private key") }
        else if header.contains("EC") { kind = ("EC", "EC private key") }
        else { kind = ("Private key", "Private key (.p8)") }
        return Detection(envName: "PRIVATE_KEY", service: kind.0, type: kind.1, value: text, confident: true)
    }

    /// Prefixos PÚBLICOS de provedores (identificam o tipo da chave, não o segredo). Mais longos primeiro.
    static let publicPrefixes = ["sk-ant-", "sk-proj-", "sk-or-v1-", "sk-svcacct-", "sk-admin-", "sk-", "AIza", "GOCSPX-", "github_pat_",
                                 "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_",
                                 "whsec_", "AKIA", "ASIA", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "sb_secret_", "sb_publishable_", "sbp_",
                                 "re_", "hf_", "gsk_", "xai-", "pplx-", "r8_", "SG.", "npm_", "xkeysib-", "APP_USR-", "eyJ",
                                 "postgresql://", "postgres://", "mysql://", "mongodb+srv://", "mongodb://", "rediss://", "redis://", "amqp://"]

    /// O que aparece na lista: só o prefixo público do provedor + bolinhas. NUNCA caracteres do valor (nem o fim, nem o tamanho).
    public static func preview(_ v: String) -> String {
        if v.contains("-----BEGIN") { return "-----BEGIN … KEY-----" }
        if let p = publicPrefixes.first(where: { v.hasPrefix($0) }) { return p + "••••" }
        return "••••••"
    }

    /// Migração: prévias antigas tinham 6 caracteres do começo e 4 do fim ("XEPs,%…G4mz"). Mantém só o que for prefixo público.
    public static func sanitizePreview(_ old: String) -> String {
        if old.contains("•") || old.hasPrefix("-----BEGIN") { return old }
        let head = old.components(separatedBy: "…").first ?? ""
        guard !head.isEmpty else { return "••••••" }
        let candidates = publicPrefixes.filter { $0.hasPrefix(head) || head.hasPrefix($0) }
        return candidates.max(by: { $0.count < $1.count }).map { $0 + "••••" } ?? "••••••"
    }
}
