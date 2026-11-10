import Foundation
import Darwin

/// O que o Claude pode fazer com UMA chave: quais programas pode rodar e para quais hosts a chave pode ir.
public struct Policy: Equatable, Sendable {
    public var commands: [String]
    public var hosts: [String]
    public var allowEnv: Bool      // pode escrever em .env / subir para hospedagem
    public var isPreset: Bool
    public var methods: [String]? = nil
    public var pathPrefixes: [String]? = nil
}

public enum Policies {
    /// Programas que NUNCA entram, mesmo se você listar: eles conseguem transformar/exfiltrar a chave.
    public static let blockedPrograms: Set<String> = [
        "sh", "bash", "zsh", "fish", "dash", "csh", "tcsh", "ksh", "env", "xargs", "eval", "exec", "sudo", "su", "doas",
        "python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php", "lua", "osascript", "swift", "swiftc",
        "awk", "gawk", "sed", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "ftp", "tftp", "open",
        "security", "lockdctl", "lockd", "base64", "xxd", "od", "openssl", "gpg", "tee", "dd", "script", "expect",
    ]

    static let presets: [String: (commands: [String], hosts: [String])] = [
        "anthropic": (["curl"], ["api.anthropic.com"]),
        "openai": (["curl"], ["api.openai.com"]),
        "openrouter": (["curl"], ["openrouter.ai"]),
        "google gemini": (["curl"], ["generativelanguage.googleapis.com"]),
        "google": (["curl"], ["oauth2.googleapis.com"]),
        "github": (["curl"], ["api.github.com", "github.com", "codeload.github.com"]),
        "stripe": (["curl"], ["api.stripe.com", "files.stripe.com"]),
        "elevenlabs": (["curl"], ["api.elevenlabs.io"]),
        "groq": (["curl"], ["api.groq.com"]),
        "xai": (["curl"], ["api.x.ai"]),
        "perplexity": (["curl"], ["api.perplexity.ai"]),
        "replicate": (["curl"], ["api.replicate.com"]),
        "hugging face": (["curl"], ["huggingface.co"]),
        "sendgrid": (["curl"], ["api.sendgrid.com"]),
        "resend": (["curl"], ["api.resend.com"]),
        "brevo": (["curl"], ["api.brevo.com"]),
        "slack": (["curl"], ["slack.com"]),
        "mercado pago": (["curl"], ["api.mercadopago.com"]),
        "fal.ai": (["curl"], ["fal.run", "queue.fal.run", "rest.alpha.fal.ai"]),
        "npm": (["curl"], ["registry.npmjs.org"]),
        "supabase": (["curl"], ["api.supabase.com"]),
        "vercel": (["curl"], ["api.vercel.com", "vercel.com"]),
        "aws": ([], []),
    ]

    public static func rulesVerified(_ item: Item) -> Bool { RuleSigner.verify(item) }
    public static func effective(_ item: Item) -> Policy {
        guard rulesVerified(item) else { return Policy(commands: [], hosts: [], allowEnv: false, isPreset: false) }
        var policy = proposed(item)
        policy.methods = item.allowedMethods; policy.pathPrefixes = item.allowedPathPrefixes
        return policy
    }
    /// Sugestão não autorizada para a UI revisar antes de assinar.
    public static func proposed(_ item: Item) -> Policy {
        let env = item.allowEnv ?? false
        if item.allowCommands != nil || item.allowHosts != nil {
            let confirmed = Set(item.confirmedWildcardHosts ?? [])
            let hosts = (item.allowHosts ?? []).filter { !$0.hasPrefix("*.") || confirmed.contains($0) }
            return Policy(commands: item.allowCommands ?? [], hosts: hosts, allowEnv: env, isPreset: false)
        }
        let key = (item.service ?? "").lowercased()
        var p = presets[key]
        if p == nil, item.name.uppercased().contains("VERCEL") { p = presets["vercel"] }
        if let p { return Policy(commands: p.commands, hosts: p.hosts, allowEnv: env, isPreset: true) }
        return Policy(commands: [], hosts: [], allowEnv: env, isPreset: true)
    }

    static func permitsHTTP(_ policy: Policy, host: String, method: String, path: String) -> Bool {
        policy.hosts.contains(host) && (policy.methods == nil || policy.methods!.contains(method)) &&
            (policy.pathPrefixes == nil || policy.pathPrefixes!.contains { prefix in
                prefix.hasPrefix("/") && (path == prefix || path.hasPrefix(prefix.hasSuffix("/") ? prefix : prefix + "/"))
            })
    }

    // MARK: Hosts

    /// "*.x.com" casa subdomínios de x.com; sem curinga só o host exato. Curingas largos (*.com, *) são recusados.
    public static func validPattern(_ p: String) -> Bool {
        let s = p.lowercased()
        if s.hasPrefix("*.") { return s.dropFirst(2).contains(".") && !s.dropFirst(2).contains("*") }
        return !s.contains("*") && !s.isEmpty && !s.contains("/") && !s.contains(" ")
    }

    public static func hostMatches(_ host: String, _ patterns: [String]) -> Bool {
        let h = host.lowercased()
        return patterns.contains { p in
            let s = p.lowercased()
            guard validPattern(s) else { return false }
            if s.hasPrefix("*.") { return h.hasSuffix(String(s.dropFirst(1))) && h.count > s.count - 1 }
            return h == s
        }
    }

    /// Com várias chaves no mesmo comando só valem os hosts permitidos para TODAS (uma chave nunca vai p/ o host de outra).
    public static func intersectHosts(_ lists: [[String]]) -> [String] {
        guard let first = lists.first else { return [] }
        return first.filter { pat in
            lists.dropFirst().allSatisfy { other in other.contains(pat) || (!pat.hasPrefix("*.") && hostMatches(pat, other)) }
        }
    }

    // MARK: Programas

    public static func searchDirs() -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
                home + "/.local/bin", home + "/.bun/bin", home + "/.cargo/bin"]
    }

    /// Somente executáveis root-owned, sem escrita de grupo/outros em toda a cadeia real.
    /// Isso recusa Homebrew/binários locais graváveis pelo usuário. Não substitui pinning/TOCTOU.
    static func trustedExecutable(_ path: String) -> Bool {
        let canonical = Sandbox.realPath(path)
        var current = canonical
        var first = true
        while true {
            var info = stat()
            guard lstat(current, &info) == 0, info.st_uid == 0,
                  info.st_mode & 0o022 == 0, access(current, W_OK) != 0 else { return false }
            let kind = info.st_mode & S_IFMT
            if first {
                guard kind == S_IFREG, info.st_mode & 0o111 != 0 else { return false }
                first = false
            } else if kind != S_IFDIR { return false }
            if current == "/" { return true }
            current = (current as NSString).deletingLastPathComponent
        }
    }

    public static func resolve(program: String) -> String? {
        guard !program.contains("/") else { return nil }
        for d in searchDirs() {
            let p = d + "/" + program
            if trustedExecutable(p) { return Sandbox.realPath(p) }
        }
        return nil
    }

}

public func isEnvName(_ s: String) -> Bool {
    guard let f = s.unicodeScalars.first, f == "_" || CharacterSet.letters.contains(f) else { return false }
    return s.unicodeScalars.allSatisfy { $0 == "_" || CharacterSet.alphanumerics.contains($0) }
}
