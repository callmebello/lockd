import Foundation

/// Linguagem fechada para curl. Opção desconhecida é recusada, inclusive abreviações.
/// Só a configuração gerada aqui entra por stdin; dados secretos nunca entram em argv.
enum CurlArguments {
    struct Rejected: Error, LocalizedError {
        let reason: String
        var errorDescription: String? { reason }
    }
    static let flags: Set<String> = ["silent", "show-error", "verbose", "fail", "fail-with-body", "include", "head", "no-buffer", "disable", "globoff"]
    static let values: Set<String> = ["header", "request", "data", "data-raw", "data-binary", "data-urlencode", "json", "max-time", "connect-timeout"]
    static let short: [Character: String] = ["s": "silent", "S": "show-error", "v": "verbose", "f": "fail", "i": "include", "I": "head", "N": "no-buffer", "q": "disable", "g": "globoff", "H": "header", "X": "request", "d": "data", "m": "max-time"]
    static func reject(_ option: String, _ why: String) throws -> Never {
        throw Rejected(reason: "curl option \(option) denied: \(why)")
    }
    static func validate(_ args: [String]) throws -> [(String, String?)] {
        var out: [(String, String?)] = []
        var urls = 0, i = 0
        func add(_ name: String, _ value: String?) throws {
            guard flags.contains(name) || values.contains(name) else {
                try reject("--" + name, "not in the allowed set; config, proxy, files, cookies, redirects and output options are disabled")
            }
            if flags.contains(name) {
                guard value == nil else { try reject("--" + name, "does not accept a value") }
                if name != "disable" { out.append((name, nil)) }
                return
            }
            guard let v = value, !v.contains("\0") else { try reject("--" + name, "a valid value is required") }
            switch name {
            case "header":
                guard !v.hasPrefix("@"), !v.utf8.contains(13), !v.utf8.contains(10), let colon = v.firstIndex(of: ":"), colon != v.startIndex else {
                    try reject("--header", "inline NAME: value required; files and CR/LF are forbidden")
                }
                let field = v[..<colon].lowercased()
                guard field != "host", !field.hasPrefix("proxy-") else { try reject("--header", "overriding Host or proxy headers is disabled") }
            case "request":
                guard ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].contains(v) else { try reject("--request", "unsupported method") }
            case "max-time", "connect-timeout":
                guard let n = Double(v), n.isFinite, n > 0, n <= 120 else { try reject("--" + name, "timeout must be greater than zero and at most 120 seconds") }
            default:
                var fileReference = v.hasPrefix("@")
                if name == "data-urlencode", let at = v.firstIndex(of: "@") {
                    // name@arquivo lê arquivo; name=conteúdo@literal não lê.
                    fileReference = !v[..<at].contains("=")
                }
                guard !fileReference else { try reject("--" + name, "file references (@file) are forbidden; supply an inline body") }
            }
            out.append((name, v))
        }
        while i < args.count {
            let arg = args[i]
            guard !arg.contains("\0") else { try reject(arg, "NUL is forbidden") }
            if arg.hasPrefix("--") {
                let pieces = arg.dropFirst(2).split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                let name = pieces.first.map(String.init) ?? ""
                guard flags.contains(name) || values.contains(name) else { try reject(arg, "option not in the closed allowed set") }
                var value = pieces.count == 2 ? String(pieces[1]) : nil
                if values.contains(name), value == nil {
                    i += 1
                    guard i < args.count else { try reject(arg, "missing value") }
                    value = args[i]
                }
                try add(name, value)
            } else if arg.hasPrefix("-") {
                let cluster = Array(arg.dropFirst())
                guard !cluster.isEmpty else { try reject(arg, "stdin URL is forbidden") }
                var j = 0
                while j < cluster.count {
                    guard let name = short[cluster[j]] else { try reject("-" + String(cluster[j]), "option not in the closed allowed set") }
                    var value: String?
                    if values.contains(name) {
                        if j + 1 < cluster.count { value = String(cluster[(j + 1)...]) }
                        else {
                            i += 1
                            guard i < args.count else { try reject(arg, "missing value") }
                            value = args[i]
                        }
                        j = cluster.count
                    } else { j += 1 }
                    try add(name, value)
                }
            } else {
                guard let u = URLComponents(string: arg), u.scheme?.lowercased() == "https",
                      let host = u.host, !host.isEmpty, u.user == nil, u.password == nil,
                      u.fragment == nil, u.port == nil || u.port == 443,
                      !arg.utf8.contains(13), !arg.utf8.contains(10) else {
                    throw Rejected(reason: "curl URL denied: only absolute HTTPS URLs on port 443 without userinfo or fragments are allowed")
                }
                urls += 1
                out.append(("url", arg))
            }
            i += 1
        }
        guard urls == 1 else { throw Rejected(reason: "curl requires exactly one HTTPS URL") }
        return out
    }

    static let processArguments = ["-q", "--proto", "=https", "--max-redirs", "0", "--globoff", "--config", "-"]
    static func configuration(_ validated: [(String, String?)], secrets: [String: String]) throws -> Data {
        let expanded = validated.map { name, value -> (String, String?) in
            var substituted = value
            for (key, secret) in secrets { substituted = substituted?.replacingOccurrences(of: "{{\(key)}}", with: secret) }
            return (name, substituted)
        }
        // A substituição também não pode introduzir @arquivo, CRLF ou URL inválida.
        _ = try validate(expanded.flatMap { name, value in
            name == "url" ? [value!] : ["--" + name] + (value.map { [$0] } ?? [])
        })
        func quote(_ s: String) throws -> String {
            guard !s.contains("\0") else { throw Rejected(reason: "NUL in curl configuration") }
            return "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
                .replacingOccurrences(of: "\r", with: "\\r").replacingOccurrences(of: "\n", with: "\\n")
                .replacingOccurrences(of: "\t", with: "\\t").replacingOccurrences(of: "\u{0B}", with: "\\v") + "\""
        }
        return Data(try expanded.map { name, value in
            if let value { return name + " = " + (try quote(value)) }
            return name
        }.joined(separator: "\n").appending("\n").utf8)
    }
}
