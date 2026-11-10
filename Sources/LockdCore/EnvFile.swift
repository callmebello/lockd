import Foundation

public enum EnvFileError: Error, LocalizedError {
    case rejected(String)
    public var errorDescription: String? { if case .rejected(let s) = self { return s }; return nil }
}

/// Materializa .env legível por processos do mesmo usuário após consentimento. Só aceita arquivos .env* dentro da sua pasta pessoal.
public enum EnvFile {
    static let nameOK = try! NSRegularExpression(pattern: #"^(\.env(\.[A-Za-z0-9_\-]+)*|[A-Za-z0-9_\-]+\.env|\.dev\.vars)$"#)
    static let forbiddenDirs: Set<String> = [".ssh", ".aws", ".gnupg", "Library", ".config", ".git", "LaunchAgents", ".kube", ".docker"]

    public static func validate(_ raw: String, cwd: String?) throws -> URL {
        guard !raw.isEmpty else { throw EnvFileError.rejected("path is required") }
        let home = FileManager.default.homeDirectoryForCurrentUser.resolvingSymlinksInPath().path
        var p = (raw as NSString).expandingTildeInPath
        if !p.hasPrefix("/") { p = ((cwd.map { ($0 as NSString).expandingTildeInPath }) ?? home) + "/" + p }
        let url = URL(fileURLWithPath: p).standardizedFileURL
        let name = url.lastPathComponent
        guard nameOK.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)) != nil else {
            throw EnvFileError.rejected("only .env, .env.local, .env.<name>, <name>.env and .dev.vars files are allowed")
        }
        let dir = url.deletingLastPathComponent().resolvingSymlinksInPath()
        guard dir.path.hasPrefix(home + "/") else { throw EnvFileError.rejected("the file must be inside your home folder") }
        for c in dir.pathComponents where forbiddenDirs.contains(c) { throw EnvFileError.rejected("writing inside \(c) is not allowed") }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir), isDir.boolValue else { throw EnvFileError.rejected("folder doesn't exist") }
        let target = dir.appendingPathComponent(name)
        if let attrs = try? FileManager.default.attributesOfItem(atPath: target.path), attrs[.type] as? FileAttributeType == .typeSymbolicLink {
            throw EnvFileError.rejected("the target is a symlink")
        }
        return target
    }

    static func quote(_ v: String) -> String {
        if v.range(of: #"^[A-Za-z0-9_\-\.\/:@+=,]*$"#, options: .regularExpression) != nil { return v }
        let e = v.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n").replacingOccurrences(of: "$", with: "\\$")
        return "\"\(e)\""
    }

    /// Mescla com o que já existe (mantém o resto do arquivo). Retorna um aviso se o arquivo não está no .gitignore.
    @discardableResult
    public static func write(_ vars: [(String, String)], to url: URL) throws -> String? {
        var lines = ((try? String(contentsOf: url, encoding: .utf8)) ?? "").components(separatedBy: "\n")
        if lines.last == "" { lines.removeLast() }
        for (k, v) in vars {
            let newLine = "\(k)=\(quote(v))"
            if let i = lines.firstIndex(where: { $0.hasPrefix("\(k)=") || $0.hasPrefix("export \(k)=") }) { lines[i] = newLine } else { lines.append(newLine) }
        }
        let text = lines.joined(separator: "\n") + "\n"
        try text.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)

        // aviso de git
        let g = Process(); g.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        g.arguments = ["-C", url.deletingLastPathComponent().path, "check-ignore", "-q", "--", url.lastPathComponent]
        g.standardOutput = FileHandle.nullDevice; g.standardError = FileHandle.nullDevice
        if (try? g.run()) != nil { g.waitUntilExit(); if g.terminationStatus == 1 { return "\(url.lastPathComponent) is NOT in .gitignore — add it before committing" } }
        return nil
    }
}

public enum VercelPush {
    static var base: String {
        // desvio de URL só em modo teste; em produção é sempre a API oficial
        #if DEBUG
        if ProcessInfo.processInfo.environment["LOCKD_HOME"] != nil, let b = ProcessInfo.processInfo.environment["LOCKD_VERCEL_BASE"] { return b }
        #endif
        return "https://api.vercel.com"
    }

    public static func upsert(token: String, project: String, team: String?, name: String, value: String, targets: [String]) -> (ok: Bool, detail: String) {
        upsert(token: token, project: project, team: team, name: name, value: value, targets: targets, client: SecureHTTPClient())
    }
    static func upsert(token: String, project: String, team: String?, name: String, value: String, targets: [String], client: SecureHTTPClient) -> (ok: Bool, detail: String) {
        var comps = URLComponents(string: base + "/v10/projects/\(project)/env")!
        comps.queryItems = [URLQueryItem(name: "upsert", value: "true")] + (team.map { [URLQueryItem(name: "teamId", value: $0)] } ?? [])
        guard let url = comps.url else { return (false, "bad URL") }
        do {
            let body = try JSONSerialization.data(withJSONObject: ["key": name, "value": value, "type": targets.contains("production") && !targets.contains("development") ? "sensitive" : "encrypted", "target": targets])
            let result = try client.perform(method: "POST", url: url.absoluteString,
                headers: ["Authorization": "Bearer \(token)", "Content-Type": "application/json"], body: body,
                hosts: [url.host!], timeout: 30)
            return ((200..<300).contains(result.status), "HTTP \(result.status)")
        } catch { return (false, "Secure Vercel request failed") }
    }
}
