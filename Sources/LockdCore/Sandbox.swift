import Foundation

/// Executa um programa SEM shell, com as chaves só no ambiente dele, dentro de um sandbox do macOS que:
///  - nega toda rede, exceto o proxy filtrado local (só os hosts da política);
///  - nega ler/escrever os dados do Lockd e executar o Lockd/lockdctl;
///  - nega falar com o Keychain/securityd.
public enum Sandbox {
    public struct Result { public var output: String; public var status: Int32; public var contacted: [String]; public var blocked: [String] }

    /// realpath(3): resolve /var → /private/var (URL.resolvingSymlinksInPath() faz o contrário).
    static func realPath(_ p: String) -> String {
        guard let r = realpath(p, nil) else {
            let parent = (p as NSString).deletingLastPathComponent
            guard !parent.isEmpty, parent != p else { return p }
            return (realPath(parent) as NSString).appendingPathComponent((p as NSString).lastPathComponent)
        }
        defer { free(r) }
        return String(cString: r)
    }

    static func esc(_ s: String) -> String { s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") }

    static func protectedPaths(home: String) -> [String] {
        [".ssh", ".aws", ".gnupg", ".config/gh", ".npmrc", ".netrc", ".kube", ".docker", ".password-store", ".config/Bitwarden",
         "Library/Keychains", "Library/Application Support/1Password", "Library/Application Support/com.agilebits.onepassword4", "Library/Application Support/Bitwarden",
         "Library/Application Support/KeePassXC", "Library/Application Support/Proton Pass",
         "Library/Group Containers/2BUA8C4S2C.com.1password", "Library/Containers/com.bitwarden.desktop",
         "Library/Containers/com.agilebits.onepassword7", "Library/Containers/com.1password.1password"]
            .map { (home as NSString).appendingPathComponent($0) }
    }

    static func profile(proxyPort: UInt16, cwd: String, temporary: String, additionalProtectedPaths: [String] = []) -> String {
        var denyExec = ["/Applications/Lockd.app", Bundle.main.bundlePath]
        if let exe = Bundle.main.executablePath { denyExec.append(exe) }
        let execRules = Set(denyExec).map { "(deny process-exec (subpath \"\(esc($0))\"))" }.joined(separator: "\n")
        // o sandbox compara caminhos reais (/var → /private/var): bloqueia os dois jeitos
        let supports = Set([LockdPaths.support.path, realPath(LockdPaths.support.path)])
        let supportRules = supports.map { "(deny file-read* (subpath \"\(esc($0))\"))\n(deny file-write* (subpath \"\(esc($0))\"))" }.joined(separator: "\n")
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let protected = protectedPaths(home: home) + additionalProtectedPaths
        let protectedRules = Set(protected.flatMap { [$0, realPath($0)] }).sorted().map {
            "(deny file-read* (subpath \"\(esc($0))\"))\n(deny file-write* (subpath \"\(esc($0))\"))"
        }.joined(separator: "\n")
        let writeRules = Set([cwd, temporary, "/tmp"].flatMap { [$0, realPath($0)] }).sorted().map {
            "(allow file-write* (subpath \"\(esc($0))\"))"
        }.joined(separator: "\n")
        return """
        (version 1)
        (allow default)
        (deny network*)
        (allow network-outbound (remote ip "localhost:\(proxyPort)"))
        (deny file-write*)
        \(writeRules)
        (allow file-write-data (literal "/dev/null"))
        \(protectedRules)
        \(supportRules)
        \(execRules)
        (deny mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd") (global-name "com.apple.secd") (global-name "com.apple.security.XPCKeychainSandboxCheck") (global-name "com.apple.coreauthd") (global-name "com.apple.CoreAuthentication.daemon"))
        """
    }

    public static func run(program: String, args: [String], env secrets: [String: String], cwd: URL?, allowedHosts: [String], timeout: TimeInterval = 120, input: Data? = nil, additionalProtectedPaths: [String] = []) -> Result {
        let fm = FileManager.default
        let callTemp = fm.temporaryDirectory.appendingPathComponent("lockd-call-\(UUID().uuidString)")
        do { try fm.createDirectory(at: callTemp, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
        catch { return Result(output: "couldn't create private working directory", status: 126, contacted: [], blocked: []) }
        defer { try? fm.removeItem(at: callTemp) }
        let workingDirectory = cwd ?? callTemp
        let proxy = FilterProxy(allowedHosts: allowedHosts)
        guard let port = try? proxy.start() else { return Result(output: "couldn't start the network filter", status: 126, contacted: [], blocked: []) }
        defer { proxy.stop() }

        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let url = "http://127.0.0.1:\(port)"
        var env: [String: String] = [
            "PATH": Policies.searchDirs().joined(separator: ":"),
            "HOME": home, "USER": NSUserName(), "LANG": "en_US.UTF-8", "TMPDIR": callTemp.path + "/",
            "HTTPS_PROXY": url, "https_proxy": url, "HTTP_PROXY": url, "http_proxy": url, "ALL_PROXY": url, "all_proxy": url,
            "NODE_USE_ENV_PROXY": "1", "NO_PROXY": "", "no_proxy": "",
        ]
        for (k, v) in secrets { env[k] = v }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        p.arguments = ["-p", profile(proxyPort: port, cwd: realPath(workingDirectory.path), temporary: realPath(callTemp.path), additionalProtectedPaths: additionalProtectedPaths), program] + args
        p.environment = env
        p.currentDirectoryURL = workingDirectory
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        let inputPipe = input.map { _ in Pipe() }
        p.standardInput = inputPipe?.fileHandleForReading ?? FileHandle.nullDevice
        do { try p.run() } catch { return Result(output: "failed to start: \(error)", status: 127, contacted: [], blocked: []) }

        if let input, let inputPipe {
            try? inputPipe.fileHandleForReading.close()
            DispatchQueue.global().async {
                defer { try? inputPipe.fileHandleForWriting.close() }
                try? inputPipe.fileHandleForWriting.write(contentsOf: input)
            }
        }
        let killer = DispatchWorkItem { if p.isRunning { p.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)
        var data = Data()
        while true {
            let chunk = pipe.fileHandleForReading.availableData
            if chunk.isEmpty { break }
            if data.count < 400_000 { data.append(chunk) }
        }
        p.waitUntilExit(); killer.cancel()
        var out = String(decoding: data, as: UTF8.self)
        if out.count > 20_000 { out = String(out.prefix(20_000)) + "\n…(truncated)" }
        return Result(output: out, status: p.terminationStatus, contacted: proxy.contacted, blocked: proxy.blocked)
    }
}
