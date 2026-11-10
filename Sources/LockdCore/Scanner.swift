import Foundation

/// Ligação entre um projeto do Lockd, a pasta dele no disco e o projeto da Vercel. Gravada uma vez; usada para sugerir e enviar.
public struct ProjectLink: Codable, Equatable, Sendable {
    public var path: String
    public var vercelProjectId: String?
    public var vercelTeamId: String?
    public init(path: String, vercelProjectId: String? = nil, vercelTeamId: String? = nil) {
        self.path = path; self.vercelProjectId = vercelProjectId; self.vercelTeamId = vercelTeamId
    }
}

/// Chave achada num arquivo .env. O valor só existe em memória durante a revisão; a tela mostra só o prefixo público.
public struct ScannedKey: Identifiable, Sendable {
    public let id = UUID()
    public var envName: String
    public var service: String
    public var type: String
    public var file: String
    public var preview: String
    public var alreadyInLockd: Bool
    public var selected: Bool
    var value: String
    var confident: Bool
}

public struct ScannedAsset: Identifiable, Sendable {
    public let id = UUID()
    public var url: URL
    public var type: String
    public var category: String
    public var selected: Bool
    var verdict: FileVerdict
    public var name: String { url.lastPathComponent }
}

public struct ScannedProject: Identifiable, Sendable {
    public let id = UUID()
    public var name: String
    public var path: URL
    public var keys: [ScannedKey]
    public var assets: [ScannedAsset]
    public var vercelProjectId: String?
    public var vercelTeamId: String?
    public var gitRemote: String?

    public var newKeys: Int { keys.filter { !$0.alreadyInLockd }.count }
    public var summary: String {
        var p: [String] = []
        if !keys.isEmpty { p.append("\(keys.count) key\(keys.count == 1 ? "" : "s")" + (newKeys < keys.count ? " (\(newKeys) new)" : "")) }
        if !assets.isEmpty { p.append("\(assets.count) asset\(assets.count == 1 ? "" : "s")") }
        if vercelProjectId != nil { p.append("Vercel linked") }
        return p.joined(separator: " · ")
    }
}

public enum ProjectScanner {
    static let markers = [".git", "package.json", ".vercel", "Package.swift", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml",
                          "pubspec.yaml", "supabase", "wrangler.toml", "composer.json", "Gemfile", "next.config.js", "next.config.mjs", "vite.config.ts"]
    static let skipDirs: Set<String> = ["node_modules", ".next", "dist", "build", ".git", "vendor", "Pods", "DerivedData", ".build", "__MACOSX",
                                        ".venv", "venv", "target", ".cache", ".turbo", ".expo", "out", "coverage", "Library", ".Trash"]
    static let envSkipWords = ["example", "sample", "template", "dist", "defaults", "schema"]
    static let childDirs = ["apps", "packages", "backend", "frontend", "web", "api", "server", "client", "app", "services"]

    /// Pastas de código comuns (só as que existem). A varredura é opt-in: a interface pede a confirmação antes.
    public static func defaultRoots() -> [URL] {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return ["Claude", "Documents/GitHub", "Developer", "Projects", "Code", "Desktop", "dev", "src"]
            .map { home.appendingPathComponent($0) }
            .filter { var d: ObjCBool = false; return FileManager.default.fileExists(atPath: $0.path, isDirectory: &d) && d.boolValue }
    }

    public static func scan(roots: [URL], maxDepth: Int = 2, store: Store = .shared,
                            progress: ((String) -> Void)? = nil) -> [ScannedProject] {
        var found: [URL] = []
        func visit(_ dir: URL, depth: Int) {
            if isProject(dir) { found.append(dir); return }
            guard depth < maxDepth, let kids = children(of: dir) else { return }
            for k in kids { visit(k, depth: depth + 1) }
        }
        for r in roots { visit(r, depth: 0) }
        var out: [ScannedProject] = []
        for dir in Set(found).sorted(by: { $0.path < $1.path }) {
            progress?(dir.lastPathComponent)
            let p = inspect(dir, store: store)
            if !p.keys.isEmpty || !p.assets.isEmpty { out.append(p) }
        }
        return out.sorted { ($0.newKeys, $0.assets.count) > ($1.newKeys, $1.assets.count) }
    }

    static func children(of dir: URL) -> [URL]? {
        guard let kids = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else { return nil }
        return kids.filter { !skipDirs.contains($0.lastPathComponent) && (try? $0.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true }
    }

    static func isProject(_ dir: URL) -> Bool {
        markers.contains { FileManager.default.fileExists(atPath: dir.appendingPathComponent($0).path) } || !envFiles(in: dir, deep: false).isEmpty
    }

    static func envFiles(in dir: URL, deep: Bool = true) -> [URL] {
        var dirs = [dir]
        if deep { dirs += childDirs.map { dir.appendingPathComponent($0) } + (children(of: dir.appendingPathComponent("apps")) ?? []) + (children(of: dir.appendingPathComponent("packages")) ?? []) }
        var out: [URL] = []
        for d in dirs {
            guard let kids = try? FileManager.default.contentsOfDirectory(at: d, includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey], options: []) else { continue }
            for f in kids {
                let n = f.lastPathComponent.lowercased()
                let isEnv = n == ".env" || n.hasPrefix(".env.") || n.hasSuffix(".env") || n == ".dev.vars"
                guard isEnv, !envSkipWords.contains(where: n.contains),
                      (try? f.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true,
                      ((try? f.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0) < 200_000 else { continue }
                out.append(f)
            }
        }
        return out
    }

    static func inspect(_ dir: URL, store: Store) -> ScannedProject {
        let name = dir.lastPathComponent
        var project = ScannedProject(name: name, path: dir, keys: keys(in: dir, project: name, store: store), assets: assets(in: dir), vercelProjectId: nil)
        if let d = try? Data(contentsOf: dir.appendingPathComponent(".vercel/project.json")),
           let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
            project.vercelProjectId = j["projectId"] as? String
            if let org = j["orgId"] as? String, org.hasPrefix("team_") { project.vercelTeamId = org }
        }
        if let cfg = try? String(contentsOf: dir.appendingPathComponent(".git/config"), encoding: .utf8) {
            project.gitRemote = cfg.components(separatedBy: "\n").first { $0.contains("url =") }?
                .components(separatedBy: "=").last?.trimmingCharacters(in: .whitespaces)
        }
        return project
    }

    /// Examina uma pasta de projeto específica (usado quando uma sugestão aponta para um projeto só).
    public static func scanProject(at dir: URL, name: String? = nil, store: Store = .shared) -> ScannedProject {
        var p = inspect(dir, store: store)
        if let name { p.name = name }
        return p
    }

    /// Só as chaves DESTA pasta que ainda não estão no Lockd (usado pelas sugestões enquanto você desenvolve).
    public static func missingKeys(project: String, link: ProjectLink, store: Store = .shared) -> [ScannedKey] {
        keys(in: URL(fileURLWithPath: link.path), project: project, store: store).filter { !$0.alreadyInLockd }
    }

    static func keys(in dir: URL, project: String, store: Store) -> [ScannedKey] {
        var out: [ScannedKey] = [], seen = Set<String>()
        let mine = store.items.filter { $0.kind == .secret && $0.project == project }
        for f in envFiles(in: dir) {
            guard let text = try? String(contentsOf: f, encoding: .utf8) else { continue }
            for d in Detector.detect(in: text) where seen.insert(d.envName + "\u{0}" + d.value).inserted {
                let strong = d.value.count >= 20 && Detector.entropy(d.value) >= 3.5 && Detector.publicPrefixes.contains { d.value.hasPrefix($0) }
                let present = (strong && store.existing(fingerprint: Vault.fingerprint(d.value)) != nil) || mine.contains { $0.name == d.envName }
                out.append(ScannedKey(envName: d.envName, service: d.service, type: d.type, file: f.lastPathComponent,
                                      preview: Detector.preview(d.value), alreadyInLockd: present, selected: !present && d.confident,
                                      value: d.value, confident: d.confident))
            }
        }
        return out
    }

    static func assets(in dir: URL) -> [ScannedAsset] {
        let exts: Set<String> = ["svg", "png", "jpg", "jpeg", "webp", "ico", "icns", "woff", "woff2", "ttf", "otf"]
        var out: [ScannedAsset] = []
        let keys: [URLResourceKey] = [.isRegularFileKey, .fileSizeKey, .isDirectoryKey]
        guard let walker = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles, .skipsPackageDescendants]) else { return [] }
        let dirDepth = dir.pathComponents.count
        for case let u as URL in walker {
            let name = u.lastPathComponent
            let rv = try? u.resourceValues(forKeys: Set(keys))
            if rv?.isDirectory == true {
                if skipDirs.contains(name) || u.pathComponents.count - dirDepth > 4 { walker.skipDescendants() }
                continue
            }
            guard rv?.isRegularFile == true, exts.contains(u.pathExtension.lowercased()), (rv?.fileSize ?? 0) < 5_000_000 else { continue }
            let v = FileClassifier.classify(u)
            guard !v.ignore else { continue }
            let branded = FileClassifier.brandWords.contains { name.lowercased().contains($0) }
            // PNG/JPG qualquer de um projeto costuma ser foto/conteúdo: só os de marca. Vetores, ícones e fontes entram.
            guard branded || ["svg", "ico", "icns", "woff", "woff2", "ttf", "otf"].contains(u.pathExtension.lowercased()) else { continue }
            out.append(ScannedAsset(url: u, type: v.type, category: v.category, selected: branded, verdict: v))
            if out.count >= 60 { break }
        }
        return out.sorted { ($0.selected ? 0 : 1, $0.name) < ($1.selected ? 0 : 1, $1.name) }
    }
}

public struct ImportResult: Equatable, Sendable {
    public var keys = 0, assets = 0, skipped = 0, failed = 0
    public var summary: String {
        var p: [String] = []
        if keys > 0 { p.append("\(keys) key\(keys == 1 ? "" : "s")") }
        if assets > 0 { p.append("\(assets) asset\(assets == 1 ? "" : "s")") }
        let text = p.isEmpty ? "Nothing new" : p.joined(separator: " and ") + " imported"
        return skipped > 0 ? text + " · \(skipped) already in Lockd" : text
    }
}

public enum ProjectImporter {
    /// Importa o que foi marcado. Chaves são cifradas para o Secure Enclave (sem Touch ID). Assets são COPIADOS: o projeto não muda.
    @discardableResult
    public static func importProjects(_ projects: [ScannedProject], store: Store = .shared) -> ImportResult {
        var r = ImportResult()
        for p in projects {
            let pickedKeys = p.keys.filter { $0.selected }, pickedAssets = p.assets.filter { $0.selected }
            guard !pickedKeys.isEmpty || !pickedAssets.isEmpty || p.vercelProjectId != nil else { continue }
            store.addProject(p.name)
            for k in pickedKeys {
                let det = Detection(envName: k.envName, service: k.service, type: k.type, value: k.value, confident: true)
                do { if try store.saveSecret(det, project: p.name, source: "Imported from \(k.file)").isNew { r.keys += 1 } else { r.skipped += 1 } }
                catch { r.failed += 1 }
            }
            for a in pickedAssets {
                do { _ = try Ingestor.ingest(a.url, project: p.name, verdict: a.verdict, copy: true, store: store); r.assets += 1 }
                catch IngestError.duplicate { r.skipped += 1 }
                catch { r.failed += 1 }
            }
            store.setLink(ProjectLink(path: p.path.path, vercelProjectId: p.vercelProjectId, vercelTeamId: p.vercelTeamId), for: p.name)
        }
        return r
    }
}
