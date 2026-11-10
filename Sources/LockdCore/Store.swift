import Foundation

public final class Store: @unchecked Sendable {
    public static let shared = Store()
    public static let didChange = Notification.Name("LockdStoreChanged")

    private let lock = NSLock()
    private var _items: [Item] = []
    private var _projects: [String] = []

    public init() { reload() }

    public var items: [Item] { lock.lock(); defer { lock.unlock() }; return _items }

    public func reload() {
        lock.lock(); defer { lock.unlock() }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        if let d = try? Data(contentsOf: LockdPaths.itemsFile), let arr = try? dec.decode([Item].self, from: d) {
            _items = arr
            for item in arr where item.kind == .secret && !Policies.rulesVerified(item) {
                Audit.write(AuditEntry(tool: "policy_verify", status: "denied", secrets: [item.name], detail: "Missing or invalid signature: agent access revoked"))
            }
        }
        if let d = try? Data(contentsOf: LockdPaths.projectsFile), let arr = try? JSONDecoder().decode([String].self, from: d) { _projects = arr }
        if let d = try? Data(contentsOf: LockdPaths.projectLinksFile), let m = try? JSONDecoder().decode([String: ProjectLink].self, from: d) { _links = m }
        if let d = try? Data(contentsOf: LockdPaths.projectColorsFile), let m = try? JSONDecoder().decode([String: Int].self, from: d) { _colors = m }
        migrateLeakyPreviews()
    }

    /// Itens antigos guardavam em texto claro 10 caracteres do segredo (prévia) e o SHA-256 dele (fingerprint).
    /// Prévia → só prefixo público; fingerprint de valor que não é chave de provedor → aleatório (um hash de senha fraca é quebrável).
    private func migrateLeakyPreviews() {
        var changedAny = false
        for i in _items.indices where _items[i].kind == .secret {
            let clean = Detector.sanitizePreview(_items[i].preview)
            let isProviderKey = clean != "••••••"
            if clean != _items[i].preview { _items[i].preview = clean; changedAny = true }
            if !isProviderKey, !_items[i].fingerprint.hasPrefix("weak-") { _items[i].fingerprint = "weak-" + UUID().uuidString; changedAny = true }
        }
        if changedAny { persist() }
    }

    private var _links: [String: ProjectLink] = [:]
    public var projectLinks: [String: ProjectLink] { lock.lock(); defer { lock.unlock() }; return _links }
    public func link(for project: String) -> ProjectLink? { projectLinks[project] }

    public func setLink(_ link: ProjectLink?, for project: String) {
        lock.lock()
        if let link { _links[project] = link } else { _links.removeValue(forKey: project) }
        if let d = try? JSONEncoder().encode(_links) { try? d.write(to: LockdPaths.projectLinksFile, options: .atomic) }
        lock.unlock(); changed()
    }

    private var _colors: [String: Int] = [:]
    public var projectColors: [String: Int] { lock.lock(); defer { lock.unlock() }; return _colors }

    /// Cor da pasta do projeto: um índice da paleta da marca (nunca uma cor livre).
    public func setProjectColor(_ project: String, index: Int?) {
        lock.lock()
        if let index { _colors[project] = index } else { _colors.removeValue(forKey: project) }
        if let d = try? JSONEncoder().encode(_colors) { try? d.write(to: LockdPaths.projectColorsFile, options: .atomic) }
        lock.unlock(); changed()
    }

    private func persist() {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601; enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(_items) { try? d.write(to: LockdPaths.itemsFile, options: .atomic) }
        if let d = try? JSONEncoder().encode(_projects) { try? d.write(to: LockdPaths.projectsFile, options: .atomic) }
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: LockdPaths.itemsFile.path)
    }

    private func changed() {
        DispatchQueue.main.async { NotificationCenter.default.post(name: Store.didChange, object: nil) }
    }

    // MARK: - Itens

    public func item(id: UUID) -> Item? { items.first { $0.id == id } }

    public func add(_ item: Item) {
        lock.lock(); _items.insert(item, at: 0); persist(); lock.unlock(); changed()
        if item.kind == .secret && !Policies.rulesVerified(item) {
            Audit.write(AuditEntry(tool: "policy_verify", status: "denied", secrets: [item.name], detail: "Unsigned key: agent access is off until local review"))
        }
    }

    public func update(id: UUID, _ mutate: (inout Item) -> Void) {
        lock.lock()
        if let i = _items.firstIndex(where: { $0.id == id }) { mutate(&_items[i]); persist() }
        lock.unlock(); changed()
    }

    public func remove(id: UUID) {
        lock.lock(); _items.removeAll { $0.id == id }; persist(); lock.unlock(); changed()
    }

    public func existing(fingerprint: String) -> Item? { items.first { $0.fingerprint == fingerprint } }

    /// Salva um segredo detectado. Retorna o item e se é novo.
    @discardableResult
    public func saveSecret(_ d: Detection, project: String?, source: String?) throws -> (item: Item, isNew: Bool) {
        // Hash só para chaves de provedor (alta entropia): serve para não duplicar. Senha fraca não ganha hash em disco.
        let strong = d.value.count >= 20 && Detector.entropy(d.value) >= 3.5 && Detector.publicPrefixes.contains(where: { d.value.hasPrefix($0) })
        let fp = strong ? Vault.fingerprint(d.value) : "weak-" + UUID().uuidString
        if strong, let e = existing(fingerprint: fp) { return (e, false) }
        let id = UUID()
        let item = Item(id: id, kind: .secret, name: d.envName, service: d.service, type: d.type, project: project,
                        expiresAt: d.expiresAt, fingerprint: fp, preview: Detector.preview(d.value),
                        cipher: try Vault.shared.encrypt(d.value, itemID: id), note: d.note, source: source)
        add(item)
        return (item, true)
    }

    public func secretValue(_ item: Item) throws -> String {
        guard let c = item.cipher else { throw Vault.VaultError.badData }
        let value = try Vault.shared.decrypt(c, itemID: item.id)
        if c.hasPrefix("v2:") {
            let upgraded = try Vault.shared.encrypt(value, itemID: item.id)
            lock.lock(); defer { lock.unlock() }
            if let index = _items.firstIndex(where: { $0 == item }) {
                var changedItem = _items[index]; changedItem.cipher = upgraded
                if RuleSigner.verify(item) {
                    changedItem = try RuleSigner.signed([changedItem], context: Vault.shared.signingContext)[0]
                }
                var snapshot = _items; snapshot[index] = changedItem
                try writeItems(snapshot); _items = snapshot; changed()
            }
        }
        return value
    }


    private func writeItems(_ items: [Item]) throws {
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(items).write(to: LockdPaths.itemsFile, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: LockdPaths.itemsFile.path)
    }

    /// Aprovação explícita da UI; jamais exposta em socket/MCP. Um prompt para todo o lote.
    public func authorizeRules(_ ids: [UUID], expected: [Item]? = nil, changes: ((inout Item) -> Void)? = nil) throws {
        let originals = items.filter { ids.contains($0.id) && $0.kind == .secret }
        guard !originals.isEmpty else { throw Vault.VaultError.badData }
        if let expected, Set(expected) != Set(originals) { throw Vault.VaultError.denied("Items changed since review; open review again") }
        try Vault.shared.unlock(reason: "Review and sign Lockd access rules for \(originals.count) keys", fresh: true)
        var pending: [Item] = []
        for var item in originals {
            let proposed = Policies.proposed(item)
            item.allowCommands = proposed.commands; item.allowHosts = proposed.hosts; item.allowEnv = proposed.allowEnv
            changes?(&item)
            if let cipher = item.cipher, cipher.hasPrefix("v2:") {
                item.cipher = try Vault.shared.encrypt(Vault.shared.decrypt(cipher, itemID: item.id), itemID: item.id)
            }
            pending.append(item)
        }
        lock.lock(); defer { lock.unlock() }
        guard originals.allSatisfy({ original in _items.contains(original) }) else { throw Vault.VaultError.denied("Item changed during approval; review again") }
        let signed = try RuleSigner.signed(pending, context: Vault.shared.signingContext)
        var snapshot = _items
        for item in signed { if let index = snapshot.firstIndex(where: { $0.id == item.id }) { snapshot[index] = item } }
        try writeItems(snapshot); _items = snapshot; changed()
        Audit.write(AuditEntry(tool: "policy_sign", status: "ok", secrets: signed.map(\.name), detail: "Rules signed after explicit local approval"))
    }

    // MARK: - Projetos

    public var userProjects: [String] { lock.lock(); defer { lock.unlock() }; return _projects }

    public func addProject(_ name: String) {
        let n = name.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty else { return }
        lock.lock()
        if !_projects.contains(where: { $0.caseInsensitiveCompare(n) == .orderedSame }) { _projects.append(n); persist() }
        lock.unlock(); changed()
    }

    /// Projetos conhecidos: criados por você + usados em itens + pastas de código na máquina.
    public func knownProjects() -> [String] {
        var seen = Set<String>(), out: [String] = []
        func push(_ s: String) { if seen.insert(s.lowercased()).inserted { out.append(s) } }
        userProjects.forEach(push)
        items.compactMap(\.project).forEach(push)
        Store.scanCodeFolders().forEach(push)
        return out.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    nonisolated(unsafe) private static var scanCache: (Date, [String])?

    static func scanCodeFolders() -> [String] {
        if let c = scanCache, Date().timeIntervalSince(c.0) < 60 { return c.1 }
        let home = FileManager.default.homeDirectoryForCurrentUser
        var names: [String] = []
        for root in ["Claude", "Documents/GitHub", "Developer", "Projects", "Code"] {
            let url = home.appendingPathComponent(root)
            let kids = (try? FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: [.isDirectoryKey],
                                                                     options: [.skipsHiddenFiles])) ?? []
            for k in kids where (try? k.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
                let n = k.lastPathComponent
                if n.count >= 3, !["node_modules", "dist", "build", "tmp", "videos"].contains(n.lowercased()) { names.append(n) }
            }
        }
        scanCache = (Date(), names)
        return names
    }

    /// Procura o nome de um projeto conhecido dentro de um texto (título de janela, nome de arquivo).
    public func matchProject(in text: String) -> String? {
        let t = Store.squash(text)
        guard !t.isEmpty else { return nil }
        return knownProjects()
            .filter { $0.count >= 3 && t.contains(Store.squash($0)) }
            .max { $0.count < $1.count }
    }

    static func squash(_ s: String) -> String {
        s.lowercased().filter { $0.isLetter || $0.isNumber }
    }
}
