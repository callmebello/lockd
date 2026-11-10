import Foundation

/// Códigos de recuperação (2FA) que o usuário baixa como .txt, ex.: "vercel-recovery-codes-fulano@x.com.br.txt".
/// Viram UM segredo cifrado no cofre (Secure Enclave): salvar é livre, ler pede Touch ID. O arquivo original vai para a
/// Lixeira (recuperável) e nunca é visível ao agente: o tipo "Recovery codes" fica fora do Broker.
public enum RecoveryCodes {
    public static let type = "Recovery codes"

    public struct Parsed: Equatable, Sendable {
        public var service: String
        public var account: String?
        public var codes: [String]
    }

    static let nameWords = ["recovery", "backup-code", "backup_code", "backup code", "backupcode"]
    static let textExt: Set<String> = ["txt", "text", "csv", "md"]

    /// Só pelo nome e extensão: o conteúdo pode ainda estar sendo baixado quando o Lockd olha.
    public static func looksLikeByName(_ url: URL) -> Bool {
        guard textExt.contains(url.pathExtension.lowercased()) else { return false }
        let n = url.lastPathComponent.lowercased()
        return nameWords.contains { n.contains($0) }
    }

    static let emailRegex = try! NSRegularExpression(pattern: #"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"#)
    static let codeRegex = try! NSRegularExpression(pattern: #"^(?:[A-Za-z0-9]{3,}(?:-[A-Za-z0-9]{3,})+|[A-Za-z0-9]{8,})$"#)
    static let headerRegex = try! NSRegularExpression(pattern: #"^\s*([A-Za-z0-9][A-Za-z0-9 .&_\-]*?)\s+(?:recovery|backup)\s+codes?\b"#, options: [.caseInsensitive])

    /// Lê o arquivo (até 16 KB) e extrai serviço, conta e códigos. nil = não parece uma lista de códigos.
    public static func parse(_ url: URL) -> Parsed? {
        guard let data = try? Data(contentsOf: url), data.count > 0, data.count <= 16_384,
              let text = String(data: data, encoding: .utf8) else { return nil }
        return parse(text: text, fileName: url.lastPathComponent)
    }

    public static func parse(text: String, fileName: String) -> Parsed? {
        func first(_ re: NSRegularExpression, in s: String) -> String? {
            re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)).flatMap { Range($0.range, in: s) }.map { String(s[$0]) }
        }
        var codes: [String] = [], seen = Set<String>()
        for raw in text.split(whereSeparator: \.isNewline) {
            var line = raw.trimmingCharacters(in: .whitespaces)
            line = line.replacingOccurrences(of: #"^\d{1,3}[.)]\s*"#, with: "", options: .regularExpression)
            guard !line.isEmpty, !line.contains(" "), !line.contains(":"), !line.contains("@"),
                  codeRegex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) != nil,
                  line.contains("-") || line.contains(where: \.isNumber) else { continue }
            if seen.insert(line).inserted { codes.append(line) }
        }
        guard (4...60).contains(codes.count) else { return nil }

        var service: String?
        if let m = headerRegex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)), let r = Range(m.range(at: 1), in: text) {
            service = String(text[r]).trimmingCharacters(in: .whitespaces)
        }
        if service == nil {
            let tokens = fileName.lowercased().split(whereSeparator: { !$0.isLetter && !$0.isNumber })
            if let i = tokens.firstIndex(where: { ["recovery", "backup"].contains(String($0)) }), i > 0 { service = String(tokens[0]) }
        }
        let name = (service ?? "").isEmpty ? "Account" : service!.prefix(1).uppercased() + service!.dropFirst()
        let account = first(emailRegex, in: text) ?? first(emailRegex, in: fileName)
        return Parsed(service: name, account: account, codes: codes)
    }

    static func envName(for service: String, store: Store) -> String {
        let base = service.uppercased().unicodeScalars.map { CharacterSet.alphanumerics.contains($0) ? String($0) : "_" }.joined()
            .trimmingCharacters(in: CharacterSet(charactersIn: "_")) + "_RECOVERY_CODES"
        var name = base, n = 2
        while store.items.contains(where: { $0.name == name }) { name = "\(base)_\(n)"; n += 1 }
        return name
    }

    /// Cifra os códigos, registra o segredo e manda o arquivo para a Lixeira (a menos que `copy`).
    /// Se algo falhar antes de o segredo estar salvo, o arquivo NÃO é tocado.
    public static func ingest(_ url: URL, project: String?, copy: Bool = false, store: Store = .shared) throws -> Item {
        guard FileManager.default.fileExists(atPath: url.path) else { throw IngestError.missing }
        guard let p = parse(url) else { throw IngestError.ignored }
        let fp = Ingestor.fileFingerprint(url)
        if let e = store.existing(fingerprint: fp) { throw IngestError.duplicate(e) }

        let id = UUID()
        let cipher = try Vault.shared.encrypt(p.codes.joined(separator: "\n"), itemID: id)
        let plural = p.codes.count == 1 ? "code" : "codes"
        var item = Item(id: id, kind: .secret, name: envName(for: p.service, store: store), service: p.service, type: type,
                        project: project, fingerprint: fp, preview: "\(p.codes.count) \(plural)", cipher: cipher,
                        note: [p.account.map { "Account: \($0)" }, "\(p.codes.count) one-time codes. Cross each one off after using it."]
                            .compactMap { $0 }.joined(separator: " · "),
                        source: url.path)
        store.add(item)
        guard store.item(id: id)?.cipher != nil else { throw IngestError.missing }

        if !copy {
            var trashed: NSURL?
            if (try? FileManager.default.trashItem(at: url, resultingItemURL: &trashed)) != nil, let t = trashed as URL? {
                store.update(id: id) { $0.originalPath = t.path }
                item.originalPath = t.path
            }
        }
        return item
    }

    /// Desfaz: devolve o arquivo da Lixeira ao lugar de origem e esquece o segredo.
    public static func undo(_ item: Item, store: Store = .shared) {
        if let trash = item.originalPath, let origin = item.source, FileManager.default.fileExists(atPath: trash),
           !FileManager.default.fileExists(atPath: origin) {
            try? FileManager.default.moveItem(atPath: trash, toPath: origin)
        }
        store.remove(id: item.id)
    }
}
