import Foundation
import CryptoKit
import CommonCrypto

public enum BackupError: Error, LocalizedError {
    case weakPassphrase, wrongPassphraseOrCorrupt, unsupported, nothingToExport
    public var errorDescription: String? {
        switch self {
        case .weakPassphrase: return "Use a passphrase with at least 12 characters."
        case .wrongPassphraseOrCorrupt: return "Wrong passphrase, or the file was changed."
        case .unsupported: return "This backup file isn't supported."
        case .nothingToExport: return "There are no keys to back up."
        }
    }
}

/// Backup cifrado com senha: a chave do Secure Enclave não sai do Mac, então sem isto perder o Mac apagaria todos os segredos.
/// PBKDF2-HMAC-SHA256 (600 mil iterações) + AES-256-GCM. Só segredos de texto, nomes de projeto, cores e vínculos; assets ficam em ~/Lockd.
public enum Backup {
    struct Entry: Codable { var name: String; var service: String?; var type: String; var project: String?; var note: String?; var expiresAt: Date?; var value: String }
    struct Payload: Codable { var version: Int; var createdAt: Date; var entries: [Entry]; var projectColors: [String: Int]; var projectLinks: [String: ProjectLink] }
    struct Envelope: Codable { var v: Int; var kdf: String; var iterations: Int; var salt: String; var box: String }

    static let iterations = 600_000
    static let aad = Data("lockd-backup-v1".utf8)

    static func key(_ passphrase: String, salt: Data, iterations: Int) -> SymmetricKey {
        var out = [UInt8](repeating: 0, count: 32)
        let pass = Array(passphrase.utf8)
        _ = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pass.map { Int8(bitPattern: $0) }, pass.count, [UInt8](salt), salt.count,
                                 CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations), &out, out.count)
        return SymmetricKey(data: Data(out))
    }

    /// O cofre precisa estar liberado (Touch ID) antes: cada segredo é aberto para entrar no arquivo.
    @discardableResult
    public static func export(store: Store = .shared, passphrase: String, to url: URL) throws -> Int {
        guard passphrase.count >= 12 else { throw BackupError.weakPassphrase }
        let secrets = store.items.filter { $0.kind == .secret }
        guard !secrets.isEmpty else { throw BackupError.nothingToExport }
        var entries: [Entry] = []
        for i in secrets {
            entries.append(Entry(name: i.name, service: i.service, type: i.type, project: i.project, note: i.note, expiresAt: i.expiresAt,
                                 value: try store.secretValue(i)))
        }
        let payload = Payload(version: 1, createdAt: Date(), entries: entries, projectColors: store.projectColors, projectLinks: store.projectLinks)
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        var salt = Data(count: 16)
        _ = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        let box = try AES.GCM.seal(try enc.encode(payload), using: key(passphrase, salt: salt, iterations: iterations), authenticating: aad)
        let env = Envelope(v: 1, kdf: "pbkdf2-sha256", iterations: iterations, salt: salt.base64EncodedString(), box: box.combined!.base64EncodedString())
        let out = JSONEncoder(); out.outputFormatting = [.prettyPrinted, .sortedKeys]
        try out.encode(env).write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return entries.count
    }

    @discardableResult
    public static func importBackup(from url: URL, passphrase: String, store: Store = .shared) throws -> ImportResult {
        guard let env = try? JSONDecoder().decode(Envelope.self, from: Data(contentsOf: url)), env.v == 1, env.kdf == "pbkdf2-sha256",
              (100_000...5_000_000).contains(env.iterations), let salt = Data(base64Encoded: env.salt), let raw = Data(base64Encoded: env.box)
        else { throw BackupError.unsupported }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        guard let box = try? AES.GCM.SealedBox(combined: raw),
              let plain = try? AES.GCM.open(box, using: key(passphrase, salt: salt, iterations: env.iterations), authenticating: aad),
              let payload = try? dec.decode(Payload.self, from: plain) else { throw BackupError.wrongPassphraseOrCorrupt }
        var r = ImportResult()
        for e in payload.entries {
            let det = Detection(envName: e.name, service: e.service ?? "Backup", type: e.type, value: e.value, confident: true, expiresAt: e.expiresAt, note: e.note)
            do { if try store.saveSecret(det, project: e.project, source: "Backup").isNew { r.keys += 1 } else { r.skipped += 1 } }
            catch { r.failed += 1 }
        }
        for (p, i) in payload.projectColors where store.projectColors[p] == nil { store.setProjectColor(p, index: i) }
        for (p, l) in payload.projectLinks where store.link(for: p) == nil { store.setLink(l, for: p) }
        return r
    }
}
