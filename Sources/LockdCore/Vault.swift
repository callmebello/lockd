import Foundation
import CryptoKit
import Security
import LocalAuthentication

/// Cofre. Guardar um segredo cifra com a chave PÚBLICA do Secure Enclave (sem Touch ID).
/// Ler exige a chave PRIVADA, que só o Secure Enclave usa e só com a sua presença (Touch ID/senha).
/// A sessão exige presença local; não isola todos os processos do mesmo usuário.
///
/// v3: ECIES P-256 + HKDF + AES-GCM com AAD ligado ao UUID do item; aceita leitura v2.
public final class Vault: @unchecked Sendable {
    public static let shared = Vault()

    public enum VaultError: Error, LocalizedError {
        case locked, badData, unavailable(String), denied(String)
        public var errorDescription: String? {
            switch self {
            case .locked: return "Vault is locked. Approve with Touch ID in Lockd."
            case .badData: return "Corrupted secret."
            case .unavailable(let s): return "Secure Enclave unavailable: \(s)"
            case .denied(let s): return "Not approved: \(s)"
            }
        }
    }

    /// Modo teste (LOCKD_HOME): chave de software, sem Touch ID. Nunca usado em produção.
    private var softwareMode: Bool { ProcessInfo.processInfo.environment["LOCKD_HOME"] != nil }

    private let now: () -> Date
    private var simulatedSession = false
    public init() { now = Date.init }
    #if DEBUG
    /// Apenas testes de sessão, com criptografia de software e LOCKD_HOME obrigatório.
    internal init(now: @escaping () -> Date, simulatedSession: Bool) {
        precondition(ProcessInfo.processInfo.environment["LOCKD_HOME"] != nil)
        self.now = now
        self.simulatedSession = simulatedSession
    }
    #endif
    private let lock = NSLock()
    private var generation: UInt64 = 0
    private var context: LAContext?
    private var cache: [String: String] = [:]           // cifrado → valor (só durante a sessão)
    private var unlockedUntil = Date.distantPast
    public var sessionSeconds: TimeInterval = 30 * 60

    private var blobURL: URL { LockdPaths.support.appendingPathComponent("se-key.blob") }
    private var pubURL: URL { LockdPaths.support.appendingPathComponent("se-key.pub") }
    private var softURL: URL { LockdPaths.support.appendingPathComponent(".test-p256") }

    // MARK: - Estado da sessão

    /// Chamar somente sob lock. Expiração revoga cache e contexto juntos.
    private func sessionValidLocked() -> Bool {
        if softwareMode && !simulatedSession { return true }
        guard now() < unlockedUntil else {
            cache.removeAll(); context?.invalidate(); context = nil
            unlockedUntil = .distantPast
            return false
        }
        return true
    }

    public var isUnlocked: Bool {
        lock.lock(); defer { lock.unlock() }
        return sessionValidLocked()
    }

    internal var sessionIdentifier: UInt64? {
        lock.lock(); defer { lock.unlock() }
        return sessionValidLocked() ? generation : nil
    }

    public var unlockedRemaining: TimeInterval {
        lock.lock(); defer { lock.unlock() }
        guard sessionValidLocked() else { return 0 }
        return max(0, unlockedUntil.timeIntervalSince(now()))
    }

    public func lockNow() {
        lock.lock(); defer { lock.unlock() }
        generation &+= 1
        cache.removeAll(); context?.invalidate(); context = nil; unlockedUntil = .distantPast
    }

    /// Pede Touch ID (ou senha do Mac). Bloqueia até o usuário responder. Chame fora da main thread.
    public func unlock(reason: String, fresh: Bool = false) throws {
        if softwareMode {
            if simulatedSession {
                lock.lock(); defer { lock.unlock() }
                generation &+= 1
                unlockedUntil = now().addingTimeInterval(sessionSeconds)
            }
            return
        }
        let ctx = LAContext()
        ctx.localizedReason = reason
        ctx.touchIDAuthenticationAllowableReuseDuration = fresh ? 0 : LATouchIDAuthenticationMaximumAllowableReuseDuration
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
            throw VaultError.unavailable(err?.localizedDescription ?? "no authentication available")
        }
        let sem = DispatchSemaphore(value: 0)
        var ok = false; var failure: Error?
        ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
            ok = success; failure = error; sem.signal()
        }
        sem.wait()
        guard ok else { throw VaultError.denied(failure?.localizedDescription ?? "cancelled") }
        lock.lock()
        context?.invalidate(); cache.removeAll(); generation &+= 1
        context = ctx
        unlockedUntil = now().addingTimeInterval(sessionSeconds)
        lock.unlock()
    }

    // MARK: - Chave

    private let keyLock = NSRecursiveLock()
    private var preparationIssue: String?
    public var keyIssue: String? { keyLock.lock(); defer { keyLock.unlock() }; return preparationIssue }
    internal var signingContext: LAContext? {
        lock.lock(); defer { lock.unlock() }
        return sessionValidLocked() ? context : nil
    }
    private func hasCiphertexts() -> Bool {
        let file = LockdPaths.itemsFile
        guard FileManager.default.fileExists(atPath: file.path) else { return false }
        guard let data = try? Data(contentsOf: file),
              let rows = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return true }
        return rows.contains { ($0["cipher"] as? String)?.isEmpty == false }
    }
    private func missingKey() -> VaultError {
        .unavailable("Vault key blob is missing. Encryption stopped to avoid data loss. Restore a backup on the original Mac; see docs/BACKUP-OPTIONS.md. Do not reset the vault.")
    }
    private func publicKey() throws -> P256.KeyAgreement.PublicKey {
        keyLock.lock(); defer { keyLock.unlock() }
        do {
            let derived: P256.KeyAgreement.PublicKey
            if softwareMode { derived = try softwareKey().publicKey }
            else if FileManager.default.fileExists(atPath: blobURL.path) {
                // Ler a pública do blob opaco não faz operação de chave privada.
                derived = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Data(contentsOf: blobURL)).publicKey
            } else {
                guard !FileManager.default.fileExists(atPath: pubURL.path), !hasCiphertexts() else { throw missingKey() }
                guard SecureEnclave.isAvailable else { throw VaultError.unavailable("this Mac has no Secure Enclave") }
                var error: Unmanaged<CFError>?
                guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    [.privateKeyUsage, .userPresence], &error) else { throw VaultError.unavailable("access control") }
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
                try key.dataRepresentation.write(to: blobURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: blobURL.path)
                derived = key.publicKey
                try derived.x963Representation.write(to: pubURL, options: .atomic)
            }
            if FileManager.default.fileExists(atPath: pubURL.path) {
                guard try Data(contentsOf: pubURL) == derived.x963Representation else {
                    throw VaultError.unavailable("Vault public key does not match its device-bound blob. Encryption stopped. Restore the original files; see docs/BACKUP-OPTIONS.md.")
                }
            }
            preparationIssue = nil
            return derived
        } catch {
            preparationIssue = "Vault key unavailable or inconsistent. Encryption stopped. Restore backup/original key files; see docs/BACKUP-OPTIONS.md."
            throw error
        }
    }

    private func softwareKey() throws -> P256.KeyAgreement.PrivateKey {
        keyLock.lock(); defer { keyLock.unlock() }
        if FileManager.default.fileExists(atPath: softURL.path) {
            return try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(contentsOf: softURL))
        }
        guard !hasCiphertexts(), !FileManager.default.fileExists(atPath: pubURL.path) else { throw missingKey() }
        let key = P256.KeyAgreement.PrivateKey()
        try key.rawRepresentation.write(to: softURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: softURL.path)
        return key
    }

    private func derive(_ shared: SharedSecret, salt: Data, version: String) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data("lockd-\(version)".utf8), outputByteCount: 32)
    }

    /// Cria a chave do Secure Enclave se ainda não existe (precisa do Mac desbloqueado).
    /// Retorna false se não deu agora — o app tenta de novo quando a tela desbloquear.
    @discardableResult
    public func prepare() -> Bool {
        do { _ = try publicKey(); return true }
        catch { NSLog("[lockd] vault key not ready yet: %@", String(describing: error)); return false }
    }

    // MARK: - Cifrar / decifrar

    public func encrypt(_ plain: String, itemID: UUID) throws -> String {
        try encryptEnvelope(plain, itemID: itemID)
    }
    #if DEBUG
    internal func encryptLegacyForTests(_ plain: String) throws -> String { try encryptEnvelope(plain, itemID: nil) }
    #endif
    private func encryptEnvelope(_ plain: String, itemID: UUID?) throws -> String {
        let version = itemID == nil ? "v2" : "v3"
        let aad = itemID.map { Data("lockd-v3:\($0.uuidString.lowercased())".utf8) } ?? Data()
        let pub = try publicKey()
        let eph = P256.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.x963Representation
        let sym = derive(try eph.sharedSecretFromKeyAgreement(with: pub), salt: ephPub, version: version)
        let box = try AES.GCM.seal(Data(plain.utf8), using: sym, authenticating: aad)
        guard let combined = box.combined else { throw VaultError.badData }
        let out = version + ":" + (ephPub + combined).base64EncodedString()
        lock.lock()
        if sessionValidLocked() { cache[(itemID?.uuidString ?? "legacy") + out] = plain }
        lock.unlock()
        return out
    }

    public func decrypt(_ stored: String, itemID: UUID? = nil) throws -> String {
        let version = stored.hasPrefix("v3:") ? "v3" : "v2"
        guard version != "v3" || itemID != nil else { throw VaultError.badData }
        let cacheID = (itemID?.uuidString ?? "legacy") + stored
        lock.lock()
        guard sessionValidLocked() else { lock.unlock(); throw VaultError.locked }
        if let hit = cache[cacheID] { lock.unlock(); return hit }
        let ctx = context, startedGeneration = generation
        lock.unlock()
        guard (stored.hasPrefix("v2:") || stored.hasPrefix("v3:")), let raw = Data(base64Encoded: String(stored.dropFirst(3))), raw.count >= 65 + 28 else {
            throw VaultError.badData
        }
        let ephPubData = raw.prefix(65), combined = raw.dropFirst(65)
        let ephPub = try P256.KeyAgreement.PublicKey(x963Representation: ephPubData)
        let shared: SharedSecret
        if softwareMode {
            shared = try softwareKey().sharedSecretFromKeyAgreement(with: ephPub)
        } else {
            guard isUnlocked, let ctx else { throw VaultError.locked }
            guard FileManager.default.fileExists(atPath: blobURL.path) else {
                keyLock.lock(); preparationIssue = missingKey().localizedDescription; keyLock.unlock()
                throw missingKey()
            }
            let blob = try Data(contentsOf: blobURL)
            let sePriv = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
            shared = try sePriv.sharedSecretFromKeyAgreement(with: ephPub)
        }
        let box = try AES.GCM.SealedBox(combined: combined)
        let aad = version == "v3" ? Data("lockd-v3:\(itemID!.uuidString.lowercased())".utf8) : Data()
        let plain = try AES.GCM.open(box, using: derive(shared, salt: Data(ephPubData), version: version), authenticating: aad)
        guard let s = String(data: plain, encoding: .utf8) else { throw VaultError.badData }
        lock.lock(); defer { lock.unlock() }
        guard sessionValidLocked(), generation == startedGeneration else { throw VaultError.locked }
        cache[cacheID] = s
        return s
    }

    public static func fingerprint(_ data: Data) -> String {
        SHA256.hash(data: data).prefix(12).map { String(format: "%02x", $0) }.joined()
    }
    public static func fingerprint(_ s: String) -> String { fingerprint(Data(s.utf8)) }
}
