import Foundation
import CryptoKit
import Security
import LocalAuthentication

/// Assinaturas detectam edição de JSON. Não fornecem âncora externa contra rollback do diretório inteiro.
enum RuleSigner {
    private static let lock = NSRecursiveLock()
    private static var highestCounter: [String: UInt64] = [:]
    private static var softwareMode: Bool { ProcessInfo.processInfo.environment["LOCKD_HOME"] != nil }
    private static var keyURL: URL { LockdPaths.support.appendingPathComponent(softwareMode ? ".test-signing-p256" : "rules-se-key.blob") }
    private static var manifestURL: URL { LockdPaths.support.appendingPathComponent("rules-manifest.json") }
    private struct Payload: Codable {
        let schema: Int
        let id: UUID
        let name: String
        let project: String?
        let service: String?
        let ciphertextHash: String
        let commands: [String]
        let hosts: [String]
        let allowEnv: Bool
        let wildcardConsent: [String]
        let methods: [String]?
        let paths: [String]?
        let version: UInt64
    }
    private struct Manifest: Codable {
        var counter: UInt64
        var entries: [String: String]
        var signature: String?
    }
    private static func encoded<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    private static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private static func payload(_ item: Item) throws -> Data {
        guard let cipher = item.cipher, let version = item.ruleVersion, version > 0,
              let commands = item.allowCommands, let hosts = item.allowHosts, let env = item.allowEnv else { throw Vault.VaultError.badData }
        return try encoded(Payload(schema: 1, id: item.id, name: item.name, project: item.project, service: item.service,
            ciphertextHash: hash(Data(cipher.utf8)), commands: commands.sorted(), hosts: hosts.sorted(), allowEnv: env,
            wildcardConsent: (item.confirmedWildcardHosts ?? []).sorted(), methods: item.allowedMethods?.sorted(), paths: item.allowedPathPrefixes?.sorted(), version: version))
    }
    private static func publicKey() throws -> P256.Signing.PublicKey {
        let data = try Data(contentsOf: keyURL)
        if softwareMode { return try P256.Signing.PrivateKey(rawRepresentation: data).publicKey }
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data).publicKey
    }
    private static func sign(_ data: Data, context: LAContext?) throws -> Data {
        if softwareMode {
            let key: P256.Signing.PrivateKey
            if FileManager.default.fileExists(atPath: keyURL.path) {
                key = try P256.Signing.PrivateKey(rawRepresentation: Data(contentsOf: keyURL))
            } else {
                guard !FileManager.default.fileExists(atPath: manifestURL.path) else { throw Vault.VaultError.unavailable("Rule signing key lost; restore original backup.") }
                key = P256.Signing.PrivateKey()
                try key.rawRepresentation.write(to: keyURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
            }
            return try key.signature(for: data).derRepresentation
        }
        guard let context else { throw Vault.VaultError.locked }
        let key: SecureEnclave.P256.Signing.PrivateKey
        if FileManager.default.fileExists(atPath: keyURL.path) {
            key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(contentsOf: keyURL), authenticationContext: context)
        } else {
            guard !FileManager.default.fileExists(atPath: manifestURL.path) else { throw Vault.VaultError.unavailable("Rule signing key lost; restore original backup.") }
            var error: Unmanaged<CFError>?
            guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence], &error) else { throw Vault.VaultError.unavailable("Rule access control unavailable") }
            key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: ac, authenticationContext: context)
            try key.dataRepresentation.write(to: keyURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
        }
        return try key.signature(for: data).derRepresentation
    }
    private static func manifest() throws -> Manifest {
        var result = try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: manifestURL))
        guard let signature = result.signature.flatMap({ Data(base64Encoded: $0) }) else { throw Vault.VaultError.badData }
        result.signature = nil
        guard try publicKey().isValidSignature(P256.Signing.ECDSASignature(derRepresentation: signature), for: encoded(result)) else { throw Vault.VaultError.badData }
        guard result.counter >= (highestCounter[manifestURL.path] ?? 0) else { throw Vault.VaultError.denied("Rule manifest rollback detected during this app session") }
        highestCounter[manifestURL.path] = result.counter
        return result
    }
    static func verify(_ item: Item) -> Bool {
        lock.lock(); defer { lock.unlock() }
        do {
            let body = try payload(item)
            guard let sig = item.ruleSignature.flatMap({ Data(base64Encoded: $0) }),
                  try publicKey().isValidSignature(P256.Signing.ECDSASignature(derRepresentation: sig), for: body),
                  try manifest().entries[item.id.uuidString] == hash(body) else { return false }
            return true
        } catch { return false }
    }
    /// Somente após autenticação nova e aprovação explícita da UI. Não chamado pelo Broker/MCP.
    static func signed(_ items: [Item], context: LAContext?) throws -> [Item] {
        lock.lock(); defer { lock.unlock() }
        var state = FileManager.default.fileExists(atPath: manifestURL.path) ? try manifest() : Manifest(counter: 0, entries: [:], signature: nil)
        state.counter = max(state.counter, highestCounter[manifestURL.path] ?? 0)
        guard state.counter < UInt64.max else { throw Vault.VaultError.badData }
        state.counter += 1
        var out: [Item] = []
        for var item in items {
            guard (item.ruleVersion ?? 0) < UInt64.max else { throw Vault.VaultError.badData }
            item.ruleVersion = max(state.counter, (item.ruleVersion ?? 0) + 1)
            let body = try payload(item)
            item.ruleSignature = try sign(body, context: context).base64EncodedString()
            state.entries[item.id.uuidString] = hash(body)
            out.append(item)
        }
        state.signature = try sign(encoded(state), context: context).base64EncodedString()
        try encoded(state).write(to: manifestURL, options: .atomic)
        highestCounter[manifestURL.path] = state.counter
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifestURL.path)
        return out
    }
}
