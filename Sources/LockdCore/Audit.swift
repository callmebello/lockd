import Foundation

public struct AuditEntry: Codable, Identifiable, Sendable {
    public var id = UUID()
    public var date = Date()
    public var tool: String
    public var status: String            // ok | denied | error
    public var project: String?
    public var secrets: [String]
    public var command: String?          // argv SEM os valores (placeholders intactos)
    public var hosts: [String] = []      // permitidos
    public var contacted: [String] = []
    public var blocked: [String] = []
    public var resolvedProgram: String?  // caminho verificado, nunca argumentos com valores
    public var exitCode: Int32?
    public var detail: String?
    public var approvedBy: String?       // "session" | "touch-id"

    public init(tool: String, status: String, project: String? = nil, secrets: [String] = [], command: String? = nil, detail: String? = nil) {
        self.tool = tool; self.status = status; self.project = project; self.secrets = secrets; self.command = command; self.detail = detail
    }
}

/// Registro de uso em JSON Lines. NUNCA grava valores de segredos.
public enum Audit {
    nonisolated(unsafe) private static let lock = NSLock()

    public static func write(_ e: AuditEntry) {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        guard var d = try? enc.encode(e) else { return }
        d.append(0x0A)
        lock.lock(); defer { lock.unlock() }
        let url = LockdPaths.auditFile
        if let h = try? FileHandle(forWritingTo: url) {
            defer { try? h.close() }
            _ = try? h.seekToEnd(); try? h.write(contentsOf: d)
        } else {
            try? d.write(to: url)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
        DispatchQueue.main.async { NotificationCenter.default.post(name: Store.didChange, object: nil) }
    }

    public static func recent(limit: Int = 50) -> [AuditEntry] {
        guard let s = try? String(contentsOf: LockdPaths.auditFile, encoding: .utf8) else { return [] }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        return s.split(separator: "\n").suffix(limit).compactMap { try? dec.decode(AuditEntry.self, from: Data($0.utf8)) }.reversed()
    }
}
