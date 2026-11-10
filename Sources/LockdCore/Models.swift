import Foundation

public enum ItemKind: String, Codable, Sendable {
    case secret      // texto copiado (chave de API, token, URL de banco…)
    case asset       // logo, imagem, fonte
    case credential  // arquivo de credencial (.p8, .mobileprovision, .p12…)
}

public struct Item: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var kind: ItemKind
    public var name: String            // nome de env (ANTHROPIC_API_KEY) ou nome do arquivo
    public var service: String?
    public var type: String
    public var project: String?        // nil = Inbox
    public var createdAt: Date
    public var expiresAt: Date?
    public var fingerprint: String
    public var preview: String
    public var cipher: String?         // AES-GCM (base64) — só para secrets
    public var path: String?           // arquivo organizado — só para assets/credentials
    public var originalPath: String?
    public var colors: [String]?
    public var note: String?
    public var source: String?
    // Regras de acesso do Claude (nil = usa o padrão do serviço)
    public var allowCommands: [String]?
    public var allowHosts: [String]?
    public var allowEnv: Bool?
    public var ruleSignature: String?
    public var ruleVersion: UInt64?
    public var allowedMethods: [String]?
    public var allowedPathPrefixes: [String]?
    public var confirmedWildcardHosts: [String]? // consentimento explícito da UI; incluído na assinatura

    public init(id: UUID = UUID(), kind: ItemKind, name: String, service: String? = nil, type: String,
                project: String? = nil, createdAt: Date = Date(), expiresAt: Date? = nil,
                fingerprint: String, preview: String, cipher: String? = nil, path: String? = nil,
                originalPath: String? = nil, colors: [String]? = nil, note: String? = nil, source: String? = nil,
                allowCommands: [String]? = nil, allowHosts: [String]? = nil, allowEnv: Bool? = nil, confirmedWildcardHosts: [String]? = nil) {
        self.id = id; self.kind = kind; self.name = name; self.service = service; self.type = type
        self.project = project; self.createdAt = createdAt; self.expiresAt = expiresAt
        self.fingerprint = fingerprint; self.preview = preview; self.cipher = cipher; self.path = path
        self.originalPath = originalPath; self.colors = colors; self.note = note; self.source = source
        self.allowCommands = allowCommands; self.allowHosts = allowHosts; self.allowEnv = allowEnv
        self.confirmedWildcardHosts = confirmedWildcardHosts
    }

    public var isFile: Bool { kind != .secret }
    public var fileURL: URL? { path.map { URL(fileURLWithPath: $0) } }

    public var daysUntilExpiry: Int? {
        guard let e = expiresAt else { return nil }
        return Calendar.current.dateComponents([.day], from: Calendar.current.startOfDay(for: Date()),
                                               to: Calendar.current.startOfDay(for: e)).day
    }

    public var haystack: String {
        [name, service ?? "", type, project ?? "inbox", note ?? "", source ?? ""].joined(separator: " ").lowercased()
    }
}

public enum LockdPaths {
    /// LOCKD_HOME existe só para testes.
    public static var support: URL {
        let base: URL
        if let h = ProcessInfo.processInfo.environment["LOCKD_HOME"] {
            base = URL(fileURLWithPath: h)
        } else {
            base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("Lockd")
        }
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }
    public static var auditFile: URL { support.appendingPathComponent("audit.jsonl") }
    public static var socketFile: URL { support.appendingPathComponent("lockd.sock") }
    public static var itemsFile: URL { support.appendingPathComponent("items.json") }
    public static var projectsFile: URL { support.appendingPathComponent("projects.json") }
    public static var projectLinksFile: URL { support.appendingPathComponent("project-links.json") }
    public static var projectColorsFile: URL { support.appendingPathComponent("project-colors.json") }
    public static var libraryRoot: URL {
        if let h = ProcessInfo.processInfo.environment["LOCKD_HOME"] {
            return URL(fileURLWithPath: h).appendingPathComponent("library")
        }
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Lockd")
    }
}
