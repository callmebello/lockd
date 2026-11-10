import Foundation
import ImageIO
import CoreGraphics

// MARK: - Classificação

public struct FileVerdict: Sendable {
    public var category: String   // pasta dentro do projeto
    public var type: String
    public var kind: ItemKind
    public var confident: Bool   // true → pode mover sozinho (com Desfazer)
    public var ignore: Bool      // true → nem sugerir (screenshot, instalador…)

    public init(category: String, type: String, kind: ItemKind, confident: Bool, ignore: Bool) {
        self.category = category; self.type = type; self.kind = kind; self.confident = confident; self.ignore = ignore
    }
}

public enum FileClassifier {
    static let brandWords = ["logo", "icon", "brand", "mark", "gradient", "favicon", "wordmark", "symbol", "avatar", "banner", "splash"]
    static let screenshotWords = ["screenshot", "screen shot", "captura de tela", "cleanshot", "screen recording", "simulator screen", "gravação de tela"]
    static let rasterExt: Set<String> = ["png", "jpg", "jpeg", "webp", "gif", "heic", "tiff"]
    static let fontExt: Set<String> = ["ttf", "otf", "woff", "woff2"]
    static let credExt: [String: (String, String)] = [
        "p8": ("Apple", "Apple key (.p8)"), "mobileprovision": ("Apple", "Provisioning profile"),
        "provisionprofile": ("Apple", "Provisioning profile"), "p12": ("Apple", "Certificate bundle (.p12)"),
        "cer": ("Apple", "Certificate"), "certsigningrequest": ("Apple", "Signing request"),
        "pem": ("Key", "PEM key"), "keystore": ("Android", "Keystore"), "jks": ("Android", "Keystore"),
    ]
    static let ignoreExt: Set<String> = ["crdownload", "download", "part", "tmp", "dmg", "pkg", "zip", "app", "ds_store", "icloud"]

    public static func classify(_ url: URL) -> FileVerdict {
        let ext = url.pathExtension.lowercased()
        let name = url.deletingPathExtension().lastPathComponent.lowercased()
        let skip = FileVerdict(category: "Other", type: "File", kind: .asset, confident: false, ignore: true)

        if ignoreExt.contains(ext) || name.hasPrefix(".") { return skip }
        if credExt[ext] != nil {
            return FileVerdict(category: "Credentials", type: credExt[ext]!.1, kind: .credential, confident: true, ignore: false)
        }
        if name == ".env" || url.lastPathComponent.hasPrefix(".env") {
            return FileVerdict(category: "Credentials", type: "Env file", kind: .credential, confident: true, ignore: false)
        }
        if RecoveryCodes.looksLikeByName(url) {
            return FileVerdict(category: "Recovery codes", type: RecoveryCodes.type, kind: .secret, confident: true, ignore: false)
        }
        if screenshotWords.contains(where: name.contains) { return skip }
        let branded = brandWords.contains(where: name.contains)
        if fontExt.contains(ext) { return FileVerdict(category: "Fonts", type: "Font", kind: .asset, confident: true, ignore: false) }
        if ext == "svg" || ext == "ico" || ext == "icns" {
            return FileVerdict(category: branded ? "Logos" : "Vectors", type: branded ? "Logo" : "Vector",
                               kind: .asset, confident: true, ignore: false)
        }
        if rasterExt.contains(ext) {
            return FileVerdict(category: branded ? "Logos" : "Images", type: branded ? "Logo" : "Image",
                               kind: .asset, confident: branded, ignore: false)
        }
        if ext == "pdf" || ext == "fig" || ext == "sketch" {
            return FileVerdict(category: "Docs", type: ext.uppercased(), kind: .asset, confident: branded, ignore: false)
        }
        return skip
    }
}

// MARK: - Cores

public enum ColorExtractor {
    public static func colors(for url: URL, max: Int = 6) -> [String] {
        switch url.pathExtension.lowercased() {
        case "svg": return svgColors(url, max: max)
        case "png", "jpg", "jpeg", "webp", "gif", "heic", "tiff", "ico", "icns": return rasterColors(url, max: max)
        default: return []
        }
    }

    /// Retorna (cores, gradiente?) para SVG.
    static func svgColors(_ url: URL, max: Int) -> [String] {
        guard let text = try? String(contentsOf: url, encoding: .utf8), text.count < 2_000_000 else { return [] }
        var freq: [String: Int] = [:], order: [String] = []
        func push(_ hex: String) {
            let h = hex.uppercased()
            if freq[h] == nil { order.append(h) }
            freq[h, default: 0] += 1
        }
        if let re = try? NSRegularExpression(pattern: #"#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b"#) {
            for m in re.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
                guard let r = Range(m.range(at: 1), in: text) else { continue }
                var h = String(text[r])
                if h.count == 3 { h = h.map { "\($0)\($0)" }.joined() }
                push("#" + h)
            }
        }
        if let re = try? NSRegularExpression(pattern: #"rgb\(\s*(\d{1,3})[ ,]+(\d{1,3})[ ,]+(\d{1,3})"#) {
            for m in re.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
                let n = (1...3).compactMap { Range(m.range(at: $0), in: text).flatMap { Int(text[$0]) } }
                if n.count == 3 { push(String(format: "#%02X%02X%02X", min(n[0], 255), min(n[1], 255), min(n[2], 255))) }
            }
        }
        return order.sorted { freq[$0]! > freq[$1]! }.prefix(max).map { $0 }
    }

    static func rasterColors(_ url: URL, max: Int) -> [String] {
        guard let src = CGImageSourceCreateWithURL(url as CFURL, nil) else { return [] }
        let opts: [CFString: Any] = [kCGImageSourceCreateThumbnailFromImageAlways: true,
                                     kCGImageSourceThumbnailMaxPixelSize: 48,
                                     kCGImageSourceCreateThumbnailWithTransform: true]
        guard let img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary) else { return [] }
        let w = img.width, h = img.height
        guard w > 0, h > 0 else { return [] }
        var px = [UInt8](repeating: 0, count: w * h * 4)
        guard let ctx = CGContext(data: &px, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                                  space: CGColorSpaceCreateDeviceRGB(),
                                  bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return [] }
        ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))

        struct Bucket { var n = 0, r = 0, g = 0, b = 0 }
        var buckets: [Int: Bucket] = [:]
        for i in stride(from: 0, to: px.count, by: 4) {
            let a = Int(px[i + 3]); if a < 128 { continue }
            // desfaz alpha pré-multiplicado
            let r = min(255, Int(px[i]) * 255 / a), g = min(255, Int(px[i + 1]) * 255 / a), b = min(255, Int(px[i + 2]) * 255 / a)
            let key = (r >> 4) << 8 | (g >> 4) << 4 | (b >> 4)
            var bk = buckets[key] ?? Bucket()
            bk.n += 1; bk.r += r; bk.g += g; bk.b += b
            buckets[key] = bk
        }
        var picked: [(Int, Int, Int)] = []
        for bk in buckets.values.sorted(by: { $0.n > $1.n }) {
            let c = (bk.r / bk.n, bk.g / bk.n, bk.b / bk.n)
            let far = picked.allSatisfy { abs($0.0 - c.0) + abs($0.1 - c.1) + abs($0.2 - c.2) > 70 }
            if far { picked.append(c) }
            if picked.count >= max { break }
        }
        return picked.map { String(format: "#%02X%02X%02X", $0.0, $0.1, $0.2) }
    }
}

// MARK: - Validade

public enum ExpiryReader {
    public static func expiry(for url: URL) -> Date? {
        switch url.pathExtension.lowercased() {
        case "mobileprovision", "provisionprofile":
            guard let out = run("/usr/bin/security", ["cms", "-D", "-i", url.path]),
                  let plist = try? PropertyListSerialization.propertyList(from: out, format: nil) as? [String: Any]
            else { return nil }
            return plist["ExpirationDate"] as? Date
        case "cer", "pem", "crt":
            for extra in [[], ["-inform", "der"]] {
                if let out = run("/usr/bin/openssl", ["x509", "-noout", "-enddate", "-in", url.path] + extra),
                   let s = String(data: out, encoding: .utf8), let eq = s.firstIndex(of: "=") {
                    let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "MMM d HH:mm:ss yyyy zzz"
                    if let d = f.date(from: s[s.index(after: eq)...].trimmingCharacters(in: .whitespacesAndNewlines)) { return d }
                }
            }
            return nil
        default: return nil
        }
    }

    static func run(_ exe: String, _ args: [String]) -> Data? {
        let p = Process(); p.executableURL = URL(fileURLWithPath: exe); p.arguments = args
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        do { try p.run() } catch { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return p.terminationStatus == 0 ? data : nil
    }
}

// MARK: - Organizador

public enum IngestError: Error { case duplicate(Item), missing, ignored }

public enum Ingestor {
    public static func folderName(_ project: String?) -> String {
        (project ?? "_Inbox").replacingOccurrences(of: "/", with: "-")
    }

    static func destination(project: String?, category: String, fileName: String) -> URL {
        let dir = LockdPaths.libraryRoot.appendingPathComponent(folderName(project)).appendingPathComponent(category)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var dest = dir.appendingPathComponent(fileName)
        let base = dest.deletingPathExtension().lastPathComponent, ext = dest.pathExtension
        var n = 2
        while FileManager.default.fileExists(atPath: dest.path) {
            dest = dir.appendingPathComponent(ext.isEmpty ? "\(base)-\(n)" : "\(base)-\(n).\(ext)")
            n += 1
        }
        return dest
    }

    static func fileFingerprint(_ url: URL) -> String {
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        let head = (try? FileHandle(forReadingFrom: url).read(upToCount: 65_536)) ?? Data()
        return Vault.fingerprint(head + Data("\(size)".utf8))
    }

    /// Move o arquivo para ~/Lockd/<Projeto>/<Categoria>/ e registra.
    @discardableResult
    /// `copy: true` deixa o arquivo original no lugar (importação de projetos). Sem isso, ele é movido para a biblioteca.
    public static func ingest(_ url: URL, project: String?, verdict: FileVerdict? = nil, copy: Bool = false, store: Store = .shared) throws -> Item {
        guard FileManager.default.fileExists(atPath: url.path) else { throw IngestError.missing }
        var v = verdict ?? FileClassifier.classify(url)
        if v.type == RecoveryCodes.type, v.kind == .secret {
            // Lista de códigos de 2FA: vira segredo cifrado. Se o conteúdo não parecer uma lista, cai para arquivo de credencial.
            do { return try RecoveryCodes.ingest(url, project: project, copy: copy, store: store) }
            catch IngestError.ignored { v = FileVerdict(category: "Credentials", type: "Recovery codes (file)", kind: .credential, confident: true, ignore: false) }
        }
        let fp = fileFingerprint(url)
        if let e = store.existing(fingerprint: fp) { throw IngestError.duplicate(e) }

        let dest = destination(project: project, category: v.category, fileName: url.lastPathComponent)
        if copy { try FileManager.default.copyItem(at: url, to: dest) } else { try FileManager.default.moveItem(at: url, to: dest) }

        let colors = ColorExtractor.colors(for: dest)
        var note: String?
        if dest.pathExtension.lowercased() == "svg", let text = try? String(contentsOf: dest, encoding: .utf8),
           text.contains("Gradient"), colors.count >= 2 { note = "Gradient: " + colors.prefix(3).joined(separator: " → ") }
        let size = (try? dest.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        let service = FileClassifier.credExt[url.pathExtension.lowercased()]?.0

        let item = Item(kind: v.kind, name: dest.lastPathComponent, service: service, type: v.type, project: project,
                        expiresAt: ExpiryReader.expiry(for: dest), fingerprint: fp,
                        preview: ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file),
                        path: dest.path, originalPath: url.path, colors: colors.isEmpty ? nil : colors, note: note)
        store.add(item)
        return item
    }

    /// Desfaz: devolve o arquivo ao lugar original e esquece o item.
    public static func undo(_ item: Item, store: Store = .shared) {
        if let p = item.path, let o = item.originalPath, FileManager.default.fileExists(atPath: p) {
            if !FileManager.default.fileExists(atPath: o) { try? FileManager.default.moveItem(atPath: p, toPath: o) }
            else { try? FileManager.default.trashItem(at: URL(fileURLWithPath: p), resultingItemURL: nil) }   // era uma cópia
        }
        store.remove(id: item.id)
    }

    /// Troca o projeto de um item (e move o arquivo junto).
    public static func reassign(_ item: Item, to project: String?, store: Store = .shared) {
        var newPath = item.path
        if let p = item.path, FileManager.default.fileExists(atPath: p) {
            let cat = URL(fileURLWithPath: p).deletingLastPathComponent().lastPathComponent
            let dest = destination(project: project, category: cat, fileName: URL(fileURLWithPath: p).lastPathComponent)
            if (try? FileManager.default.moveItem(atPath: p, toPath: dest.path)) != nil { newPath = dest.path }
        }
        store.update(id: item.id) { $0.project = project; $0.path = newPath }
    }

    /// Apaga o item e (para arquivos) manda o arquivo para a Lixeira.
    public static func delete(_ item: Item, store: Store = .shared) {
        if let p = item.path, FileManager.default.fileExists(atPath: p) {
            try? FileManager.default.trashItem(at: URL(fileURLWithPath: p), resultingItemURL: nil)
        }
        store.remove(id: item.id)
    }
}


/// Busca por cor: "#22d3ee" encontra logos e imagens com uma cor parecida na paleta extraída.
public enum ColorMatch {
    public static func isColorToken(_ t: String) -> Bool { t.hasPrefix("#") && parse(t) != nil }

    public static func parse(_ token: String) -> (Int, Int, Int)? {
        var h = token.trimmingCharacters(in: CharacterSet(charactersIn: "#"))
        if h.count == 3 { h = h.map { "\($0)\($0)" }.joined() }
        guard h.count == 6, let v = Int(h, radix: 16) else { return nil }
        return ((v >> 16) & 255, (v >> 8) & 255, v & 255)
    }

    public static func distance(_ a: (Int, Int, Int), _ b: (Int, Int, Int)) -> Int { abs(a.0 - b.0) + abs(a.1 - b.1) + abs(a.2 - b.2) }

    public static func matches(_ item: Item, token: String, tolerance: Int = 90) -> Bool {
        guard let target = parse(token) else { return false }
        return (item.colors ?? []).contains { c in parse(c).map { distance($0, target) <= tolerance } ?? false }
    }
}
