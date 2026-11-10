import Foundation

/// Tira segredos de qualquer saída que volte para o Claude: valor exato, base64, hex, URL-encoded, invertido
/// e FATIAS de 10+ caracteres (pega `cut`, `${KEY:0:20}` etc.). Depois varre por padrões de chave conhecidos.
public enum Redactor {
    static let window = 10

    static func variants(_ v: String) -> [String] {
        let data = Data(v.utf8)
        let b64 = data.base64EncodedString()
        let b64url = b64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        let hex = data.map { String(format: "%02x", $0) }.joined()
        var out = [v, String(v.reversed()), b64, b64.replacingOccurrences(of: "=", with: ""), b64url,
                   b64url.replacingOccurrences(of: "=", with: ""), hex, hex.uppercased()]
        if let pct = v.addingPercentEncoding(withAllowedCharacters: CharacterSet.alphanumerics), pct != v { out.append(pct) }
        // base64 em 3 alinhamentos (a chave aparecendo no meio de outro texto base64)
        for pad in 1...2 {
            let shifted = Data(String(repeating: "A", count: pad).utf8) + data
            let s = shifted.base64EncodedString().replacingOccurrences(of: "=", with: "")
            out.append(String(s.dropFirst(pad == 1 ? 2 : 3)))
        }
        return out.filter { !$0.isEmpty }
    }

    static func redactTemplate(_ text: String, secrets: [(name: String, value: String)]) -> String {
        var out = "", cursor = text.startIndex
        for match in Broker.placeholder.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            guard let range = Range(match.range, in: text) else { continue }
            out += redact(String(text[cursor..<range.lowerBound]), secrets: secrets)
            out += text[range]
            cursor = range.upperBound
        }
        return out + redact(String(text[cursor...]), secrets: secrets)
    }

    public static func redact(_ text: String, secrets: [(name: String, value: String)]) -> String {
        var bytes = Array(text.utf8)
        var owner = [Int](repeating: -1, count: bytes.count)   // índice do segredo que cobre cada byte

        for (si, s) in secrets.enumerated() where !s.value.isEmpty {
            var tables: [Int: Set<[UInt8]>] = [:]
            for var variant in variants(s.value) {
                var vb = Array(variant.utf8)
                let k = min(window, vb.count)
                guard k > 0 else { continue }
                for i in 0...(vb.count - k) { tables[k, default: []].insert(Array(vb[i..<(i + k)])) }
                variant.removeAll(); vb.removeAll()
            }
            for (k, table) in tables where bytes.count >= k {
                for i in 0...(bytes.count - k) where table.contains(Array(bytes[i..<(i + k)])) {
                    for j in i..<(i + k) { owner[j] = si }
                }
            }
        }

        var out = [UInt8](); var i = 0
        while i < bytes.count {
            if owner[i] >= 0 {
                let si = owner[i]
                while i < bytes.count, owner[i] >= 0 { i += 1 }
                out.append(contentsOf: Array("[REDACTED:\(secrets[si].name)]".utf8))
            } else { out.append(bytes[i]); i += 1 }
        }
        var result = String(decoding: out, as: UTF8.self)

        // 2ª camada: qualquer coisa que pareça uma chave conhecida
        if let re = try? NSRegularExpression(pattern: #"[A-Za-z0-9_\-\.\+/=:]{20,}"#) {
            let ns = result as NSString
            var parts: [(NSRange, String)] = []
            for m in re.matches(in: result, range: NSRange(location: 0, length: ns.length)) {
                let tok = ns.substring(with: m.range)
                if !tok.contains("[REDACTED"), let d = Detector.detect(in: tok).first, d.confident { parts.append((m.range, d.envName)) }
            }
            for (r, n) in parts.reversed() { result = (result as NSString).replacingCharacters(in: r, with: "[REDACTED:\(n)]") }
        }
        return result
    }
}
