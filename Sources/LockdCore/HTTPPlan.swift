import Foundation

struct HTTPPlan {
    let method: String
    let url: String
    let headers: [String: String]
    let body: Any?
    let timeout: TimeInterval
    let names: [String]
    let host: String
    let path: String
    let auditTemplate: String
    init(_ args: [String: Any], client: SecureHTTPClient) throws {
        guard let method = args["method"] as? String, ["GET", "POST", "PUT", "PATCH", "DELETE"].contains(method),
              let raw = args["url"] as? String, raw.utf8.count <= 8192,
              let components = URLComponents(string: raw), let host = components.host?.lowercased(),
              !components.path.contains("{{"), !host.contains("{{"),
              !components.path.contains("%"), !components.path.contains("\\"),
              !components.path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) else {
            throw HTTPFailure(message: "Invalid method/URL; placeholders are forbidden in host and path")
        }
        _ = try client.validateURL(raw, hosts: [host])
        if let headers = args["headers"], !(headers is [String: String]) { throw HTTPFailure(message: "Headers must be a string dictionary") }
        let headers = args["headers"] as? [String: String] ?? [:]
        try SecureHTTPClient.validateHeaders(headers)
        guard !headers.keys.contains(where: { $0.contains("{{") }),
              !(components.queryItems ?? []).contains(where: { $0.name.contains("{{") }) else {
            throw HTTPFailure(message: "Placeholders may appear only in header values, query values and body")
        }
        let timeout = (args["timeout"] as? NSNumber)?.doubleValue ?? 30
        guard timeout.isFinite, timeout > 0, timeout <= 120 else { throw HTTPFailure(message: "Timeout must be in (0,120] seconds") }
        let body = args["body"]
        let bodyData = try Self.bodyData(body)
        guard (bodyData?.count ?? 0) <= SecureHTTPClient.requestLimit else { throw HTTPFailure(message: "Request body exceeds 256 KB") }
        let headerData = try JSONSerialization.data(withJSONObject: headers, options: [.sortedKeys])
        let template = method + " " + raw + "\n" + String(decoding: headerData, as: UTF8.self) + "\n" + (bodyData.map { String(decoding: $0, as: UTF8.self) } ?? "")
        var names = args["names"] as? [String] ?? []
        for match in Broker.placeholder.matches(in: template, range: NSRange(template.startIndex..., in: template)) {
            if let range = Range(match.range(at: 1), in: template), !names.contains(String(template[range])) { names.append(String(template[range])) }
        }
        guard !names.isEmpty, names.count <= 32 else { throw HTTPFailure(message: "Request requires 1–32 named keys or placeholders") }
        self.method = method; self.url = raw; self.host = host; self.path = components.path.isEmpty ? "/" : components.path
        self.headers = headers; self.body = body; self.timeout = timeout; self.names = names
        self.auditTemplate = String(template.prefix(8000)) + (template.count > 8000 ? "\n[template truncated]" : "")
    }
    static func bodyData(_ body: Any?) throws -> Data? {
        guard let body else { return nil }
        if let string = body as? String { return Data(string.utf8) }
        return try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .fragmentsAllowed])
    }
    static func replace(_ input: String, values: [String: String]) -> String {
        // Uma passagem: não interpretar placeholders introduzidos pelo próprio segredo.
        var out = input
        for match in Broker.placeholder.matches(in: input, range: NSRange(input.startIndex..., in: input)).reversed() {
            guard let range = Range(match.range, in: out), let nameRange = Range(match.range(at: 1), in: input), let value = values[String(input[nameRange])] else { continue }
            out.replaceSubrange(range, with: value)
        }
        return out
    }
    func materialized(_ values: [String: String]) throws -> (String, [String: String], Data?) {
        var components = URLComponents(string: url)!
        components.queryItems = components.queryItems?.map { URLQueryItem(name: $0.name, value: $0.value.map { Self.replace($0, values: values) }) }
        func json(_ value: Any) throws -> Any {
            if let string = value as? String { return Self.replace(string, values: values) }
            if let rows = value as? [Any] { return try rows.map(json) }
            if let fields = value as? [String: Any] {
                guard !fields.keys.contains(where: { $0.contains("{{") }) else { throw HTTPFailure(message: "Placeholders in JSON keys are forbidden") }
                return try fields.mapValues(json)
            }
            return value
        }
        let body = try self.body.map(json)
        var headers = self.headers.mapValues { Self.replace($0, values: values) }
        if self.body != nil, !(self.body is String), !headers.keys.contains(where: { $0.lowercased() == "content-type" }) {
            headers["Content-Type"] = "application/json"
        }
        try SecureHTTPClient.validateHeaders(headers)
        guard let url = components.url else { throw HTTPFailure(message: "Invalid substituted URL") }
        return (url.absoluteString, headers, try Self.bodyData(body))
    }
}
