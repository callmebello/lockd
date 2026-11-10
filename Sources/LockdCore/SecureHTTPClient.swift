import Foundation
import Darwin

struct HTTPFailure: Error, LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// URLSession efêmera, sem cookies/credenciais/cache, com TLS normal e sem redirects.
/// HTTPS usa túnel local fixado ao IP público validado: DNS não é consultado de novo pelo upstream.
final class SecureHTTPClient {
    struct Result {
        let status: Int
        let contentType: String
        let data: Data
        let truncated: Bool
        let binary: Bool
    }
    static let requestLimit = 256 * 1024
    static let responseLimit = 1024 * 1024
    private let allowLoopback: Bool
    init() { allowLoopback = false }
    #if DEBUG
    /// Inexistente no build de produção. Não há variável de ambiente que habilite isto.
    init(testAllowLoopback: Bool) {
        precondition(ProcessInfo.processInfo.environment["LOCKD_HOME"] != nil)
        allowLoopback = testAllowLoopback
    }
    #endif

    func validateURL(_ raw: String, hosts: [String]) throws -> URL {
        guard !raw.utf8.contains(where: { $0 < 0x20 || $0 == 0x7f }), let components = URLComponents(string: raw),
              let host = components.host?.lowercased(), !host.isEmpty,
              hosts.contains(host), !host.contains("*"), !host.hasSuffix("."),
              components.user == nil, components.password == nil, components.fragment == nil,
              let url = components.url else { throw HTTPFailure(message: "URL or exact host is not allowed") }
        let isTestLocal = allowLoopback && (host == "127.0.0.1" || host == "localhost")
        guard (components.scheme == "https" && (components.port == nil || components.port == 443)) ||
              (isTestLocal && components.scheme == "http") else { throw HTTPFailure(message: "Only HTTPS on port 443 is allowed") }
        if !isTestLocal {
            guard host != "localhost", !host.hasSuffix(".localhost"), !Self.isIPLiteral(host) else { throw HTTPFailure(message: "IP literals and local hosts are forbidden") }
        }
        return url
    }
    static func isIPLiteral(_ raw: String) -> Bool {
        let s = raw.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var a = in_addr(), b = in6_addr()
        return inet_pton(AF_INET, s, &a) == 1 || inet_pton(AF_INET6, s, &b) == 1 || s.contains(":") ||
            s.allSatisfy { $0.isNumber || $0 == "." }
    }
    static func isPublicAddress(_ raw: String) -> Bool {
        var ipv4 = in_addr()
        if inet_pton(AF_INET, raw, &ipv4) == 1 {
            let v = UInt32(bigEndian: ipv4.s_addr)
            let a = v >> 24, b = (v >> 16) & 255, c = (v >> 8) & 255
            if a == 0 || a == 10 || a == 127 || a >= 224 { return false }
            if a == 100 && (64...127).contains(b) { return false }
            if a == 169 && b == 254 || a == 172 && (16...31).contains(b) { return false }
            if a == 192 && (b == 168 || b == 0 && (c == 0 || c == 2)) { return false }
            if a == 198 && (b == 18 || b == 19 || b == 51 && c == 100) { return false }
            if a == 203 && b == 0 && c == 113 { return false }
            return true
        }
        var ipv6 = in6_addr()
        guard inet_pton(AF_INET6, raw, &ipv6) == 1 else { return false }
        let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
        guard bytes[0] & 0xe0 == 0x20 else { return false } // global unicast 2000::/3
        if bytes[0] == 0x20 && bytes[1] == 0x02 { return false } // 6to4
        if bytes[0] == 0x20 && bytes[1] == 0x01 &&
            ((bytes[2] == 0x0d && bytes[3] == 0xb8) || bytes[2] < 2) { return false }
        return true
    }
    static func resolvePublic(_ host: String, timeout: TimeInterval) throws -> String {
        final class Resolution: @unchecked Sendable {
            let lock = NSLock(); var addresses: [String] = []
        }
        let state = Resolution(), done = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .utility).async {
            var hints = addrinfo(); hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP
            var result: UnsafeMutablePointer<addrinfo>?
            var addresses: [String] = []
            if getaddrinfo(host, "443", &hints, &result) == 0 {
                defer { if let result { freeaddrinfo(result) } }
                var current = result
                while let item = current {
                    var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(item.pointee.ai_addr, item.pointee.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                        addresses.append(String(cString: buffer))
                    }
                    current = item.pointee.ai_next
                }
            }
            state.lock.lock(); state.addresses = addresses; state.lock.unlock(); done.signal()
        }
        guard done.wait(timeout: .now() + min(10, timeout)) == .success else { throw HTTPFailure(message: "DNS resolution timed out") }
        state.lock.lock(); let addresses = state.addresses; state.lock.unlock()
        guard let first = addresses.first, addresses.allSatisfy(isPublicAddress) else { throw HTTPFailure(message: "DNS returned no address or a non-public address") }
        return first
    }
    static func validateHeaders(_ headers: [String: String]) throws {
        let allowed = CharacterSet(charactersIn: "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        for (key, value) in headers {
            guard !key.isEmpty, key.unicodeScalars.allSatisfy({ allowed.contains($0) }),
                  !value.utf8.contains(where: { ($0 < 0x20 && $0 != 9) || $0 == 0x7f }),
                  !["host", "content-length", "transfer-encoding", "connection", "trailer", "upgrade", "cookie"].contains(key.lowercased()),
                  !key.lowercased().hasPrefix("proxy-") else { throw HTTPFailure(message: "Invalid or reserved HTTP header") }
        }
    }
    func perform(method: String, url raw: String, headers: [String: String], body: Data?, hosts: [String], timeout: TimeInterval) throws -> Result {
        guard ["GET", "POST", "PUT", "PATCH", "DELETE"].contains(method), timeout.isFinite, timeout > 0, timeout <= 120 else { throw HTTPFailure(message: "Invalid HTTP method or timeout (maximum 120 seconds)") }
        guard (body?.count ?? 0) <= Self.requestLimit else { throw HTTPFailure(message: "Request body exceeds 256 KB") }
        try Self.validateHeaders(headers)
        let url = try validateURL(raw, hosts: hosts)
        let deadline = Date().addingTimeInterval(timeout)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false; configuration.httpCookieStorage = nil
        configuration.urlCache = nil; configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = timeout; configuration.timeoutIntervalForResource = timeout
        let pinnedProxy: FilterProxy?
        if url.scheme == "https" {
            let address = try Self.resolvePublic(url.host!, timeout: timeout)
            let proxy = FilterProxy(allowedHosts: [url.host!], pinnedAddresses: [url.host!: address])
            let port = try proxy.start(); pinnedProxy = proxy
            configuration.connectionProxyDictionary = ["HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": Int(port),
                "HTTPSEnable": 1, "HTTPSProxy": "127.0.0.1", "HTTPSPort": Int(port), "ExceptionsList": [], "ExcludeSimpleHostnames": 0]
        } else {
            // Só alcançável pelo inicializador DEBUG de loopback.
            pinnedProxy = nil; configuration.connectionProxyDictionary = [:]
        }
        defer { pinnedProxy?.stop() }
        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0 else { throw HTTPFailure(message: "HTTP timeout exceeded during DNS/connection preparation") }
        configuration.timeoutIntervalForRequest = remaining; configuration.timeoutIntervalForResource = remaining
        let receiver = HTTPReceiver()
        let session = URLSession(configuration: configuration, delegate: receiver, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url, timeoutInterval: remaining)
        request.httpMethod = method; request.httpBody = body
        for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
        let task = session.dataTask(with: request)
        task.resume()
        guard receiver.finished.wait(timeout: .now() + remaining + 1) == .success else {
            task.cancel(); throw HTTPFailure(message: "HTTP request timed out")
        }
        let result = try receiver.result()
        if let pinnedProxy, !pinnedProxy.contacted.contains(url.host!) {
            throw HTTPFailure(message: "HTTPS did not use the pinned connection; response discarded")
        }
        return result
    }
}

private final class HTTPReceiver: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    let finished = DispatchSemaphore(value: 0)
    private var data = Data()
    private var response: HTTPURLResponse?
    private var failure: Error?
    private var truncated = false
    private var redirected = false
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        // Não seguir nenhum redirect: nenhum Authorization/header sensível é reenviado, nem no mesmo host.
        redirected = true; completionHandler(nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.performDefaultHandling, nil)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        self.response = response as? HTTPURLResponse; completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        let room = max(0, SecureHTTPClient.responseLimit - data.count)
        data.append(chunk.prefix(room))
        if chunk.count > room { truncated = true; dataTask.cancel() }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        failure = error; finished.signal()
    }
    func result() throws -> SecureHTTPClient.Result {
        if redirected { throw HTTPFailure(message: "Redirect refused; sensitive headers were not forwarded") }
        if let failure, !truncated { throw HTTPFailure(message: "HTTP transport failed (\((failure as NSError).code)); response omitted") }
        guard let response else { throw HTTPFailure(message: "Missing HTTP response") }
        let type = response.value(forHTTPHeaderField: "Content-Type") ?? "application/octet-stream"
        let mime = type.lowercased().split(separator: ";").first.map(String.init) ?? ""
        let textual = mime.hasPrefix("text/") || mime == "application/json" || mime.hasSuffix("+json") || mime == "application/xml" || mime.hasSuffix("+xml")
        return SecureHTTPClient.Result(status: response.statusCode, contentType: type, data: data, truncated: truncated,
            binary: !textual || String(data: data, encoding: .utf8) == nil || data.contains(0))
    }
}
