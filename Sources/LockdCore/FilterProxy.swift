import Foundation
import Network

/// Proxy HTTPS local que só abre túnel (CONNECT :443) para hosts da lista. O comando roda num sandbox sem
/// rede e sem DNS, e só enxerga ESTE proxy: o que não passa por aqui simplesmente não sai do Mac.
final class FilterProxy: @unchecked Sendable {
    private let queue = DispatchQueue(label: "lockd.proxy")
    private var listener: NWListener?
    private let hosts: [String]
    private let pinnedAddresses: [String: String]
    private var connections: [NWConnection] = []
    private var stopped = false
    private let lock = NSLock()
    private var _contacted = Set<String>(), _blocked = Set<String>()

    var contacted: [String] { lock.lock(); defer { lock.unlock() }; return _contacted.sorted() }
    var blocked: [String] { lock.lock(); defer { lock.unlock() }; return _blocked.sorted() }

    init(allowedHosts: [String], pinnedAddresses: [String: String] = [:]) { hosts = allowedHosts; self.pinnedAddresses = pinnedAddresses }

    func start() throws -> UInt16 {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: .any)
        let l = try NWListener(using: params)
        let sem = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var port: UInt16 = 0
        l.stateUpdateHandler = { st in
            switch st {
            case .ready: port = l.port?.rawValue ?? 0; sem.signal()
            case .failed, .cancelled: sem.signal()
            default: break
            }
        }
        l.newConnectionHandler = { [weak self] c in self?.accept(c) }
        l.start(queue: queue)
        _ = sem.wait(timeout: .now() + 5)
        listener = l
        guard port != 0 else { throw NSError(domain: "lockd.proxy", code: 1) }
        return port
    }

    func stop() {
        listener?.cancel(); listener = nil
        lock.lock(); stopped = true; let active = connections; connections.removeAll(); lock.unlock()
        active.forEach { $0.stateUpdateHandler = nil; $0.cancel() }
    }

    private func accept(_ c: NWConnection) {
        lock.lock()
        if stopped { lock.unlock(); c.cancel(); return }
        connections.append(c); lock.unlock()
        c.start(queue: queue)
        readHead(c, Data())
    }

    private func readHead(_ c: NWConnection, _ buf: Data) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, done, err in
            guard let self else { return }
            var b = buf; if let d = data { b.append(d) }
            if let r = b.range(of: Data("\r\n\r\n".utf8)) {
                self.route(c, head: String(decoding: b[..<r.lowerBound], as: UTF8.self))
            } else if done || err != nil || b.count > 16_384 { c.cancel() }
            else { self.readHead(c, b) }
        }
    }

    private func reply(_ c: NWConnection, _ line: String, then: (() -> Void)? = nil) {
        c.send(content: Data((line + "\r\n\r\n").utf8), completion: .contentProcessed { _ in then?() })
    }

    private func route(_ c: NWConnection, head: String) {
        let first = head.split(separator: "\r\n").first.map(String.init) ?? ""
        let parts = first.split(separator: " ")
        guard parts.count >= 2, parts[0] == "CONNECT" else { return reply(c, "HTTP/1.1 403 Forbidden") { c.cancel() } }
        let target = String(parts[1])
        let hp = target.split(separator: ":", maxSplits: 1).map(String.init)
        let host = (hp.first ?? "").lowercased()
        let port = hp.count > 1 ? Int(hp[1]) ?? 0 : 443
        guard port == 443, Policies.hostMatches(host, hosts) else {
            lock.lock(); _blocked.insert(host); lock.unlock()
            return reply(c, "HTTP/1.1 403 Forbidden") { c.cancel() }
        }
        lock.lock(); _contacted.insert(host); lock.unlock()
        let up = NWConnection(host: NWEndpoint.Host(pinnedAddresses[host] ?? host), port: 443, using: .tcp)
        lock.lock()
        if stopped { lock.unlock(); c.cancel(); up.cancel(); return }
        connections.append(up); lock.unlock()
        up.stateUpdateHandler = { [weak self] st in
            guard let self else { return }
            switch st {
            case .ready:
                self.reply(c, "HTTP/1.1 200 Connection Established") {
                    self.pump(c, up); self.pump(up, c)
                }
            case .failed:
                self.reply(c, "HTTP/1.1 502 Bad Gateway") { c.cancel() }
                up.cancel()
            default: break
            }
        }
        up.start(queue: queue)
    }

    private func pump(_ from: NWConnection, _ to: NWConnection) {
        from.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, done, err in
            if let d = data, !d.isEmpty {
                to.send(content: d, completion: .contentProcessed { e in
                    if e == nil { self?.pump(from, to) } else { from.cancel(); to.cancel() }
                })
            } else if done || err != nil { from.cancel(); to.cancel() }
            else { self?.pump(from, to) }
        }
    }
}
