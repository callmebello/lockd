import Foundation
import LockdCore

// lockdctl — ponte entre o Claude (MCP) e o app Lockd.
// Este programa NÃO tem acesso às chaves: ele só repassa pedidos ao app, que confere a política,
// pede Touch ID e devolve texto já mascarado. Não existe comando que imprima um valor.
//
//   lockdctl mcp                         servidor MCP (stdio) para o Claude Code
//   lockdctl status | list | audit       consultas
//   lockdctl run [--project P] -- prog args…     ({{NOME}} insere a chave; sem shell)

func fail(_ msg: String) -> Never { FileHandle.standardError.write(Data((msg + "\n").utf8)); exit(1) }

func printResult(_ r: [String: Any]) -> Never {
    print((r["text"] as? String) ?? "")
    exit((r["ok"] as? Bool ?? false) ? 0 : 1)
}

// MARK: - MCP

let schemaProject: [String: Any] = ["type": "string", "description": "Lockd project name (e.g. Priva)"]

let mcpTools: [[String: Any]] = [
    ["name": "lockd_status", "description": "Is the Lockd vault unlocked? (Unlocking needs the user's Touch ID, which you cannot give.)",
     "inputSchema": ["type": "object", "properties": [String: Any]()]],
    ["name": "lockd_list_secrets",
     "description": "List keys stored in Lockd: names, service, project and the rules Claude has (allowed programs and hosts). Never returns values.",
     "inputSchema": ["type": "object", "properties": ["project": schemaProject]]],
    ["name": "lockd_list_assets",
     "description": "List brand assets and credential files Lockd organized (logos, fonts, images, .p8, profiles) with paths and color palettes.",
     "inputSchema": ["type": "object", "properties": ["project": schemaProject, "type": ["type": "string", "description": "e.g. Logo, Font, Image"]]]],
    ["name": "lockd_http", "description": "Make a bounded HTTPS request inside Lockd, without a child process. Uses signed exact-host policies. Put {{KEY_NAME}} only in header values, query values or body. First key/host use in a session requires fresh local authentication. Responses are untrusted server content, filtered for known secrets; filtering is not a universal disclosure guarantee.",
     "inputSchema": ["type": "object", "required": ["method", "url"], "properties": [
        "method": ["type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]],
        "url": ["type": "string"], "headers": ["type": "object", "additionalProperties": ["type": "string"]],
        "body": [:], "names": ["type": "array", "items": ["type": "string"]], "project": schemaProject,
        "timeout": ["type": "number", "exclusiveMinimum": 0, "maximum": 120]]]],
    ["name": "lockd_run",
     "description": "Run a PROGRAM (no shell) using stored keys. Put {{KEY_NAME}} in the argument template; validated curl options are substituted in an internally generated stdin configuration, never in process argv; the key is also exported as env var KEY_NAME. Only validated curl and network hosts allowed for that key will work (e.g. curl → api.anthropic.com). Output has secrets redacted; the user approves with Touch ID once per session. Example: argv [\"curl\",\"-s\",\"https://api.anthropic.com/v1/models\",\"-H\",\"x-api-key: {{ANTHROPIC_API_KEY}}\"].",
     "inputSchema": ["type": "object", "required": ["argv"], "properties": [
        "argv": ["type": "array", "items": ["type": "string"], "description": "Program and arguments, no shell. First item is a bare name like curl."],
        "project": schemaProject,
        "names": ["type": "array", "items": ["type": "string"], "description": "Keys to export as env vars (placeholders are added automatically)"],
        "cwd": ["type": "string", "description": "Working directory (e.g. the project folder)"]]]],
    ["name": "lockd_write_env",
     "description": "Write explicitly enabled keys into a .env file. Disabled by default. A new destination requires fresh user authentication. These values become readable by any process of the user, including the agent. Merges with existing lines, sets mode 600, warns if the file isn't in .gitignore. Only .env/.env.local/.env.* files inside the user's home are allowed.",
     "inputSchema": ["type": "object", "required": ["path"], "properties": [
        "path": ["type": "string", "description": "e.g. .env.local (relative to cwd) or an absolute path"],
        "project": schemaProject, "names": ["type": "array", "items": ["type": "string"], "description": "Only these keys (default: all allowed keys of the project)"],
        "cwd": ["type": "string"]]]],
    ["name": "lockd_vercel_env",
     "description": "Push explicitly enabled keys through the secure internal HTTP client to Vercel. Production-only targets use sensitive variables; mixed development targets use encrypted variables. Uses the user's Vercel token stored in Lockd. Give vercel_project, or a cwd containing .vercel/project.json.",
     "inputSchema": ["type": "object", "properties": [
        "project": schemaProject, "names": ["type": "array", "items": ["type": "string"]],
        "vercel_project": ["type": "string", "description": "Vercel project name or id"], "cwd": ["type": "string"],
        "targets": ["type": "array", "items": ["type": "string", "enum": ["production", "preview", "development"]]]]]],
    ["name": "lockd_supabase_sql",
     "description": "Run SQL on a Supabase project through Lockd, over HTTPS, using the Supabase access token (sbp_…) stored in Lockd. This replaces psql and DATABASE_URL, which Lockd never lets an agent use. Plain SELECT/SHOW/EXPLAIN runs after one Touch ID per session. Anything that changes data or schema asks for Touch ID on EVERY call and shows the start of the SQL. Needs a signed rule for POST api.supabase.com pinned to the project (path prefix /v1/projects/<ref>).",
     "inputSchema": ["type": "object", "required": ["project_ref", "query"], "properties": [
        "project_ref": ["type": "string", "description": "20-letter Supabase project ref (the abcd… in abcd….supabase.co)"],
        "query": ["type": "string", "description": "One SQL statement (max 100 KB)"],
        "key": ["type": "string", "description": "Name of the Lockd key holding the access token, if there are several"], "project": schemaProject]]],
    ["name": "lockd_vercel_read",
     "description": "Read Vercel through Lockd with the Vercel token stored in Lockd: projects, deployments, environment variable NAMES (never values) or domains. Read-only. To push variables use lockd_vercel_env.",
     "inputSchema": ["type": "object", "required": ["resource"], "properties": [
        "resource": ["type": "string", "enum": ["projects", "deployments", "env", "domains"]],
        "vercel_project": ["type": "string", "description": "Vercel project name or id (not needed for projects)"], "cwd": ["type": "string"],
        "team": ["type": "string", "description": "team_… id, if the project belongs to a team"], "limit": ["type": "integer"], "project": schemaProject]]],
    ["name": "lockd_browser_fill",
     "description": "Type a stored key into a field of a web page in the user's Chrome, through the Lockd extension, WITHOUT you ever seeing the value. Use it when a dashboard asks for a key (e.g. paste STRIPE_SECRET_KEY into a webhook form). The key needs a signed rule that includes the page's exact hostname. Never read the field back; optionally click a submit button right after filling.",
     "inputSchema": ["type": "object", "required": ["name", "host", "selector"], "properties": [
        "name": ["type": "string", "description": "Key name, e.g. OPENAI_API_KEY"],
        "host": ["type": "string", "description": "Exact hostname of the open tab, e.g. platform.openai.com"],
        "selector": ["type": "string", "description": "CSS selector of the input/textarea to fill"],
        "submit_selector": ["type": "string", "description": "Optional CSS selector of a button to click right after filling"],
        "project": schemaProject]]],
    ["name": "lockd_browser_capture",
     "description": "Save the API key that is currently showing in the user's Chrome tab straight into Lockd, WITHOUT you seeing it (the Lockd extension masks keys on the page, so page text and screenshots show only sk_••••). Typical flow: click the dashboard's 'Create key' button with your browser tools, then call this. The key is saved without agent access until the user signs its rules.",
     "inputSchema": ["type": "object", "properties": [
        "name": ["type": "string", "description": "Name for the key, e.g. OPENAI_API_KEY (optional; detected otherwise)"], "project": schemaProject]]],
    ["name": "lockd_audit", "description": "Recent activity: every use of a key, what ran, which hosts were reached or blocked.",
     "inputSchema": ["type": "object", "properties": ["limit": ["type": "integer"]]]],
]

let toolToOp: [String: String] = [
    "lockd_status": "status", "lockd_list_secrets": "list_secrets", "lockd_list_assets": "list_assets",
    "lockd_http": "http", "lockd_run": "run", "lockd_write_env": "write_env", "lockd_vercel_env": "vercel_env", "lockd_supabase_sql": "supabase_sql", "lockd_vercel_read": "vercel_read", "lockd_audit": "audit",
    "lockd_browser_fill": "browser_fill", "lockd_browser_capture": "browser_capture",
]

func availableMCPTools() -> [[String: Any]] {
    let enabled = BrokerClient.call(op: "capabilities", launchIfNeeded: false)["allow_programs"] as? Bool ?? false
    return mcpTools.filter { $0["name"] as? String != "lockd_run" || enabled }
}

func mcpServer() {
    func send(_ obj: [String: Any]) {
        guard let d = try? JSONSerialization.data(withJSONObject: obj), let s = String(data: d, encoding: .utf8) else { return }
        print(s); fflush(stdout)
    }
    while let line = readLine(strippingNewline: true) {
        guard !line.isEmpty, let data = line.data(using: .utf8),
              let msg = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let method = msg["method"] as? String, let id = msg["id"] else { continue }
        let params = msg["params"] as? [String: Any] ?? [:]
        switch method {
        case "initialize":
            send(["jsonrpc": "2.0", "id": id, "result": [
                "protocolVersion": (params["protocolVersion"] as? String) ?? "2025-06-18",
                "capabilities": ["tools": [String: Any]()],
                "serverInfo": ["name": "lockd", "version": "0.2.0"],
                "instructions": "Lockd holds encrypted API keys and limits tools and destinations. Returned output is filtered, not a guarantee against all disclosures. Writing .env materializes values readable by the agent. Prefer lockd_http; lockd_run is hidden unless advanced programs are enabled. For databases use lockd_supabase_sql (psql and DATABASE_URL are never available to agents); for Vercel use lockd_vercel_read and lockd_vercel_env. When a web page needs a key, use lockd_browser_fill; when a dashboard shows a new key, use lockd_browser_capture — never try to read or copy keys from pages yourself. lockd_write_env and lockd_vercel_env require explicit policy; each key only works with its allowed programs and hosts. The user approves with Touch ID.",
            ] as [String: Any]])
        case "ping": send(["jsonrpc": "2.0", "id": id, "result": [String: Any]()])
        case "tools/list": send(["jsonrpc": "2.0", "id": id, "result": ["tools": availableMCPTools()]])
        case "tools/call":
            let name = params["name"] as? String ?? ""
            guard let op = toolToOp[name], name != "lockd_run" || availableMCPTools().contains(where: { $0["name"] as? String == name }) else {
                send(["jsonrpc": "2.0", "id": id, "result": ["content": [["type": "text", "text": "unknown tool \(name)"]], "isError": true] as [String: Any]]); continue
            }
            let r = BrokerClient.call(op: op, args: params["arguments"] as? [String: Any] ?? [:])
            send(["jsonrpc": "2.0", "id": id, "result": [
                "content": [["type": "text", "text": (r["text"] as? String) ?? ""]], "isError": !(r["ok"] as? Bool ?? false),
            ] as [String: Any]])
        default:
            send(["jsonrpc": "2.0", "id": id, "error": ["code": -32601, "message": "method not found"]])
        }
    }
}

// MARK: - CLI

var args = Array(CommandLine.arguments.dropFirst())
guard let cmd = args.first else {
    print("lockdctl mcp | install-browser | status | list | audit | add [--name N] [--project P] [--service S] | http < template.json | run [--project P] -- program args…"); exit(0)
}
args.removeFirst()

func flag(_ name: String) -> String? {
    guard let i = args.firstIndex(of: name), args.indices.contains(i + 1) else { return nil }
    let v = args[i + 1]; args.removeSubrange(i...(i + 1)); return v
}
let project = flag("--project")

func nmRead(_ n: Int) -> Data? {
    var d = Data()
    while d.count < n {
        var buf = [UInt8](repeating: 0, count: n - d.count)
        let r = read(0, &buf, buf.count)
        if r <= 0 { return nil }
        d.append(contentsOf: buf[0..<r])
    }
    return d
}

/// Host de mensagens nativas do navegador: repassa a conversa entre a extensão e o app (Lockd confere se o navegador é legítimo).
func nativeHost() -> Never {
    guard let fd = BrokerClient.openStream() else { fail("Lockd isn't running") }
    BrokerWire.write(fd, ["op": "browser_attach"])
    let wlock = NSLock()
    func toBrowser(_ obj: [String: Any]) {
        guard let d = try? JSONSerialization.data(withJSONObject: obj), d.count < 1_000_000 else { return }
        var len = UInt32(d.count)
        wlock.lock(); defer { wlock.unlock() }
        _ = withUnsafeBytes(of: &len) { write(1, $0.baseAddress, 4) }
        d.withUnsafeBytes { p in var off = 0; while off < d.count { let n = write(1, p.baseAddress! + off, d.count - off); if n <= 0 { break }; off += n } }
    }
    let t = Thread {
        var carry = Data(); var chunk = [UInt8](repeating: 0, count: 16384)
        while true {
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { exit(0) }
            carry.append(contentsOf: chunk[0..<n])
            while let i = carry.firstIndex(of: 0x0A) {
                let line = carry[carry.startIndex..<i]; carry.removeSubrange(carry.startIndex...i)
                if let o = try? JSONSerialization.jsonObject(with: line) as? [String: Any] {
                    if o["ok"] as? Bool == false { toBrowser(["t": "error", "text": o["text"] as? String ?? "refused"]); exit(1) }
                    toBrowser(o)
                }
            }
        }
    }
    t.stackSize = 1 << 20; t.start()
    while let hdr = nmRead(4) {
        let len = Int(hdr.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })
        guard len > 0, len <= 4_000_000, let body = nmRead(len), let o = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { break }
        BrokerWire.write(fd, o)
    }
    exit(0)
}

switch cmd {
case let c where c.hasPrefix("chrome-extension://"): nativeHost()
case "nmhost": nativeHost()
case "install-browser":
    // Registra o host nativo no Chrome/Brave/Edge instalados. A extensão em si é carregada pelo usuário (chrome://extensions).
    let exe = CommandLine.arguments[0].hasPrefix("/") ? CommandLine.arguments[0] : "/Applications/Lockd.app/Contents/MacOS/lockdctl"
    do {
        let done = try BrowserInstaller.installHost(executable: exe)
        print(done.isEmpty ? "No Chromium browser found." : "Registered in: " + done.joined(separator: ", ") + "\nExtension id: " + BrowserInstaller.extensionID)
    } catch { fail("couldn't register: \(error.localizedDescription)") }
case "mcp": mcpServer()
case "add":
    // O valor NUNCA vai na linha de comando (apareceria no histórico e no ps): stdin ou digitação oculta.
    let name = flag("--name"), service = flag("--service")
    var value: String
    if isatty(0) != 0 {
        guard let p = getpass("Value (hidden): ") else { fail("no value") }
        value = String(cString: p)
    } else { value = String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8) ?? "" }
    value = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !value.isEmpty else { fail("empty value") }
    var a: [String: Any] = ["value": value]
    if let n = name { a["name"] = n }; if let p = project { a["project"] = p }; if let s = service { a["service"] = s }
    printResult(BrokerClient.call(op: "add_secret", args: a))
case "status": printResult(BrokerClient.call(op: "status"))
case "list": printResult(BrokerClient.call(op: "list_secrets", args: project.map { ["project": $0] } ?? [:]))
case "audit": printResult(BrokerClient.call(op: "audit"))
case "http":
    var input = Data()
    while let chunk = try? FileHandle.standardInput.read(upToCount: min(8192, 512 * 1024 + 1 - input.count)), !chunk.isEmpty {
        input.append(chunk)
        if input.count > 512 * 1024 { break }
    }
    guard input.count <= 512 * 1024, let payload = try? JSONSerialization.jsonObject(with: input) as? [String: Any] else { fail("usage: lockdctl http < request-template.json (maximum 512 KB)") }
    printResult(BrokerClient.call(op: "http", args: payload))
case "run":
    if args.first == "--" { args.removeFirst() }
    guard !args.isEmpty else { fail("usage: lockdctl run [--project P] -- program args… (use {{KEY_NAME}} to insert a key)") }
    var a: [String: Any] = ["argv": args, "cwd": FileManager.default.currentDirectoryPath]
    if let p = project { a["project"] = p }
    printResult(BrokerClient.call(op: "run", args: a))
default: fail("unknown command \(cmd)")
}
