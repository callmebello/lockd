import AppKit
import SwiftUI
import LockdCore

let app = NSApplication.shared

// Modo de verificação visual: lockd --snapshot DIR  (usa dados de exemplo, nunca toca nos seus)
if let i = CommandLine.arguments.firstIndex(of: "--snapshot"), CommandLine.arguments.indices.contains(i + 1) {
    let dir = CommandLine.arguments[i + 1]
    setenv("LOCKD_HOME", dir + "/home", 1)
    SnapshotMode.run(into: dir)
    exit(0)
}

// Abrir no login sem precisar do app aberto: Lockd --enable-login | --disable-login
if CommandLine.arguments.contains("--enable-login") || CommandLine.arguments.contains("--disable-login") {
    LoginItem.set(CommandLine.arguments.contains("--enable-login"))
    print(LoginItem.enabled ? "login item: enabled" : "login item: disabled")
    exit(0)
}

// Diagnóstico: Lockd --selftest-se  → tenta criar/usar a chave do Secure Enclave e imprime o resultado
if CommandLine.arguments.contains("--selftest-se") {
    do { let c = try Vault.shared.encrypt("selftest", itemID: UUID()); print("SE encrypt OK, ciphertext bytes:", c.count) }
    catch { print("SE encrypt FAILED:", error) }
    exit(0)
}

let delegate = AppDelegate()
app.delegate = delegate
app.run()

enum SnapshotMode {
    static func run(into dir: String) {
        app.setActivationPolicy(.accessory)
        if CommandLine.arguments.contains("--light") { app.appearance = NSAppearance(named: .aqua) }
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

        let store = Store.shared
        func secret(_ d: Detection, _ p: String?, _ src: String) { _ = try? store.saveSecret(d, project: p, source: src) }
        secret(Detection(envName: "ANTHROPIC_API_KEY", service: "Anthropic", type: "API key", value: "sk-ant-api03-DEMO0000000000000001", confident: true), "Priva", "Google Chrome")
        secret(Detection(envName: "GEMINI_API_KEY", service: "Google Gemini", type: "API key", value: "AIzaSyDEMO000000000000000000000000001", confident: true), "Priva", "Google Chrome")
        secret(Detection(envName: "STRIPE_SECRET_KEY", service: "Stripe", type: "Secret key", value: "sk_" + "live_DEMO00000000000000000002", confident: true), "Konvo", "Terminal")
        secret(Detection(envName: "SUPABASE_SERVICE_ROLE_KEY", service: "Supabase", type: "service_role key", value: "eyJDEMO.eyJDEMO.sigDEMO0001", confident: true), "Roll", "Cursor")
        secret(Detection(envName: "OPENAI_API_KEY", service: "OpenAI", type: "API key", value: "sk-proj-DEMO000000000000000000000000003", confident: true), nil, "Safari")

        // Assets de exemplo
        func svgFile(_ name: String, _ c1: String, _ c2: String) -> String {
            let p = dir + "/" + name
            try? "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 100 100\"><defs><linearGradient id=\"g\"><stop offset=\"0\" stop-color=\"\(c1)\"/><stop offset=\"1\" stop-color=\"\(c2)\"/></linearGradient></defs><circle cx=\"50\" cy=\"50\" r=\"42\" fill=\"url(#g)\"/><rect x=\"36\" y=\"36\" width=\"28\" height=\"28\" rx=\"8\" fill=\"#fff\"/></svg>".write(toFile: p, atomically: true, encoding: .utf8)
            return p
        }
        _ = try? Ingestor.ingest(URL(fileURLWithPath: svgFile("priva-logo.svg", "#22D3EE", "#6366F1")), project: "Priva")
        _ = try? Ingestor.ingest(URL(fileURLWithPath: svgFile("priva-icon.svg", "#34D399", "#0EA5E9")), project: "Priva")
        _ = try? Ingestor.ingest(URL(fileURLWithPath: svgFile("konvo-logo.svg", "#F97316", "#EC4899")), project: "Konvo")
        let prov = dir + "/AuthKey_DEMO.p8"
        try? "demo".write(toFile: prov, atomically: true, encoding: .utf8)
        if let it = try? Ingestor.ingest(URL(fileURLWithPath: prov), project: "Priva") {
            store.update(id: it.id) { $0.expiresAt = Calendar.current.date(byAdding: .day, value: 9, to: Date()) }
        }
        secret(Detection(envName: "VERCEL_TOKEN", service: "Vercel", type: "Token", value: "vercel_DEMO000000000000000004", confident: true), "Priva", "Google Chrome")
        Audit.write(AuditEntry(tool: "run", status: "ok", project: "Priva", secrets: ["VERCEL_TOKEN"], command: "vercel env ls"))
        var blocked = AuditEntry(tool: "run", status: "denied", project: "Konvo", secrets: ["STRIPE_SECRET_KEY"], command: "sh -c echo $STRIPE_SECRET_KEY",
                                 detail: "`sh` is never allowed with keys — shells, interpreters and encoders can leak them")
        blocked.date = Date().addingTimeInterval(-3600); Audit.write(blocked)

        func shot(_ name: String, _ view: some View, size: NSSize) {
            let host = NSHostingView(rootView: view)
            let win = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: [.borderless], backing: .buffered, defer: false)
            win.contentView = host
            win.backgroundColor = NSColor(srgbRed: 0.55, green: 0.78, blue: 0.74, alpha: 1)
            win.orderBack(nil)
            host.frame = NSRect(origin: .zero, size: size)
            RunLoop.current.run(until: Date().addingTimeInterval(0.8))
            host.layoutSubtreeIfNeeded()
            guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
            host.cacheDisplay(in: host.bounds, to: rep)
            try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: "\(dir)/\(name).png"))
        }

        shot("home", LibraryView(start: .home), size: NSSize(width: 1200, height: 800))
        shot("project", LibraryView(start: .project("Priva")), size: NSSize(width: 1200, height: 800))
        shot("folder", LibraryView(start: .folder("Priva", "Logos")), size: NSSize(width: 1200, height: 800))
        writeStatusIconPreview(into: dir)
        do {   // projetos de mentira para a revisão da importação (nada do seu disco)
            let code = URL(fileURLWithPath: dir + "/code")
            func write(_ p: String, _ t: String) {
                let u = code.appendingPathComponent(p)
                try? FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
                try? t.write(to: u, atomically: true, encoding: .utf8)
            }
            let logo = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 100 100\"><circle cx=\"50\" cy=\"50\" r=\"42\" fill=\"#F97316\"/></svg>"
            write("devio-scrap/package.json", "{}")
            write("devio-scrap/.env", "SUPABASE_ACCESS_TOKEN=sbp_" + String(repeating: "ab12", count: 10) + "\nSTRIPE_SECRET_KEY=sk_" + "live_DEMO0123456789abcdefghij\nOPENAI_API_KEY=sk-proj-DEMO0123456789abcdefghijklmnopqrstu\nPORT=3000\n")
            write("devio-scrap/public/logo.svg", logo); write("devio-scrap/public/favicon.ico", "ico")
            write("devio-scrap/.vercel/project.json", "{\"projectId\":\"prj_demo123\",\"orgId\":\"team_demo\"}")
            write("kiosk/package.json", "{}"); write("kiosk/.env.local", "GEMINI_API_KEY=AIzaSyDEMO0123456789abcdefghijklmnopqrs\n"); write("kiosk/src/assets/brand-mark.svg", logo)
            let review = ScanModel()
            review.roots = [RootChoice(url: code, on: true)]
            review.projects = ProjectScanner.scan(roots: [code]); review.phase = .review
            shot("import", ImportSheet(model: review) {}, size: NSSize(width: 720, height: 600))
            let choose = ScanModel(); choose.roots = [RootChoice(url: code, on: true), RootChoice(url: URL(fileURLWithPath: NSHomeDirectory() + "/Documents/GitHub"), on: false)]
            shot("import-choose", ImportSheet(model: choose) {}, size: NSSize(width: 720, height: 600))
            shot("welcome", WelcomeSheet(onImport: {}, onClose: {}), size: NSSize(width: 560, height: 560))
            shot("send", VercelSendSheet(project: "Priva") {}, size: NSSize(width: 600, height: 560))
        }
        do {
            let vm = ToastVM(ToastModel(icon: "photo.badge.plus", title: "priva-logo.svg", subtitle: "Looks like logo · you're working on Priva",
                                        actions: [ToastAction(label: "File it", prominent: true) {}], duration: 10, thumbPath: Store.shared.items.first(where: { $0.type == "Logo" })?.path))
            vm.visible = true; vm.hovering = true
            shot("toast", ToastView(vm: vm), size: NSSize(width: 470, height: 130))
        }
        if let k = Store.shared.items.first(where: { $0.kind == .secret }) {
            shot("detail", DetailView(item: k, projects: ["Priva", "Konvo", "Roll"]), size: NSSize(width: 760, height: 1100))
        }
    }
}


/// Ícone da barra de menu: 18 pt a 2x (36 px), ampliado 10x sem suavizar, em barra clara e escura.
func writeStatusIconPreview(into dir: String) {
    func rep(_ w: Int, _ h: Int) -> NSBitmapImageRep {
        NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: w, pixelsHigh: h, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                         isPlanar: false, colorSpaceName: NSColorSpaceName.deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    }
    let px = 36, big = 360
    let small = rep(px, px)
    small.size = NSSize(width: 18, height: 18)
    let ctx1 = NSGraphicsContext(bitmapImageRep: small)!
    NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = ctx1
    StatusIcon.make().draw(in: NSRect(x: 0, y: 0, width: 18, height: 18))
    NSGraphicsContext.restoreGraphicsState()

    let out = rep(big * 2, big)
    let ctx2 = NSGraphicsContext(bitmapImageRep: out)!
    NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = ctx2
    ctx2.imageInterpolation = .none
    for (i, dark) in [false, true].enumerated() {
        let area = NSRect(x: i * big, y: 0, width: big, height: big)
        (dark ? NSColor(white: 0.16, alpha: 1) : NSColor(white: 0.93, alpha: 1)).setFill()
        area.fill()
        let tinted = NSImage(size: NSSize(width: px, height: px))
        tinted.lockFocus()
        small.draw(in: NSRect(x: 0, y: 0, width: px, height: px))
        (dark ? NSColor.white : NSColor.black).set()
        NSRect(x: 0, y: 0, width: px, height: px).fill(using: .sourceIn)
        tinted.unlockFocus()
        tinted.draw(in: area, from: .zero, operation: .sourceOver, fraction: 1)
    }
    NSGraphicsContext.restoreGraphicsState()
    try? out.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: dir + "/statusicon.png"))
}
