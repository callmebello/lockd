import AppKit
import SwiftUI
import Carbon
import LockdCore

/// Cobre o botão da barra de menu: aceita arquivos soltos e repassa os cliques.
final class StatusDropView: NSView {
    var onClick: (() -> Void)?
    var onRightClick: (() -> Void)?
    var onDrop: (([URL]) -> Void)?
    var onHoverDrag: ((Bool) -> Void)?

    override init(frame: NSRect) { super.init(frame: frame); registerForDraggedTypes([.fileURL]) }
    required init?(coder: NSCoder) { fatalError() }

    override func mouseDown(with event: NSEvent) {
        if event.modifierFlags.contains(.control) { onRightClick?() } else { onClick?() }
    }
    override func rightMouseDown(with event: NSEvent) { onRightClick?() }

    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation { onHoverDrag?(true); return .copy }
    override func draggingExited(_ sender: NSDraggingInfo?) { onHoverDrag?(false) }
    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        onHoverDrag?(false)
        let urls = sender.draggingPasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        guard !urls.isEmpty else { return false }
        onDrop?(urls)
        return true
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    nonisolated(unsafe) static var shared: AppDelegate?

    private var statusItem: NSStatusItem!
    private let clipboard = ClipboardWatcher()
    private let folders = FolderWatcher()
    private let quick = QuickPanelController()
    private var hotKey: HotKey?
    private var saveHotKey: HotKey?
    private var library: NSWindow?
    let broker = Broker()
    private var server: BrokerServer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        AppDelegate.shared = self
        NSApp.setActivationPolicy(.accessory)
        buildMainMenu()
        buildStatusItem()

        Clip.watcher = clipboard
        clipboard.onDetect = { dets, src in Flows.handleSecrets(dets, source: src) }
        clipboard.start()

        folders.onFile = { Flows.handleWatchedFile($0) }
        folders.restart()

        ProjectTracker.shared.start()
        Notifier.setup()
        startBroker()
        Flows.onSaved = { [weak self] in self?.pulseIcon() }

        quick.model.onActivate = { [weak self] item, paste in self?.activate(item, paste: paste) }
        quick.model.onReveal = { item in
            if let u = item.fileURL { NSWorkspace.shared.activateFileViewerSelecting([u]) } else { AppDelegate.shared?.openLibrary() }
        }
        quick.model.onOpenLibrary = { [weak self] in self?.quick.hide(); self?.openLibrary() }

        // ⌥⌘L
        hotKey = HotKey(keyCode: UInt32(kVK_ANSI_L), modifiers: UInt32(cmdKey | optionKey)) { [weak self] in
            DispatchQueue.main.async { self?.quick.toggle() }
        }

        saveHotKey = HotKey(keyCode: UInt32(kVK_ANSI_S), modifiers: UInt32(cmdKey | optionKey)) { [weak self] in
            DispatchQueue.main.async { self?.saveSelection() }
        }
        ProjectTracker.shared.onProjectChange = { Suggestions.projectChanged($0) }

        if !AXIsProcessTrusted(), !Prefs.askedAccessibility {
            Prefs.askedAccessibility = true
            AXIsProcessTrustedWithOptions([kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary)
        }

        // Aberto à mão (Applications/Spotlight) mostra a biblioteca; no login fica quieto na barra de menu.
        let event = NSAppleEventManager.shared().currentAppleEvent
        let atLogin = event?.paramDescriptor(forKeyword: AEKeyword(keyAEPropData))?.enumCodeValue == OSType(keyAELaunchedAsLogInItem)
        if !atLogin { DispatchQueue.main.async { self.openLibrary() } }

        if Store.shared.items.isEmpty {
            ToastController.shared.show(ToastModel(
                icon: "lock.shield.fill", title: "Lockd is running",
                subtitle: "Copy an API key — it saves itself.  ⌥⌘L to search.", duration: 7))
        }
    }

    func restartWatchers() { folders.restart() }

    // MARK: Claude → Lockd (broker)

    private func startBroker() {
        Vault.shared.sessionSeconds = Double(Prefs.sessionMinutes) * 60
        broker.onAudit = { e in
            DispatchQueue.main.async {
                let who = e.secrets.prefix(2).joined(separator: ", ")
                switch e.status {
                case "ok":
                    ToastController.shared.show(ToastModel(icon: "key.fill", title: "Claude used \(who)",
                                                           subtitle: e.command ?? e.tool, duration: 3.5))
                case "denied":
                    ToastController.shared.show(ToastModel(icon: "hand.raised.fill", title: "Claude was blocked",
                                                           subtitle: e.detail ?? e.tool, tint: Theme.amber, duration: 5))
                default: break
                }
            }
        }
        broker.currentProject = { DispatchQueue.main.sync { ProjectTracker.shared.lastProject } }
        server = BrokerServer(broker: broker)
        do { try server?.start() } catch { NSLog("[lockd] broker socket failed: %@", error.localizedDescription) }

        // cria a chave do Secure Enclave já na abertura (e de novo ao desbloquear, se estava bloqueado)
        DispatchQueue.global().async { Vault.shared.prepare() }
        // trava o cofre ao bloquear a tela / dormir
        let dn = DistributedNotificationCenter.default()
        dn.addObserver(forName: .init("com.apple.screenIsUnlocked"), object: nil, queue: .main) { _ in
            DispatchQueue.global().async { Vault.shared.prepare() }
        }
        dn.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in Vault.shared.lockNow() }
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { _ in Vault.shared.lockNow() }
    }

    /// Clicar no app em Applications/Dock (com ele já rodando) abre a biblioteca.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openLibrary()
        return true
    }

    // MARK: Barra de menu

    private func buildStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        guard let button = statusItem.button else { return }
        button.image = icon(filled: false)
        button.image?.isTemplate = true
        button.toolTip = "Lockd — ⌥⌘L"

        let drop = StatusDropView(frame: button.bounds)
        drop.autoresizingMask = [.width, .height]
        drop.onClick = { [weak self] in self?.quick.toggle() }
        drop.onRightClick = { [weak self] in self?.showMenu() }
        drop.onHoverDrag = { [weak self] on in self?.statusItem.button?.alphaValue = on ? 0.55 : 1 }
        drop.onDrop = { urls in
            Flows.ingestDropped(urls, project: ProjectTracker.shared.current().project)
        }
        button.addSubview(drop)
    }

    /// Símbolo da marca na barra de menu: disco com o L vazado (template).
    private func icon(filled: Bool) -> NSImage? { StatusIcon.make() }

    /// Pulsada discreta quando algo é guardado.
    private func pulseIcon() {
        guard let b = statusItem.button else { return }
        b.wantsLayer = true
        let a = CASpringAnimation(keyPath: "transform.scale")
        a.fromValue = 1.35; a.toValue = 1; a.mass = 0.8; a.stiffness = 220; a.damping = 9; a.duration = a.settlingDuration
        b.layer?.add(a, forKey: "pulse")
    }

    private func showMenu() {
        let menu = NSMenu()
        menu.addItem(withTitle: "Search…  ⌥⌘L", action: #selector(menuSearch), keyEquivalent: "").target = self
        menu.addItem(withTitle: "Open library", action: #selector(menuLibrary), keyEquivalent: "").target = self
        menu.addItem(withTitle: "Save selection  ⌥⌘S", action: #selector(menuSaveSelection), keyEquivalent: "").target = self
        menu.addItem(withTitle: "Import from your projects…", action: #selector(menuImport), keyEquivalent: "").target = self
        menu.addItem(.separator())

        let proj = NSMenuItem(title: "Current project: \(Prefs.pinnedProject ?? "auto")", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        let auto = NSMenuItem(title: "Auto-detect from window", action: #selector(pickProject(_:)), keyEquivalent: "")
        auto.target = self; auto.state = Prefs.pinnedProject == nil ? .on : .off; sub.addItem(auto)
        sub.addItem(.separator())
        for p in Store.shared.knownProjects() {
            let it = NSMenuItem(title: p, action: #selector(pickProject(_:)), keyEquivalent: "")
            it.target = self; it.representedObject = p; it.state = Prefs.pinnedProject == p ? .on : .off
            sub.addItem(it)
        }
        proj.submenu = sub
        menu.addItem(proj)

        let vaultItem = NSMenuItem(title: Vault.shared.isUnlocked ? "Vault unlocked · \(Int(Vault.shared.unlockedRemaining / 60)) min — Lock now" : "Vault locked (Touch ID on first use)",
                                   action: Vault.shared.isUnlocked ? #selector(lockVault) : nil, keyEquivalent: "")
        vaultItem.target = self; menu.addItem(vaultItem)
        let pause = NSMenuItem(title: Prefs.paused ? "Resume capture" : "Pause capture", action: #selector(togglePause), keyEquivalent: "")
        pause.target = self; menu.addItem(pause)
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit Lockd", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        statusItem.menu = menu
        statusItem.button?.performClick(nil)
        statusItem.menu = nil
    }

    @objc private func menuSearch() { quick.show() }
    @objc private func menuLibrary() { openLibrary() }
    @objc private func menuSaveSelection() { saveSelection() }
    @objc private func menuImport() { openLibrary(startImport: true) }

    /// ⌥⌘S: copia a seleção do app da frente e guarda. Reconhecida → salva sozinha; senão abre "Add secret" já preenchido.
    private func saveSelection() {
        guard AXIsProcessTrusted() else {
            ToastController.shared.show(ToastModel(icon: "hand.raised.fill", title: "Allow Accessibility first",
                                                   subtitle: "System Settings → Privacy & Security → Accessibility → Lockd", tint: Theme.amber, duration: 6))
            return
        }
        let pb = NSPasteboard.general, before = pb.changeCount
        let src = CGEventSource(stateID: .combinedSessionState)
        for down in [true, false] {
            let e = CGEvent(keyboardEventSource: src, virtualKey: 8, keyDown: down)
            e?.flags = .maskCommand; e?.post(tap: .cgAnnotatedSessionEventTap)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { [weak self] in
            guard pb.changeCount != before, let text = pb.string(forType: .string), !text.isEmpty else {
                ToastController.shared.show(ToastModel(icon: "text.cursor", title: "Nothing selected", subtitle: "Select the key first, then press ⌥⌘S", duration: 3)); return
            }
            Clip.watcher?.ignoreCount = pb.changeCount          // este caminho já trata a captura; o monitor não duplica
            let found = Detector.detect(in: text)
            if found.isEmpty { self?.openLibrary(addSecret: text) }
            else { Flows.handleSecrets(found, source: ProjectTracker.shared.current().app) }
        }
    }
    @objc private func lockVault() { Vault.shared.lockNow() }
    @objc private func togglePause() { Prefs.paused.toggle() }
    @objc private func pickProject(_ s: NSMenuItem) { Prefs.pinnedProject = s.representedObject as? String }

    // MARK: Ações

    private func activate(_ item: Item, paste: Bool) {
        quick.hide()
        let target = quick.previousApp
        if item.kind == .secret {
            Unlock.value(of: item, reason: "Use \(item.name) from Lockd") { [weak self] v in
                guard let v else { return }
                Clip.setSecret(v)
                self?.finishActivate(item, paste: paste, target: target)
            }
            return
        }
        if let u = item.fileURL { Clip.setFile(u) }
        finishActivate(item, paste: paste, target: target)
    }

    private func finishActivate(_ item: Item, paste: Bool, target: NSRunningApplication?) {
        if paste {
            if !Clip.paste(into: target) {
                ToastController.shared.show(ToastModel(icon: "doc.on.clipboard.fill", title: "Copied \(item.name)",
                                                       subtitle: "Press ⌘V — grant Accessibility to auto-paste", duration: 3.5))
            }
        } else {
            ToastController.shared.show(ToastModel(icon: "doc.on.clipboard.fill", title: "Copied \(item.name)",
                                                   subtitle: item.kind == .secret ? "Clears in \(Prefs.clearSeconds)s" : "", duration: 2))
        }
    }

    func openLibrary(importProject: String? = nil, addSecret: String? = nil, startImport: Bool = false) {
        if library == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1160, height: 720),
                             styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
            w.titlebarAppearsTransparent = true
            w.titleVisibility = .hidden
            w.isReleasedWhenClosed = false
            w.backgroundColor = NSColor(name: nil) { $0.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? NSColor(srgbRed: 0.149, green: 0.149, blue: 0.141, alpha: 1) : NSColor(srgbRed: 0.961, green: 0.973, blue: 0.969, alpha: 1) }
            w.contentView = NSHostingView(rootView: LibraryView())
            w.center()
            w.setFrameAutosaveName("LockdLibrary")
            library = w
        }
        NSApp.activate(ignoringOtherApps: true)
        library?.makeKeyAndOrderFront(nil)
        if importProject != nil || addSecret != nil || startImport {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
                if let v = addSecret { NotificationCenter.default.post(name: .lockdAddSecret, object: nil, userInfo: ["value": v]) }
                else { NotificationCenter.default.post(name: .lockdImport, object: nil, userInfo: importProject.map { ["project": $0] } ?? [:]) }
            }
        }
    }

    // MARK: Menu principal (necessário p/ ⌘C ⌘V em app de barra de menu)

    private func buildMainMenu() {
        let main = NSMenu()
        let app = NSMenuItem(); main.addItem(app)
        let appMenu = NSMenu(); app.submenu = appMenu
        appMenu.addItem(withTitle: "Quit Lockd", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        let edit = NSMenuItem(); main.addItem(edit)
        let e = NSMenu(title: "Edit"); edit.submenu = e
        e.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        e.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        e.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        e.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        e.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")

        let win = NSMenuItem(); main.addItem(win)
        let w = NSMenu(title: "Window"); win.submenu = w
        w.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        NSApp.mainMenu = main
    }
}
