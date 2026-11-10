import SwiftUI
import AppKit
import LockdCore

enum QuickFilter: String, CaseIterable, Identifiable {
    case all = "All", keys = "Keys", files = "Files", inbox = "Inbox", expiring = "Expiring"
    var id: String { rawValue }
}

final class QuickModel: ObservableObject {
    @Published var query = ""
    @Published var filter: QuickFilter = .all
    @Published var selection = 0
    @Published var items: [Item] = []
    @Published var focusTick = 0
    var onActivate: ((Item, Bool) -> Void)?
    var onReveal: ((Item) -> Void)?
    var onClose: (() -> Void)?
    var onOpenLibrary: (() -> Void)?

    func reset() { query = ""; filter = .all; selection = 0; refresh(); focusTick += 1 }

    func refresh() {
        let current = ProjectTracker.shared.current().project
        let words = query.lowercased().split(separator: " ").map(String.init)
        let colorTokens = words.filter(ColorMatch.isColorToken), tokens = words.filter { !ColorMatch.isColorToken($0) }
        var list = Store.shared.items.filter { i in
            switch filter {
            case .all: return true
            case .keys: return i.kind == .secret
            case .files: return i.kind != .secret
            case .inbox: return i.project == nil
            case .expiring: return (i.daysUntilExpiry ?? 999) <= 30
            }
        }
        if !words.isEmpty { list = list.filter { i in tokens.allSatisfy { i.haystack.contains($0) } && colorTokens.allSatisfy { ColorMatch.matches(i, token: $0) } } }
        list.sort { a, b in
            let ap = a.project == current && current != nil, bp = b.project == current && current != nil
            if ap != bp { return ap }
            return a.createdAt > b.createdAt
        }
        items = Array(list.prefix(60))
        selection = min(selection, max(items.count - 1, 0))
    }

    func move(_ d: Int) { guard !items.isEmpty else { return }; selection = (selection + d + items.count) % items.count }
    var selected: Item? { items.indices.contains(selection) ? items[selection] : nil }
}

struct QuickPanelView: View {
    @ObservedObject var m: QuickModel
    @FocusState private var focused: Bool
    @State private var appear = false
    @State private var dropTarget = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").font(.system(size: 15, weight: .medium)).foregroundStyle(.secondary)
                TextField("Search keys, logos, projects…", text: $m.query)
                    .textFieldStyle(.plain).font(.system(size: 17)).foregroundStyle(.primary)
                    .focused($focused)
                    .onSubmit { if let s = m.selected { m.onActivate?(s, true) } }
                    .onKeyPress(.downArrow) { m.move(1); return .handled }
                    .onKeyPress(.upArrow) { m.move(-1); return .handled }
                    .onKeyPress(.escape) { m.onClose?(); return .handled }
                    .onKeyPress(.tab) {
                        let all = QuickFilter.allCases
                        m.filter = all[(all.firstIndex(of: m.filter)! + 1) % all.count]; return .handled
                    }
                Button { m.onOpenLibrary?() } label: {
                    Image(systemName: "square.grid.2x2").font(.system(size: 13)).foregroundStyle(Theme.dim)
                }.buttonStyle(.plain).help("Open library")
            }
            .padding(.horizontal, 16).padding(.vertical, 14)

            HStack(spacing: 6) {
                ForEach(QuickFilter.allCases) { f in
                    Button { withAnimation(.snappy(duration: 0.2)) { m.filter = f } } label: {
                        Text(f.rawValue).font(.system(size: 11.5, weight: .semibold))
                            .foregroundStyle(m.filter == f ? Theme.cyan : Theme.dim)
                            .padding(.horizontal, 10).padding(.vertical, 4)
                            .background(m.filter == f ? Theme.cyanSoft : .clear, in: Capsule())
                    }.buttonStyle(.plain)
                }
                Spacer()
                if let p = ProjectTracker.shared.current().project {
                    HStack(spacing: 4) { Circle().fill(Theme.cyan).frame(width: 6, height: 6); Text(p) }
                        .font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.dim)
                }
            }
            .padding(.horizontal, 12).padding(.bottom, 8)

            Divider().overlay(Theme.line)

            if m.items.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "lock.open.trianglebadge.exclamationmark").font(.system(size: 26)).foregroundStyle(Theme.faint)
                    Text(Store.shared.items.isEmpty ? "Nothing here yet" : "No match").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.dim)
                    Text(Store.shared.items.isEmpty ? "Copy an API key, or drop a logo on the menu bar icon." : "Try fewer words.")
                        .font(.system(size: 11.5)).foregroundStyle(Theme.faint)
                }
                .frame(maxWidth: .infinity).frame(height: 190)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 2) {
                            ForEach(Array(m.items.enumerated()), id: \.element.id) { idx, item in
                                ItemRow(item: item, selected: idx == m.selection, showHint: true)
                                    .id(item.id)
                                    .onTapGesture { m.selection = idx; m.onActivate?(item, true) }
                                    .dragFile(item)
                            }
                        }
                        .padding(8)
                    }
                    .frame(height: min(CGFloat(m.items.count) * 52 + 16, 380))
                    .onChange(of: m.selection) { _, s in
                        if m.items.indices.contains(s) { withAnimation(.easeOut(duration: 0.12)) { proxy.scrollTo(m.items[s].id) } }
                    }
                }
            }

            Divider().overlay(Theme.line)
            HStack(spacing: 14) {
                hint("↩", "paste"); hint("⌘C", "copy"); hint("⌘R", "reveal"); hint("⇥", "filter"); hint("esc", "close")
                Spacer()
                Text("\(m.items.count)").font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.faint)
            }
            .padding(.horizontal, 14).padding(.vertical, 8)
        }
        .frame(width: 640)
        .lockdGlass(radius: 28, scrim: 0.5)
        .shadow(color: .black.opacity(0.18), radius: 28, y: 14)
        .padding(30)
        .scaleEffect(appear ? 1 : 0.96).opacity(appear ? 1 : 0).offset(y: appear ? 0 : -8)
        .animation(.spring(response: 0.34, dampingFraction: 0.78), value: appear)
        .onAppear { appear = true; focused = true }
        .onChange(of: m.focusTick) { _, _ in focused = true }
        .onChange(of: m.query) { _, _ in m.selection = 0; m.refresh() }
        .onChange(of: m.filter) { _, _ in m.selection = 0; m.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: Store.didChange)) { _ in m.refresh() }
        .background {
            Group {
                Button("") { if let s = m.selected { m.onActivate?(s, false) } }.keyboardShortcut("c", modifiers: .command)
                Button("") { if let s = m.selected { m.onReveal?(s) } }.keyboardShortcut("r", modifiers: .command)
            }.opacity(0)
        }
        .onDrop(of: [.fileURL], isTargeted: $dropTarget) { providers in
            DropIngest.handle(providers, project: ProjectTracker.shared.current().project); return true
        }
    }

    private func hint(_ k: String, _ t: String) -> some View {
        HStack(spacing: 5) {
            Text(k).font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundStyle(Theme.dim)
                .padding(.horizontal, 5).padding(.vertical, 1.5).background(Theme.raised, in: RoundedRectangle(cornerRadius: 4))
            Text(t).font(.system(size: 11)).foregroundStyle(Theme.faint)
        }
    }
}

final class KeyPanel: NSPanel {
    override var canBecomeKey: Bool { true }
}

final class QuickPanelController: NSObject, NSWindowDelegate {
    let model = QuickModel()
    private var panel: KeyPanel?
    private(set) var previousApp: NSRunningApplication?
    var isVisible: Bool { panel?.isVisible ?? false }

    override init() {
        super.init()
        model.onClose = { [weak self] in self?.hide() }
    }

    func toggle(anchor: NSRect? = nil) { isVisible ? hide() : show(anchor: anchor) }

    func show(anchor: NSRect? = nil) {
        let front = NSWorkspace.shared.frontmostApplication
        if front?.bundleIdentifier != Bundle.main.bundleIdentifier { previousApp = front }

        model.reset()
        let host = NSHostingView(rootView: QuickPanelView(m: model))
        host.frame = NSRect(origin: .zero, size: host.fittingSize)

        let p = panel ?? KeyPanel(contentRect: host.frame, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        p.contentView = host
        p.setContentSize(host.fittingSize)
        p.isOpaque = false; p.backgroundColor = .clear; p.hasShadow = false
        p.level = .floating; p.isFloatingPanel = true; p.hidesOnDeactivate = false
        p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        p.delegate = self

        let screen = NSScreen.screens.first { NSMouseInRect(NSEvent.mouseLocation, $0.frame, false) } ?? NSScreen.main
        if let f = screen?.visibleFrame {
            let s = p.frame.size
            p.setFrameOrigin(NSPoint(x: f.midX - s.width / 2, y: f.maxY - s.height - f.height * 0.12))
        }
        panel = p
        NSApp.activate(ignoringOtherApps: true)
        p.makeKeyAndOrderFront(nil)
    }

    func hide() { panel?.orderOut(nil) }

    func windowDidResignKey(_ notification: Notification) { hide() }
}
