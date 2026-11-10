import SwiftUI
import AppKit
import LockdCore

enum Route: Hashable {
    case home, activity, settings, inbox, expiring
    case project(String)
    case folder(String, String)      // projeto, categoria
}

final class LibraryModel: ObservableObject {
    @Published var route: Route = .home
    @Published var query = ""
    @Published var selected: UUID?
    @Published var selection: Set<UUID> = []
    @Published var showImport = false
    @Published var importPreload: ScannedProject?
    @Published var sendProject: String?
    @Published var showWelcome = false
    @Published var addInitial: String?
    private var anchor: UUID?
    @Published var all: [Item] = []
    @Published var items: [Item] = []
    @Published var projects: [String] = []
    @Published var expanded: Set<String> = []
    @Published var showAdd = false
    @Published var newProject = ""
    @Published var addingProject = false

    init(route: Route = .home) { self.route = route; refresh() }

    var currentProject: String? {
        switch route { case .project(let p), .folder(let p, _): return p; default: return nil }
    }

    func go(_ r: Route) {
        query = ""; selected = nil; selection = []; anchor = nil
        withAnimation(.snappy(duration: 0.2)) { route = r }
        switch r { case .project(let p), .folder(let p, _): expanded.insert(p); default: break }
        refresh()
    }

    func refresh() {
        all = Store.shared.items
        var set = Set(all.compactMap(\.project)); Store.shared.userProjects.forEach { set.insert($0) }
        projects = set.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
        let words = query.lowercased().split(separator: " ").map(String.init)
        let colorTokens = words.filter(ColorMatch.isColorToken), tokens = words.filter { !ColorMatch.isColorToken($0) }
        var base: [Item]
        if !words.isEmpty { base = all }
        else {
            switch route {
            case .inbox: base = all.filter { $0.project == nil }
            case .expiring: base = all.filter { $0.expiresAt != nil }
            case .folder(let p, let c): base = all.filter { $0.project == p && $0.category == c }
            default: base = []
            }
        }
        items = base.filter { i in tokens.allSatisfy { i.haystack.contains($0) } && colorTokens.allSatisfy { ColorMatch.matches(i, token: $0) } }
            .sorted { route == .expiring && words.isEmpty ? ($0.expiresAt ?? .distantFuture) < ($1.expiresAt ?? .distantFuture) : $0.createdAt > $1.createdAt }
        if let s = selected, !items.contains(where: { $0.id == s }) { selected = nil }
        selection = selection.filter { id in items.contains { $0.id == id } }
    }

    /// Clique com ⌘ alterna, com ⇧ seleciona o intervalo, sem tecla seleciona só aquele.
    func select(_ id: UUID, flags: NSEvent.ModifierFlags) {
        if flags.contains(.command) {
            if selection.contains(id) { selection.remove(id) } else { selection.insert(id) }
            anchor = id
        } else if flags.contains(.shift), let a = anchor, let i = items.firstIndex(where: { $0.id == a }), let j = items.firstIndex(where: { $0.id == id }) {
            selection = Set(items[min(i, j)...max(i, j)].map(\.id))
        } else { selection = [id]; anchor = id }
        selected = selection.count == 1 ? selection.first : nil
    }

    func move(_ delta: Int) {
        guard !items.isEmpty else { return }
        let cur = (selected ?? anchor).flatMap { id in items.firstIndex { $0.id == id } }
        let next = min(max((cur ?? (delta > 0 ? -1 : items.count)) + delta, 0), items.count - 1)
        select(items[next].id, flags: [])
    }

    func selectAll() { selection = Set(items.map(\.id)); selected = selection.count == 1 ? selection.first : nil }

    func items(in project: String?) -> [Item] { all.filter { $0.project == project } }

    func categories(of project: String) -> [(name: String, items: [Item])] {
        let mine = items(in: project)
        return Categories.order.compactMap { c in
            let xs = mine.filter { $0.category == c }
            return xs.isEmpty ? nil : (c, xs)
        }
    }

    var expiringCount: Int { all.filter { ($0.daysUntilExpiry ?? 999) <= 30 }.count }
}

struct LibraryView: View {
    @StateObject private var m: LibraryModel
    @State private var dropTarget = false
    @FocusState private var searchFocused: Bool
    @Namespace private var selNS

    private var contentKey: String { m.query.isEmpty ? "\(m.route)" : "search" }

    init(start: Route = .home) { _m = StateObject(wrappedValue: LibraryModel(route: start)) }

    var body: some View {
        HStack(spacing: 0) {
            sidebar.frame(width: 252)
            Rectangle().fill(Theme.line).frame(width: 1)
            VStack(spacing: 0) {
                topBar
                Divider().overlay(Theme.line)
                content
                    .id(contentKey)
                    .transition(.asymmetric(insertion: .opacity.combined(with: .offset(y: 10)), removal: .opacity))
            }
            .animation(.smooth(duration: 0.3), value: contentKey)
            .frame(maxWidth: .infinity).background(Theme.bg)
        }
        .background(Theme.bg)
        .overlay {
            if dropTarget {
                RoundedRectangle(cornerRadius: 14).stroke(Theme.cyan, style: .init(lineWidth: 2, dash: [8, 6])).padding(10)
                    .background(Theme.cyan.opacity(0.05)).allowsHitTesting(false)
            }
        }
        .onDrop(of: [.fileURL], isTargeted: $dropTarget) { providers in
            DropIngest.handle(providers, project: m.currentProject ?? ProjectTracker.shared.current().project); return true
        }
        .onChange(of: m.query) { _, _ in m.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: Store.didChange)) { _ in m.refresh() }
        .sheet(isPresented: $m.showAdd, onDismiss: { m.addInitial = nil }) { AddSecretSheet(project: m.currentProject, initial: m.addInitial) }
        .sheet(isPresented: $m.showImport) { ImportSheet(model: ScanModel(preloaded: m.importPreload)) { m.showImport = false; m.importPreload = nil; m.refresh() } }
        .sheet(isPresented: Binding(get: { m.sendProject != nil }, set: { if !$0 { m.sendProject = nil } })) {
            if let p = m.sendProject { VercelSendSheet(project: p) { m.sendProject = nil } }
        }
        .sheet(isPresented: $m.showWelcome) {
            WelcomeSheet(onImport: { Prefs.welcomed = true; m.showWelcome = false; DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { m.importPreload = nil; m.showImport = true } },
                         onClose: { Prefs.welcomed = true; m.showWelcome = false })
        }
        .onReceive(NotificationCenter.default.publisher(for: .lockdImport)) { n in
            if let name = n.userInfo?["project"] as? String, let link = Store.shared.link(for: name), !link.path.isEmpty {
                m.importPreload = ProjectScanner.scanProject(at: URL(fileURLWithPath: link.path), name: name)
            } else { m.importPreload = nil }
            m.showImport = true
        }
        .onReceive(NotificationCenter.default.publisher(for: .lockdAddSecret)) { n in m.addInitial = n.userInfo?["value"] as? String; m.showAdd = true }
        .onAppear {
            if !Prefs.welcomed { if Store.shared.items.isEmpty { m.showWelcome = true } else { Prefs.welcomed = true } }
        }
        .background { Button("") { searchFocused = true }.keyboardShortcut("k", modifiers: .command).opacity(0) }
        .frame(minWidth: 1060, minHeight: 680)
    }

    // MARK: Barra superior com caminho

    private var crumbs: [(String, Route?)] {
        if !m.query.isEmpty { return [("Home", .home), ("Search", nil)] }
        switch m.route {
        case .home: return [("Home", nil)]
        case .activity: return [("Home", .home), ("Activity", nil)]
        case .settings: return [("Home", .home), ("Settings", nil)]
        case .inbox: return [("Home", .home), ("Inbox", nil)]
        case .expiring: return [("Home", .home), ("Expiring", nil)]
        case .project(let p): return [("Home", .home), (p, nil)]
        case .folder(let p, let c): return [("Home", .home), (p, .project(p)), (c, nil)]
        }
    }

    private var topBar: some View {
        HStack(spacing: 8) {
            ForEach(Array(crumbs.enumerated()), id: \.offset) { i, c in
                if i > 0 { Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(Theme.faint) }
                if let r = c.1 {
                    Button(c.0) { m.go(r) }.buttonStyle(.plain).foregroundStyle(Theme.dim)
                } else {
                    Text(c.0).foregroundStyle(Theme.text).fontWeight(.medium)
                }
            }
            .font(.system(size: 15))
            Spacer()
            Button { m.showAdd = true } label: { Label("Add secret", systemImage: "plus") }
                .buttonStyle(PressStyle(prominent: true))
        }
        .padding(.horizontal, 28).frame(height: 58)
    }

    // MARK: Conteúdo

    @ViewBuilder private var content: some View {
        if !m.query.isEmpty { splitList }
        else {
            switch m.route {
            case .home: HomeView(m: m)
            case .activity: ActivityView()
            case .settings: SettingsView()
            case .project(let p): ProjectView(m: m, project: p)
            case .inbox, .expiring, .folder: splitList
            }
        }
    }

    private var splitList: some View {
        HStack(spacing: 0) {
            list.frame(width: 380)
            Rectangle().fill(Theme.line).frame(width: 1)
            detail.frame(maxWidth: .infinity)
        }
    }

    private var list: some View {
        Group {
            if m.items.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "tray").font(.system(size: 28)).foregroundStyle(Theme.faint)
                    Text(m.query.isEmpty ? "Nothing here" : "No match").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.dim)
                    Text("Copy a key or drop files on this window.").font(.system(size: 11.5)).foregroundStyle(Theme.faint)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 2) {
                        ForEach(m.items) { it in
                            ItemRow(item: it, selected: m.selection.contains(it.id))
                                .onTapGesture { m.select(it.id, flags: NSEvent.modifierFlags) }
                                .dragFile(it)
                        }
                    }.padding(8)
                }
                .focusable()
                .onKeyPress(.downArrow) { m.move(1); return .handled }
                .onKeyPress(.upArrow) { m.move(-1); return .handled }
                .onKeyPress(.escape) { m.selection = []; m.selected = nil; return .handled }
                .onKeyPress("a", phases: .down) { p in if p.modifiers.contains(.command) { m.selectAll(); return .handled }; return .ignored }
            }
        }
        .background(Theme.bg)
    }

    @ViewBuilder private var detail: some View {
        if m.selection.count > 1 {
            BulkView(ids: m.selection, projects: m.projects)
        } else if let id = m.selected, let it = Store.shared.item(id: id) {
            DetailView(item: it, projects: m.projects).id(it.id)
        } else {
            VStack(spacing: 10) {
                Image(systemName: "lock.shield").font(.system(size: 34)).foregroundStyle(Theme.faint)
                Text("Select something").font(.system(size: 13)).foregroundStyle(Theme.faint)
                Text("⌥⌘L from anywhere to search and paste").font(.system(size: 11.5)).foregroundStyle(Theme.faint.opacity(0.8))
            }.frame(maxWidth: .infinity, maxHeight: .infinity).background(Theme.bg)
        }
    }

    // MARK: Sidebar em árvore

    private var vaultText: String { Vault.shared.isUnlocked ? "Vault unlocked" : "Vault locked" }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 11) {
                AppIconTile(size: 40)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Lockd").font(.system(size: 18, weight: .semibold)).tracking(-0.4).foregroundStyle(Theme.text)
                    HStack(spacing: 5) {
                        Image(systemName: Vault.shared.isUnlocked ? "lock.open.fill" : "lock.fill").font(.system(size: 9))
                        Text(vaultText).font(.system(size: 11.5))
                    }.foregroundStyle(Theme.dim)
                }
                Spacer()
            }
            .padding(.horizontal, 16).padding(.top, 40).padding(.bottom, 14)

            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").font(.system(size: 13)).foregroundStyle(Theme.dim)
                TextField("Search", text: $m.query).textFieldStyle(.plain).font(.system(size: 14)).focused($searchFocused)
                Text("⌘K").font(.system(size: 10.5, weight: .medium)).foregroundStyle(Theme.faint)
                    .padding(.horizontal, 6).padding(.vertical, 2).background(Theme.raised, in: RoundedRectangle(cornerRadius: 5))
            }
            .padding(.horizontal, 12).padding(.vertical, 9)
            .background(Theme.raised.opacity(0.7), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(Theme.line))
            .padding(.horizontal, 12).padding(.bottom, 12)

            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    navRow("Home", "house.fill", .home, 0)
                    navRow("Activity", "waveform.path.ecg", .activity, 0)
                    navRow("Expiring", "clock.badge.exclamationmark.fill", .expiring, m.expiringCount, amber: true)
                    navRow("Inbox", "tray.fill", .inbox, m.items(in: nil).count)

                    HStack {
                        Text("PROJECTS").font(.system(size: 10.5, weight: .bold)).tracking(0.8).foregroundStyle(Theme.faint)
                        Spacer()
                        Button { m.addingProject = true } label: { Image(systemName: "plus").font(.system(size: 11, weight: .bold)) }
                            .buttonStyle(.plain).foregroundStyle(Theme.dim)
                    }
                    .padding(.horizontal, 14).padding(.top, 20).padding(.bottom, 6)

                    if m.addingProject {
                        TextField("Project name", text: $m.newProject)
                            .textFieldStyle(.plain).font(.system(size: 12.5)).padding(8)
                            .background(Theme.raised, in: RoundedRectangle(cornerRadius: 8)).padding(.horizontal, 10)
                            .onSubmit {
                                let n = m.newProject.trimmingCharacters(in: .whitespaces)
                                if !n.isEmpty { Store.shared.addProject(n); m.go(.project(n)) }
                                m.newProject = ""; m.addingProject = false
                            }
                    }
                    ForEach(m.projects, id: \.self) { projectRow($0) }
                }
                .padding(.horizontal, 8)
            }
            Spacer(minLength: 0)
            navRow("Settings", "gearshape.fill", .settings, 0).padding(.horizontal, 8).padding(.bottom, 12)
        }
        .background(Theme.panel.opacity(0.9))
    }

    /// Destaque da seleção que desliza de um item para o outro.
    @ViewBuilder private func selBackground(_ on: Bool, _ radius: CGFloat) -> some View {
        if on { RoundedRectangle(cornerRadius: radius, style: .continuous).fill(Theme.cyanSoft).matchedGeometryEffect(id: "sidebar-sel", in: selNS) }
    }

    private func navRow(_ title: String, _ icon: String, _ r: Route, _ n: Int, amber: Bool = false) -> some View {
        let on = m.route == r && m.query.isEmpty
        return Button { m.go(r) } label: {
            HStack(spacing: 11) {
                Image(systemName: icon).font(.system(size: 13)).frame(width: 18).foregroundStyle(on ? Theme.cyan : Theme.dim)
                Text(title).font(.system(size: 14, weight: on ? .semibold : .regular)).foregroundStyle(on ? Theme.text : Theme.dim)
                Spacer()
                if n > 0 { Text("\(n)").font(.system(size: 12, weight: .medium)).foregroundStyle(amber ? Theme.amber : Theme.faint) }
            }
            .padding(.horizontal, 10).padding(.vertical, 7.5)
            .background { selBackground(on, 10) }
            .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }

    private func projectRow(_ p: String) -> some View {
        let open = m.expanded.contains(p)
        let on: Bool = { if case .project(let q) = m.route, q == p, m.query.isEmpty { return true }; return false }()
        let n = m.items(in: p).count
        return VStack(alignment: .leading, spacing: 1) {
            HStack(spacing: 6) {
                Button { withAnimation(.snappy(duration: 0.2)) { if open { m.expanded.remove(p) } else { m.expanded.insert(p) } } } label: {
                    Image(systemName: "chevron.right").font(.system(size: 9, weight: .bold)).foregroundStyle(Theme.faint)
                        .rotationEffect(.degrees(open ? 90 : 0)).frame(width: 16, height: 24)
                }.buttonStyle(.plain)
                Button { m.go(.project(p)) } label: {
                    HStack(spacing: 9) {
                        Image(systemName: "folder.fill").font(.system(size: 14)).foregroundStyle(ProjectPalette.tint(p))
                        Text(p).font(.system(size: 14, weight: on ? .semibold : .regular)).foregroundStyle(on ? Theme.text : Theme.dim).lineLimit(1)
                        Spacer()
                        if n > 0 { Text("\(n)").font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.faint) }
                    }.contentShape(Rectangle())
                }.buttonStyle(.plain)
            }
            .padding(.leading, 6).padding(.trailing, 10).padding(.vertical, 4.5)
            .background { selBackground(on, 10) }

            if open {
                ForEach(m.categories(of: p), id: \.name) { cat in
                    let sel: Bool = { if case .folder(let q, let c) = m.route, q == p, c == cat.name, m.query.isEmpty { return true }; return false }()
                    Button { m.go(.folder(p, cat.name)) } label: {
                        HStack(spacing: 9) {
                            Image(systemName: "folder.fill").font(.system(size: 12)).foregroundStyle(Categories.tint(cat.name).opacity(0.9))
                            Text(cat.name).font(.system(size: 13.5, weight: sel ? .semibold : .regular)).foregroundStyle(sel ? Theme.text : Theme.dim)
                            Spacer()
                            Text("\(cat.items.count)").font(.system(size: 12)).foregroundStyle(Theme.faint)
                        }
                        .padding(.leading, 44).padding(.trailing, 10).padding(.vertical, 5)
                        .background { selBackground(sel, 9) }
                        .contentShape(Rectangle())
                    }.buttonStyle(.plain)
                }
            }
        }
    }
}

// MARK: - Home: grade de projetos + atividade recente

struct HomeView: View {
    @ObservedObject var m: LibraryModel
    private let cols = [GridItem(.adaptive(minimum: 230), spacing: 14, alignment: .top)]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 30) {
                HStack {
                    Text("Projects").font(.system(size: 30, weight: .semibold)).foregroundStyle(Theme.text)
                    Spacer()
                    Button { m.importPreload = nil; m.showImport = true } label: { Label("Import from your projects", systemImage: "tray.and.arrow.down") }
                        .buttonStyle(PressStyle())
                }

                LazyVGrid(columns: cols, alignment: .leading, spacing: 14) {
                    let inbox = m.items(in: nil)
                    if !inbox.isEmpty {
                        FolderCard(title: "Inbox", meta: ProjectStats(items: inbox).summary,
                                   art: FolderArt(tint: Color(hex: 0x8A949E), peek: ProjectStats(items: inbox).peek, symbol: "tray.fill",
                                                  badge: shortAgo(ProjectStats(items: inbox).updated).map { "Updated \($0)" })) { m.go(.inbox) }
                    }
                    ForEach(Array(m.projects.enumerated()), id: \.element) { idx, p in
                        let s = ProjectStats(items: m.items(in: p))
                        FolderCard(title: p, meta: s.summary,
                                   art: FolderArt(tint: ProjectPalette.tint(p), peek: s.peek, text: String(p.prefix(1)).uppercased(),
                                                  badge: shortAgo(s.updated).map { "Updated \($0)" }),
                                   palette: PalettePicker(current: ProjectPalette.index(p), pick: { Store.shared.setProjectColor(p, index: $0) })) { m.go(.project(p)) }
                            .staggerIn(idx + 1)
                    }
                    NewFolderCard { m.addingProject = true }
                }

                if m.all.isEmpty { welcome }

                Text("Recent activity").font(.system(size: 26, weight: .semibold)).foregroundStyle(Theme.text)
                let feed = FeedEvent.recent(project: nil, limit: 8)
                if feed.isEmpty {
                    Text("Nothing yet. Every key you copy, file you drop and use by Claude shows up here.")
                        .font(.system(size: 13.5)).foregroundStyle(Theme.dim)
                } else {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(feed.enumerated()), id: \.element.id) { i, e in VStack(spacing: 0) { FeedRow(e: e); Divider().overlay(Theme.line) }.staggerIn(i) }
                    }
                }
            }
            .padding(.horizontal, 30).padding(.vertical, 26)
        }
    }

    private var welcome: some View {
        HStack(spacing: 14) {
            Image(systemName: "sparkles").font(.system(size: 18)).foregroundStyle(Theme.cyan)
            VStack(alignment: .leading, spacing: 3) {
                Text("Start by copying an API key").font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
                Text("Lockd saves it, picks the service and project, and asks for your Touch ID only when something uses it. Drop logos here to file them.")
                    .font(.system(size: 12.5)).foregroundStyle(Theme.dim)
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.cyanSoft, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

// MARK: - Projeto: pastas por categoria + atividade do projeto

struct ProjectView: View {
    @ObservedObject var m: LibraryModel
    let project: String
    private let cols = [GridItem(.adaptive(minimum: 230), spacing: 14, alignment: .top)]

    var body: some View {
        let cats = m.categories(of: project)
        ScrollView {
            VStack(alignment: .leading, spacing: 30) {
                HStack {
                    Text("Folders").font(.system(size: 30, weight: .semibold)).foregroundStyle(Theme.text)
                    Spacer()
                    Button { m.sendProject = project } label: { Label("Send to Vercel", systemImage: "paperplane.fill") }.buttonStyle(PressStyle(prominent: true))
                }
                if cats.isEmpty {
                    VStack(spacing: 10) {
                        FolderArt(tint: ProjectPalette.tint(project), text: String(project.prefix(1)).uppercased(), width: 170)
                        Text("\(project) is empty").font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text)
                        Text("Copy a key while working on it, or drop logos and files on this window.")
                            .font(.system(size: 12.5)).foregroundStyle(Theme.dim)
                    }.frame(maxWidth: .infinity).padding(.vertical, 30)
                } else {
                    LazyVGrid(columns: cols, alignment: .leading, spacing: 14) {
                        ForEach(Array(cats.enumerated()), id: \.element.name) { idx, c in
                            let g = Categories.glyph(c.name)
                            let peek = c.items.filter { $0.isFile && ["Logo", "Vector", "Image"].contains($0.type) }.prefix(2).compactMap(\.path)
                            FolderCard(title: c.name, meta: "\(c.items.count) item\(c.items.count == 1 ? "" : "s")",
                                       art: FolderArt(tint: Categories.tint(c.name), peek: Array(peek), symbol: g.symbol, text: g.text,
                                                      badge: shortAgo(c.items.map(\.createdAt).max()).map { "Updated \($0)" })) {
                                m.go(.folder(project, c.name))
                            }
                            .staggerIn(idx)
                        }
                    }
                }

                Text("Recent in \(project)").font(.system(size: 26, weight: .semibold)).foregroundStyle(Theme.text)
                let feed = FeedEvent.recent(project: project, limit: 6)
                if feed.isEmpty { Text("No activity yet.").font(.system(size: 13.5)).foregroundStyle(Theme.dim) }
                else { VStack(alignment: .leading, spacing: 0) { ForEach(Array(feed.enumerated()), id: \.element.id) { i, e in VStack(spacing: 0) { FeedRow(e: e); Divider().overlay(Theme.line) }.staggerIn(i) } } }
            }
            .padding(.horizontal, 30).padding(.vertical, 26)
        }
    }
}

struct DetailView: View {
    let item: Item
    let projects: [String]
    @State private var revealed: String?
    @State private var copied = false
    @State private var name: String = ""
    @State private var note: String = ""
    @State private var hasExpiry = false
    @State private var expiry = Date()
    @State private var nameError: String?
    @State private var justSaved = false
    @State private var confirmRename = false
    @State private var pendingProject: ProjectChoice?

    struct ProjectChoice: Identifiable { let id = UUID(); let project: String? }

    /// Há algo digitado que ainda não foi gravado?
    private var dirty: Bool {
        name != item.name || note != (item.note ?? "") || hasExpiry != (item.expiresAt != nil) ||
            (hasExpiry && (item.expiresAt.map { !Calendar.current.isDate($0, inSameDayAs: expiry) } ?? false))
    }
    /// Nome e projeto fazem parte da regra assinada: mudar qualquer um desliga o acesso do agente até assinar de novo.
    private var rulesWouldBeRevoked: Bool { item.kind == .secret && Policies.rulesVerified(item) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    ItemIcon(item: item, size: 52)
                    VStack(alignment: .leading, spacing: 4) {
                        TextField("Name", text: $name)
                            .textFieldStyle(.plain).font(.system(size: 18, weight: .bold, design: item.kind == .secret ? .monospaced : .default))
                            .onSubmit { save() }
                        if let nameError { Text(nameError).font(.system(size: 11.5)).foregroundStyle(Theme.amber) }
                        HStack(spacing: 6) {
                            if let s = item.service { Chip(text: s, tint: Theme.cyan) }
                            Chip(text: item.type)
                            ExpiryBadge(item: item)
                        }
                    }
                    Spacer()
                    projectMenu
                }

                if item.kind == .secret { secretBlock; AccessBlock(item: item) } else { fileBlock }

                if let colors = item.colors, !colors.isEmpty { palette(colors) }

                VStack(alignment: .leading, spacing: 8) {
                    label("Expires")
                    HStack {
                        Toggle("", isOn: $hasExpiry).labelsHidden().toggleStyle(.switch).tint(Theme.cyan)
                        if hasExpiry {
                            DatePicker("", selection: $expiry, displayedComponents: .date).labelsHidden()
                        } else { Text("No alarm").font(.system(size: 12)).foregroundStyle(Theme.faint) }
                    }
                }

                VStack(alignment: .leading, spacing: 8) {
                    label("Note")
                    TextField("Where is this used?", text: $note, axis: .vertical)
                        .textFieldStyle(.plain).font(.system(size: 12.5)).lineLimit(1...4).padding(10)
                        .background(Theme.raised, in: RoundedRectangle(cornerRadius: 9)).overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.line))
                }

                saveBar

                VStack(alignment: .leading, spacing: 4) {
                    if let s = item.source { meta("From", s) }
                    meta("Saved", item.createdAt.formatted(date: .abbreviated, time: .shortened))
                }

                Button(role: .destructive) { Ingestor.delete(item) } label: {
                    Label(item.isFile ? "Move file to Trash" : "Delete", systemImage: "trash").font(.system(size: 12, weight: .semibold))
                }.buttonStyle(.plain).foregroundStyle(Theme.danger).padding(.top, 6)
            }
            .padding(28).padding(.top, 14)
        }
        .background(Theme.bg)
        .onAppear { resetFields() }
        .alert("Rename and turn off agent access?", isPresented: $confirmRename) {
            Button("Cancel", role: .cancel) { }
            Button("Rename", role: .destructive) { save(confirmed: true) }
        } message: {
            Text("The name is part of this key's signed rules. After renaming, the agent can't use it until you sign the rules again with Touch ID.")
        }
        .alert("Move and turn off agent access?", isPresented: Binding(get: { pendingProject != nil }, set: { if !$0 { pendingProject = nil } })) {
            Button("Cancel", role: .cancel) { pendingProject = nil }
            Button("Move", role: .destructive) { if let c = pendingProject { reassign(c.project) }; pendingProject = nil }
        } message: {
            Text("The project is part of this key's signed rules. After moving it, the agent can't use it until you sign the rules again with Touch ID.")
        }
    }

    private var saveBar: some View {
        HStack(spacing: 10) {
            Button { save() } label: {
                HStack(spacing: 6) {
                    Image(systemName: justSaved ? "checkmark" : "tray.and.arrow.down").contentTransition(.symbolEffect(.replace))
                    Text(justSaved ? "Saved" : "Save changes")
                }
            }
            .buttonStyle(PressStyle(prominent: true)).disabled(!dirty && !justSaved)
            .opacity(dirty || justSaved ? 1 : 0.4)
            .keyboardShortcut("s", modifiers: .command)
            Button("Discard") { resetFields(); nameError = nil }.buttonStyle(PressStyle()).disabled(!dirty)
                .opacity(dirty ? 1 : 0.4)
            if dirty {
                HStack(spacing: 5) { Circle().fill(Theme.amber).frame(width: 6, height: 6); Text("Unsaved changes").foregroundStyle(Theme.dim) }
                    .font(.system(size: 11.5)).transition(.opacity)
            }
        }
        .animation(.easeOut(duration: 0.15), value: dirty)
    }

    private func resetFields() {
        name = item.name; note = item.note ?? ""
        hasExpiry = item.expiresAt != nil
        expiry = item.expiresAt ?? Calendar.current.date(byAdding: .month, value: 6, to: Date())!
    }

    private func save(confirmed: Bool = false) {
        guard dirty else { return }
        let newName = name.trimmingCharacters(in: .whitespaces)
        guard !newName.isEmpty else { nameError = "The name can't be empty."; return }
        if item.kind == .secret, !isEnvName(newName) { nameError = "Use letters, digits and _ only (e.g. OPENAI_API_KEY)."; return }
        nameError = nil
        if newName != item.name, rulesWouldBeRevoked, !confirmed { confirmRename = true; return }
        let cleanNote = note.trimmingCharacters(in: .whitespacesAndNewlines)
        let on = hasExpiry, day = expiry
        Store.shared.update(id: item.id) {
            $0.name = newName
            $0.note = cleanNote.isEmpty ? nil : note
            $0.expiresAt = on ? day : nil
        }
        name = newName
        withAnimation { justSaved = true }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) { withAnimation { justSaved = false } }
    }

    private var projectMenu: some View {
        Menu {
            Button("Inbox") { choose(nil) }
            Divider()
            ForEach(Array(Set(projects + Store.shared.knownProjects())).sorted(), id: \.self) { p in Button(p) { choose(p) } }
        } label: {
            HStack(spacing: 5) {
                Image(systemName: "folder.fill").font(.system(size: 10))
                Text(item.project ?? "Inbox")
                Image(systemName: "chevron.up.chevron.down").font(.system(size: 8, weight: .bold))
            }
            .font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.cyan)
            .padding(.horizontal, 11).padding(.vertical, 6).background(Theme.cyanSoft, in: Capsule())
        }.menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).fixedSize()
    }

    private func choose(_ p: String?) {
        guard p != item.project else { return }
        if rulesWouldBeRevoked { pendingProject = ProjectChoice(project: p) } else { reassign(p) }
    }

    private func reassign(_ p: String?) {
        if item.isFile { Ingestor.reassign(item, to: p) } else { Store.shared.update(id: item.id) { $0.project = p } }
    }

    private var secretBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            label("Value")
            HStack(spacing: 10) {
                Text(revealed ?? String(repeating: "•", count: 28))
                    .font(.system(size: 12.5, design: .monospaced)).foregroundStyle(revealed == nil ? Theme.faint : Theme.text)
                    .lineLimit(revealed == nil ? 1 : 6).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button {
                    if revealed != nil { revealed = nil }
                    else { Unlock.value(of: item, reason: "Show \(item.name) in Lockd") { revealed = $0 } }
                } label: {
                    Image(systemName: revealed == nil ? "eye" : "eye.slash")
                }.buttonStyle(.plain).foregroundStyle(Theme.dim)
                Button {
                    Unlock.value(of: item, reason: "Copy \(item.name) from Lockd") { v in
                        guard let v else { return }
                        Clip.setSecret(v)
                        withAnimation(.spring(response: 0.3, dampingFraction: 0.6)) { copied = true }
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { withAnimation { copied = false } }
                    }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc").contentTransition(.symbolEffect(.replace))
                        Text(copied ? "Copied" : "Copy")
                    }
                }.buttonStyle(PressStyle(prominent: true))
            }
            .padding(12).background(Theme.raised, in: RoundedRectangle(cornerRadius: 10)).overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.line))
            Text("Sealed by your Mac's Secure Enclave · opening it needs Touch ID · clipboard clears in \(Prefs.clearSeconds)s")
                .font(.system(size: 10.5)).foregroundStyle(Theme.faint)
        }
    }

    private var fileBlock: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let p = item.path, ["Logo", "Vector", "Image"].contains(item.type) {
                ThumbView(path: p).frame(maxWidth: .infinity).frame(height: 200)
                    .background(
                        ZStack { Theme.raised; Checker().opacity(0.5) }.clipShape(RoundedRectangle(cornerRadius: 12))
                    )
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Theme.line))
                    .dragFile(item)
            }
            if let p = item.path {
                Text((p as NSString).abbreviatingWithTildeInPath).font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.faint)
                    .textSelection(.enabled).lineLimit(2)
                HStack(spacing: 8) {
                    Button { if let u = item.fileURL { Clip.setFile(u) } } label: { Label("Copy file", systemImage: "doc.on.doc") }
                        .buttonStyle(PressStyle(prominent: true))
                    Button { if let u = item.fileURL { NSWorkspace.shared.activateFileViewerSelecting([u]) } } label: { Label("Show in Finder", systemImage: "folder") }
                        .buttonStyle(PressStyle())
                    Button { if let u = item.fileURL { NSWorkspace.shared.open(u) } } label: { Label("Open", systemImage: "arrow.up.forward.app") }
                        .buttonStyle(PressStyle())
                }
            }
            if let n = item.note, n.hasPrefix("Gradient") { Text(n).font(.system(size: 12)).foregroundStyle(Theme.dim) }
        }
    }

    private func palette(_ colors: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            label("Palette · click to copy")
            HStack(spacing: 8) {
                ForEach(colors, id: \.self) { c in
                    Button { Clip.setText(c) } label: {
                        VStack(spacing: 5) {
                            RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color(hexString: c) ?? .gray).frame(width: 62, height: 46)
                                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.line))
                            Text(c).font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.dim)
                        }
                    }.buttonStyle(.plain).onDrag { NSItemProvider(object: c as NSString) }
                }
            }
        }
    }

    private func label(_ s: String) -> some View {
        Text(s.uppercased()).font(.system(size: 10, weight: .bold)).tracking(0.8).foregroundStyle(Theme.faint)
    }
    private func meta(_ k: String, _ v: String) -> some View {
        HStack { Text(k).foregroundStyle(Theme.faint).frame(width: 50, alignment: .leading); Text(v).foregroundStyle(Theme.dim) }.font(.system(size: 11.5))
    }
}

struct Checker: View {
    var body: some View {
        Canvas { ctx, size in
            let s: CGFloat = 10
            for x in 0..<Int(size.width / s) + 1 { for y in 0..<Int(size.height / s) + 1 where (x + y) % 2 == 0 {
                ctx.fill(Path(CGRect(x: CGFloat(x) * s, y: CGFloat(y) * s, width: s, height: s)), with: .color(.white.opacity(0.035)))
            } }
        }
    }
}

struct AddSecretSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State var project: String?
    init(project: String?, initial: String? = nil) {
        _project = State(initialValue: project); _value = State(initialValue: initial ?? "")
    }
    @State private var name = ""
    @State private var value = ""
    @State private var service = ""
    @State private var saveError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let saveError { Text(saveError).font(.caption).foregroundStyle(Theme.amber) }
            Text("Add secret").font(.system(size: 16, weight: .bold))
            field("Value", text: $value, mono: true)
            field("Name", text: $name, mono: true, prompt: "ANTHROPIC_API_KEY")
            field("Service", text: $service, prompt: "Anthropic")
            Menu(project ?? "Inbox") {
                Button("Inbox") { project = nil }
                ForEach(Store.shared.knownProjects(), id: \.self) { p in Button(p) { project = p } }
            }.menuStyle(.button).fixedSize()
            HStack {
                Button("Paste from clipboard") {
                    if let s = NSPasteboard.general.string(forType: .string) { value = s.trimmingCharacters(in: .whitespacesAndNewlines); autofill() }
                }.buttonStyle(PressStyle())
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(PressStyle())
                Button("Save") { save() }.buttonStyle(PressStyle(prominent: true)).disabled(value.isEmpty).keyboardShortcut(.defaultAction)
            }
        }
        .padding(22).frame(width: 460).background(Theme.panel)
        .onChange(of: value) { _, _ in if name.isEmpty { autofill() } }
        .onAppear { if !value.isEmpty { autofill() } }
    }

    private func autofill() {
        if let d = Detector.detect(in: value).first { name = d.envName; service = d.service }
    }

    private func save() {
        let det = Detector.detect(in: value).first
        let d = Detection(envName: name.isEmpty ? (det?.envName ?? "SECRET") : name, service: service.isEmpty ? (det?.service ?? "Manual") : service,
                          type: det?.type ?? "Secret", value: det?.value ?? value, confident: true, expiresAt: det?.expiresAt, note: det?.note)
        do { _ = try Store.shared.saveSecret(d, project: project, source: "Manual"); dismiss() }
        catch { saveError = error.localizedDescription }
    }

    private func field(_ title: String, text: Binding<String>, mono: Bool = false, prompt: String = "") -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title.uppercased()).font(.system(size: 10, weight: .bold)).tracking(0.8).foregroundStyle(Theme.faint)
            TextField(prompt, text: text).textFieldStyle(.plain).font(.system(size: 13, design: mono ? .monospaced : .default))
                .padding(10).background(Theme.raised, in: RoundedRectangle(cornerRadius: 9)).overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.line))
        }
    }
}

struct SettingsView: View {
    @State private var downloads = Prefs.watchDownloads
    @State private var desktop = Prefs.watchDesktop
    @State private var clear = Prefs.clearSeconds
    @State private var session = Prefs.sessionMinutes
    @State private var paused = Prefs.paused
    @State private var login = LoginItem.enabled
    @State private var ax = AXIsProcessTrusted()
    @State private var suggest = Prefs.suggestions
    @State private var backup: BackupMode?
    @State private var browserLinked = AppDelegate.shared?.broker.bridge.isConnected ?? false
    @State private var browserNote: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                Text("Settings").font(.system(size: 20, weight: .bold))
                SecuritySettingsBlock()
                group("Projects") {
                    Button { NotificationCenter.default.post(name: .lockdImport, object: nil) } label: { Label("Import from your projects…", systemImage: "tray.and.arrow.down") }.buttonStyle(PressStyle())
                    toggle("While I work, tell me about keys in a project's .env that aren't in Lockd", $suggest) { Prefs.suggestions = $0 }
                    Text("Needs Accessibility so Lockd can tell which project is open. Each project is mentioned at most twice a day.").font(.system(size: 11.5)).foregroundStyle(Theme.dim)
                }
                group("Browser") {
                    HStack(spacing: 8) {
                        Image(systemName: browserLinked ? "checkmark.circle.fill" : "circle.dashed").foregroundStyle(browserLinked ? Theme.cyan : Theme.dim)
                        Text(browserLinked ? "Chrome extension connected" : "Chrome extension not connected").font(.system(size: 13, weight: .semibold))
                    }
                    Text("The extension hides API keys on web pages (page text and screenshots show only sk-ant-••••), saves a key to Lockd with one click, and types keys into forms when Claude asks — Claude never sees the value.")
                        .font(.system(size: 12.5)).foregroundStyle(Theme.dim)
                    Button { browserNote = BrowserSetup.run() } label: { Label(browserLinked ? "Set up again…" : "Set up Chrome extension…", systemImage: "puzzlepiece.extension") }
                        .buttonStyle(PressStyle(prominent: !browserLinked))
                    if let n = browserNote { Text(n).font(.system(size: 12)).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true) }
                }
                .onReceive(Timer.publish(every: 2, on: .main, in: .common).autoconnect()) { _ in
                    browserLinked = AppDelegate.shared?.broker.bridge.isConnected ?? false
                }
                group("Backup") {
                    Text("Keys are sealed to this Mac. A passphrase-encrypted backup lets you restore them on a new Mac. Without one, losing this Mac loses the keys.")
                        .font(.system(size: 12.5)).foregroundStyle(Theme.dim)
                    HStack(spacing: 10) {
                        Button { backup = .export } label: { Label("Export encrypted backup…", systemImage: "square.and.arrow.up") }.buttonStyle(PressStyle(prominent: true))
                        Button { backup = .importing } label: { Label("Import backup…", systemImage: "square.and.arrow.down") }.buttonStyle(PressStyle())
                    }
                }
                group("Capture") {
                    toggle("Pause capture", $paused) { Prefs.paused = $0 }
                    toggle("Watch Downloads for logos, fonts and credentials", $downloads) { Prefs.watchDownloads = $0; AppDelegate.shared?.restartWatchers() }
                    toggle("Watch Desktop", $desktop) { Prefs.watchDesktop = $0; AppDelegate.shared?.restartWatchers() }
                }
                group("Clipboard") {
                    Stepper("Clear copied secrets after \(clear == 0 ? "never" : "\(clear)s")", value: $clear, in: 0...300, step: 10)
                        .onChange(of: clear) { _, v in Prefs.clearSeconds = v }.font(.system(size: 13))
                }
                group("Vault") {
                    Stepper("Stay unlocked for \(session) min after Touch ID", value: $session, in: 1...120, step: 5)
                        .onChange(of: session) { _, v in Prefs.sessionMinutes = v; Vault.shared.sessionSeconds = Double(v) * 60 }.font(.system(size: 13))
                    Text("Claude and you can use keys without asking again during this time. It locks on sleep and when the screen locks.")
                        .font(.system(size: 11.5)).foregroundStyle(Theme.dim)
                }
                group("System") {
                    toggle("Open Lockd at login", $login) { LoginItem.set($0) }
                    HStack {
                        Image(systemName: ax ? "checkmark.circle.fill" : "exclamationmark.triangle.fill").foregroundStyle(ax ? Theme.cyan : Theme.amber)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(ax ? "Accessibility granted" : "Accessibility needed").font(.system(size: 13, weight: .semibold))
                            Text("Lets Lockd read the project from your window title and paste with ↩.").font(.system(size: 11.5)).foregroundStyle(Theme.dim)
                        }
                        Spacer()
                        if !ax {
                            Button("Grant") {
                                AXIsProcessTrustedWithOptions([kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary)
                            }.buttonStyle(PressStyle(prominent: true))
                        }
                        Button { ax = AXIsProcessTrusted() } label: { Image(systemName: "arrow.clockwise") }.buttonStyle(.plain)
                    }
                }
                group("Files") {
                    HStack {
                        Text("Organized in ~/Lockd/<Project>/<Logos · Images · Fonts · Credentials>").font(.system(size: 12.5)).foregroundStyle(Theme.dim)
                        Spacer()
                        Button("Open") { try? FileManager.default.createDirectory(at: LockdPaths.libraryRoot, withIntermediateDirectories: true); NSWorkspace.shared.open(LockdPaths.libraryRoot) }
                            .buttonStyle(PressStyle())
                    }
                }
                group("Shortcuts") {
                    HStack { Text("Search & paste anywhere"); Spacer(); Chip(text: "⌥⌘L", tint: Theme.cyan) }.font(.system(size: 13))
                }
                group("Use from Claude Code") {
                    Text("Lockd encrypts keys on this Mac, requires local authentication, and limits agent tools and destinations. Use lockd_http; output filtering reduces accidental exposure. .env files remain readable by your user and the agent.")
                        .font(.system(size: 12.5)).foregroundStyle(Theme.dim)
                    Button("Copy install command") {
                        Clip.setText("claude mcp add lockd -- \(Bundle.main.bundlePath)/Contents/MacOS/lockdctl mcp")
                    }.buttonStyle(PressStyle(prominent: true))
                }
            }
            .padding(32).padding(.top, 14).frame(maxWidth: 620, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .sheet(item: $backup) { mode in BackupSheet(mode: mode) { backup = nil } }
        .background(Theme.bg)
        .onAppear { ax = AXIsProcessTrusted() }
    }

    private func group<C: View>(_ title: String, @ViewBuilder _ content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title.uppercased()).font(.system(size: 10, weight: .bold)).tracking(0.8).foregroundStyle(Theme.faint)
            VStack(alignment: .leading, spacing: 12) { content() }
                .padding(16).frame(maxWidth: .infinity, alignment: .leading)
                .background(Theme.panel, in: RoundedRectangle(cornerRadius: 12)).overlay(RoundedRectangle(cornerRadius: 12).stroke(Theme.line))
        }
    }

    private func toggle(_ t: String, _ b: Binding<Bool>, _ set: @escaping (Bool) -> Void) -> some View {
        Toggle(t, isOn: b).toggleStyle(.switch).tint(Theme.cyan).font(.system(size: 13)).onChange(of: b.wrappedValue) { _, v in set(v) }
    }
}
