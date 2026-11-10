import SwiftUI
import AppKit
import LockdCore

// MARK: - Categorias e cores

extension Item {
    /// Pasta lógica dentro do projeto: chaves vão em "Keys"; arquivos pela pasta onde o Lockd os organizou.
    var category: String {
        if kind == .secret { return "Keys" }
        if let p = path { return URL(fileURLWithPath: p).deletingLastPathComponent().lastPathComponent }
        return "Other"
    }
}

enum Categories {
    static let order = ["Keys", "Logos", "Images", "Vectors", "Fonts", "Credentials", "Docs", "Other"]

    static func glyph(_ c: String) -> (symbol: String?, text: String?) {
        switch c {
        case "Keys": return ("key.fill", nil)
        case "Logos": return ("pentagon.fill", nil)
        case "Images": return ("photo.fill", nil)
        case "Vectors": return ("square.on.circle.fill", nil)
        case "Fonts": return (nil, "Aa")
        case "Credentials": return ("lock.doc.fill", nil)
        case "Docs": return ("doc.text.fill", nil)
        default: return ("doc.fill", nil)
        }
    }

    static func tint(_ c: String) -> Color {
        switch c {
        case "Keys": return Color(hex: 0x16A394)
        case "Logos": return Color(hex: 0x4C8DD6)
        case "Images": return Color(hex: 0x8B7AE0)
        case "Vectors": return Color(hex: 0x2FB59F)
        case "Fonts": return Color(hex: 0xE0805A)
        case "Credentials": return Color(hex: 0xD9A441)
        case "Docs": return Color(hex: 0x8A949E)
        default: return Color(hex: 0x8A949E)
        }
    }
}

enum ProjectPalette {
    static let colors: [UInt32] = [0x2FB59F, 0x4C8DD6, 0x8B7AE0, 0xD9A441, 0xE0805A, 0x5FB36A, 0xD6678A]

    static let names = ["Mint", "Blue", "Violet", "Amber", "Coral", "Green", "Rose"]

    /// Estável entre execuções (hashValue do Swift muda a cada abertura). A cor escolhida pelo usuário vence, mas só da paleta.
    static func index(_ name: String) -> Int {
        if let i = Store.shared.projectColors[name], colors.indices.contains(i) { return i }
        var h: UInt32 = 5381
        for b in name.lowercased().utf8 { h = h &* 33 &+ UInt32(b) }
        return Int(h % UInt32(colors.count))
    }
    static func tint(_ name: String) -> Color { Color(hex: colors[index(name)]) }
}

struct ProjectStats {
    var keys = 0, files = 0
    var updated: Date?
    var peek: [String] = []        // até 2 imagens para "espiar" da pasta

    init(items: [Item]) {
        keys = items.filter { $0.kind == .secret }.count
        files = items.filter { $0.kind != .secret }.count
        updated = items.map(\.createdAt).max()
        peek = items.filter { $0.isFile && ["Logo", "Vector", "Image"].contains($0.type) }
            .sorted { $0.createdAt > $1.createdAt }.prefix(2).compactMap(\.path)
    }

    var summary: String {
        var parts: [String] = []
        if keys > 0 { parts.append("\(keys) key\(keys == 1 ? "" : "s")") }
        if files > 0 { parts.append("\(files) file\(files == 1 ? "" : "s")") }
        return parts.isEmpty ? "Empty" : parts.joined(separator: " · ")
    }
}

func shortAgo(_ d: Date?) -> String? {
    guard let d else { return nil }
    let s = Date().timeIntervalSince(d)
    if s < 60 { return "now" }
    if s < 3600 { return "\(Int(s / 60))m" }
    if s < 86_400 { return "\(Int(s / 3600))h" }
    return "\(Int(s / 86_400))d"
}

// MARK: - Arte da pasta (vidro tingido)

struct FolderArt: View {
    var tint: Color
    var peek: [String] = []
    var symbol: String? = nil
    var text: String? = nil
    var badge: String? = nil
    var width: CGFloat = 200
    var hover = false

    var body: some View {
        let W = width, H = width * 0.8
        ZStack(alignment: .bottom) {
            // fundo da pasta com a aba
            ZStack(alignment: .topLeading) {
                RoundedRectangle(cornerRadius: W * 0.05, style: .continuous).fill(tint)
                    .frame(width: W * 0.36, height: W * 0.14).offset(x: W * 0.05, y: H * 0.04)
                RoundedRectangle(cornerRadius: W * 0.08, style: .continuous).fill(tint)
                    .frame(width: W, height: H * 0.84).offset(y: H * 0.16)
            }
            .frame(width: W, height: H, alignment: .topLeading)
            .overlay(Color.black.opacity(0.22).clipShape(RoundedRectangle(cornerRadius: W * 0.08, style: .continuous)).padding(.top, H * 0.16))

            // papéis espiando
            ZStack {
                if peek.count > 1 { paper(peek[1], W, H).rotationEffect(.degrees(hover ? 10 : 5)).offset(x: W * (hover ? 0.19 : 0.14), y: -H * (hover ? 0.07 : 0.02)) }
                paper(peek.first, W, H).rotationEffect(.degrees(peek.count > 1 ? (hover ? -9 : -5) : (hover ? -6 : -3)))
                    .offset(x: peek.count > 1 ? -W * (hover ? 0.14 : 0.1) : W * 0.02, y: hover ? -H * 0.04 : 0)
            }
            .frame(width: W, height: H, alignment: .top).offset(y: -H * (hover ? 0.2 : 0.14))

            // frente de vidro
            ZStack {
                RoundedRectangle(cornerRadius: W * 0.09, style: .continuous)
                    .fill(LinearGradient(colors: [tint.opacity(0.96), tint.opacity(0.80)], startPoint: .top, endPoint: .bottom))
                RoundedRectangle(cornerRadius: W * 0.09, style: .continuous)
                    .fill(LinearGradient(colors: [.white.opacity(0.28), .clear], startPoint: .top, endPoint: .center))
                RoundedRectangle(cornerRadius: W * 0.09, style: .continuous)
                    .stroke(LinearGradient(colors: [.white.opacity(0.55), .white.opacity(0.05)], startPoint: .top, endPoint: .bottom), lineWidth: 1.2)
                if let symbol { Image(systemName: symbol).font(.system(size: W * 0.2, weight: .semibold)).foregroundStyle(.white.opacity(0.92)) }
                if let text { Text(text).font(.system(size: W * 0.24, weight: .semibold, design: .rounded)).foregroundStyle(.white.opacity(0.92)) }
                if let badge {
                    Text(badge).font(.system(size: W * 0.058, weight: .medium)).foregroundStyle(.white.opacity(0.95))
                        .padding(.horizontal, W * 0.04).padding(.vertical, W * 0.018)
                        .background(Color.black.opacity(0.22), in: Capsule())
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomLeading).padding(W * 0.05)
                }
            }
            .frame(width: W, height: H * 0.6)
            .shadow(color: tint.opacity(0.35), radius: W * 0.05, y: W * 0.03)
        }
        .frame(width: W, height: H)
        .animation(.spring(response: 0.5, dampingFraction: 0.68), value: hover)
    }

    @ViewBuilder private func paper(_ path: String?, _ W: CGFloat, _ H: CGFloat) -> some View {
        RoundedRectangle(cornerRadius: W * 0.04, style: .continuous).fill(Color.white.opacity(0.96))
            .frame(width: W * 0.46, height: H * 0.56)
            .overlay {
                if let path { ThumbView(path: path).padding(W * 0.05) }
                else {
                    VStack(alignment: .leading, spacing: W * 0.03) {
                        ForEach(0..<3, id: \.self) { i in
                            Capsule().fill(Color.black.opacity(0.12)).frame(width: W * (i == 2 ? 0.16 : 0.3), height: W * 0.022)
                        }
                    }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading).padding(W * 0.06)
                }
            }
            .shadow(color: .black.opacity(0.18), radius: W * 0.02, y: W * 0.01)
    }
}

/// Escolha de cor da pasta: só as cores da paleta da marca, para nunca ficar feio.
struct PalettePicker {
    let current: Int
    let pick: (Int?) -> Void
}

struct FolderCard: View {
    var title: String
    var meta: String
    var art: FolderArt
    var palette: PalettePicker? = nil
    var action: () -> Void
    @State private var hover = false
    @State private var showPalette = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: 10) {
                { () -> FolderArt in var a = art; a.hover = hover; return a }()
                VStack(spacing: 2) {
                    Text(title).font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text).lineLimit(1)
                    Text(meta).font(.system(size: 12)).foregroundStyle(Theme.dim).lineLimit(1)
                }
            }
            .padding(.vertical, 16).padding(.horizontal, 12)
            .frame(maxWidth: .infinity)
            .background(hover ? Theme.raised : Color.clear, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
            .offset(y: hover ? -3 : 0)
            .animation(.spring(response: 0.35, dampingFraction: 0.72), value: hover)
        }
        .buttonStyle(.plain)
        .overlay(alignment: .topTrailing) {
            if let palette {
                Button { showPalette.toggle() } label: {
                    Image(systemName: "paintpalette.fill").font(.system(size: 11)).foregroundStyle(.secondary)
                        .frame(width: 26, height: 26).background(.regularMaterial, in: Circle()).overlay(Circle().stroke(Theme.line))
                }
                .buttonStyle(.plain).padding(10)
                .opacity(hover || showPalette ? 1 : 0).scaleEffect(hover || showPalette ? 1 : 0.6)
                .animation(.spring(response: 0.3, dampingFraction: 0.7), value: hover)
                .help("Folder color")
                .popover(isPresented: $showPalette, arrowEdge: .bottom) { PaletteGrid(picker: palette) }
            }
        }
        .onHover { hover = $0 }
    }
}

struct PaletteGrid: View {
    let picker: PalettePicker
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Folder color").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text)
            HStack(spacing: 9) {
                ForEach(Array(ProjectPalette.colors.enumerated()), id: \.offset) { i, hex in
                    Button { picker.pick(i) } label: {
                        Circle().fill(Color(hex: hex)).frame(width: 24, height: 24)
                            .overlay(Circle().stroke(Color.white.opacity(0.35), lineWidth: 1))
                            .overlay { if picker.current == i { Image(systemName: "checkmark").font(.system(size: 10, weight: .bold)).foregroundStyle(.white) } }
                            .scaleEffect(picker.current == i ? 1.12 : 1)
                    }
                    .buttonStyle(.plain).help(ProjectPalette.names[i])
                }
            }
            Button("Automatic") { picker.pick(nil) }.buttonStyle(.plain).font(.system(size: 11.5)).foregroundStyle(Theme.dim)
        }
        .padding(14)
        .animation(.spring(response: 0.3, dampingFraction: 0.7), value: picker.current)
    }
}

/// Entrada escalonada: cada item sobe e aparece com um pequeno atraso (sensação de fluidez, sem exagero).
struct StaggerIn: ViewModifier {
    let index: Int
    @State private var shown = false
    func body(content: Content) -> some View {
        content
            .opacity(shown ? 1 : 0).offset(y: shown ? 0 : 14).scaleEffect(shown ? 1 : 0.97, anchor: .bottom)
            .onAppear {
                withAnimation(.spring(response: 0.55, dampingFraction: 0.82).delay(min(Double(index), 12) * 0.05)) { shown = true }
            }
    }
}
extension View { func staggerIn(_ i: Int) -> some View { modifier(StaggerIn(index: i)) } }

/// Cartão "novo projeto" tracejado.
struct NewFolderCard: View {
    var action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            VStack(spacing: 10) {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .stroke(Theme.faint.opacity(0.7), style: StrokeStyle(lineWidth: 1.5, dash: [7, 6]))
                    .frame(width: 200, height: 160)
                    .overlay(Image(systemName: "plus").font(.system(size: 26, weight: .medium)).foregroundStyle(hover ? Theme.cyan : Theme.dim))
                Text("New project").font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.dim)
                Text("or just drop files here").font(.system(size: 12)).foregroundStyle(Theme.faint)
            }
            .padding(.vertical, 16).padding(.horizontal, 12).frame(maxWidth: .infinity)
        }
        .buttonStyle(.plain).onHover { hover = $0 }
    }
}

// MARK: - Atividade recente (capturas + uso pelo Claude)

struct FeedEvent: Identifiable {
    let id = UUID()
    var date: Date
    var symbol: String
    var tint: Color
    var lead: String        // "Lockd" / "Claude"
    var verb: String
    var object: String
    var tail: String
    var quote: String?
    var project: String?

    static func recent(project: String?, limit: Int) -> [FeedEvent] {
        var out: [FeedEvent] = []
        for i in Store.shared.items where project == nil || i.project == project {
            out.append(FeedEvent(date: i.createdAt, symbol: i.kind == .secret ? "key.fill" : "tray.and.arrow.down.fill",
                                 tint: Theme.cyan, lead: "Lockd", verb: i.kind == .secret ? "saved" : "filed",
                                 object: i.name, tail: i.project.map { " to \($0)" } ?? " to Inbox",
                                 quote: i.source.map { "from \($0)" }, project: i.project))
        }
        for e in Audit.recent(limit: 60) where project == nil || e.project == project {
            let names = e.secrets.prefix(2).joined(separator: ", ")
            switch e.status {
            case "ok": out.append(FeedEvent(date: e.date, symbol: "sparkle", tint: Color(hex: 0xD97757), lead: "Claude", verb: "used",
                                            object: names.isEmpty ? e.tool : names, tail: e.project.map { " in \($0)" } ?? "",
                                            quote: e.command, project: e.project))
            case "denied": out.append(FeedEvent(date: e.date, symbol: "hand.raised.fill", tint: Theme.amber, lead: "Claude", verb: "was blocked from",
                                                object: e.tool, tail: "", quote: e.detail, project: e.project))
            default: break
            }
        }
        return Array(out.sorted { $0.date > $1.date }.prefix(limit))
    }
}

struct FeedRow: View {
    let e: FeedEvent
    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            ZStack {
                Circle().fill(e.tint.opacity(0.16)).frame(width: 40, height: 40)
                Image(systemName: e.symbol).font(.system(size: 15, weight: .semibold)).foregroundStyle(e.tint)
            }
            VStack(alignment: .leading, spacing: 6) {
                (Text(e.lead).foregroundColor(Theme.text).fontWeight(.medium) + Text(" \(e.verb) ").foregroundColor(Theme.dim)
                 + Text(e.object).foregroundColor(Theme.text).fontWeight(.semibold) + Text(e.tail).foregroundColor(Theme.dim))
                    .font(.system(size: 14.5)).lineLimit(2)
                if let q = e.quote, !q.isEmpty {
                    Text(q).font(.system(size: 12.5)).foregroundStyle(Theme.dim).lineLimit(2)
                        .padding(.horizontal, 14).padding(.vertical, 9).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Theme.raised, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                }
            }
            Text(shortAgo(e.date) ?? "").font(.system(size: 12)).foregroundStyle(Theme.faint)
        }
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
