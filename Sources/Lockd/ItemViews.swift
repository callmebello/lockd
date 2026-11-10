import SwiftUI
import LockdCore

enum ItemStyle {
    static func symbol(_ i: Item) -> String {
        switch i.kind {
        case .secret:
            if i.type.contains("Private") { return "key.horizontal.fill" }
            if i.type == "Connection URL" { return "externaldrive.connected.to.line.below.fill" }
            return "key.fill"
        case .credential: return i.type.contains("Provisioning") ? "doc.badge.gearshape.fill" : "lock.doc.fill"
        case .asset:
            switch i.type {
            case "Font": return "textformat"
            case "Logo", "Vector": return "pentagon.fill"
            case "Image": return "photo.fill"
            default: return "doc.fill"
            }
        }
    }

    static func subtitle(_ i: Item) -> String {
        [i.service, i.type, i.project ?? "Inbox"].compactMap { $0 }.joined(separator: "  ·  ")
    }
}

struct ExpiryBadge: View {
    let item: Item
    var body: some View {
        if let d = item.daysUntilExpiry {
            let tint: Color = d < 0 ? Theme.danger : d <= 14 ? Theme.amber : Theme.dim
            Chip(text: d < 0 ? "expired" : d == 0 ? "today" : "\(d)d", tint: tint)
        }
    }
}

struct ItemIcon: View {
    let item: Item
    var size: CGFloat = 34
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous).fill(Theme.raised)
            if item.isFile, let p = item.path, ["Logo", "Vector", "Image"].contains(item.type) {
                ThumbView(path: p).padding(size * 0.14)
            } else {
                Image(systemName: ItemStyle.symbol(item)).font(.system(size: size * 0.42, weight: .semibold))
                    .foregroundStyle(item.kind == .secret ? Theme.cyan : Theme.dim)
            }
        }
        .frame(width: size, height: size)
        .overlay(RoundedRectangle(cornerRadius: size * 0.28, style: .continuous).stroke(Theme.line))
    }
}

struct ItemRow: View {
    let item: Item
    var selected = false
    var showHint = false

    var body: some View {
        HStack(spacing: 11) {
            ItemIcon(item: item)
            VStack(alignment: .leading, spacing: 2.5) {
                Text(item.name).font(.system(size: 13, weight: .semibold, design: item.kind == .secret ? .monospaced : .default))
                    .foregroundStyle(Theme.text).lineLimit(1)
                Text(ItemStyle.subtitle(item)).font(.system(size: 11)).foregroundStyle(Theme.dim).lineLimit(1)
            }
            Spacer(minLength: 8)
            ExpiryBadge(item: item)
            if let cs = item.colors, !cs.isEmpty {
                HStack(spacing: -4) {
                    ForEach(cs.prefix(4), id: \.self) { c in
                        Circle().fill(Color(hexString: c) ?? .gray).frame(width: 13, height: 13)
                            .overlay(Circle().stroke(Theme.panel, lineWidth: 1.5))
                    }
                }
            }
            if item.kind == .secret {
                Text(item.preview).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.faint)
            }
            if showHint && selected {
                Text("↩").font(.system(size: 11, weight: .bold)).foregroundStyle(Theme.cyan)
                    .padding(.horizontal, 6).padding(.vertical, 2).background(Theme.cyanSoft, in: RoundedRectangle(cornerRadius: 5))
            }
        }
        .padding(.horizontal, 10).padding(.vertical, 7)
        .background(selected ? Theme.hover : .clear, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        .overlay(alignment: .leading) {
            if selected { Capsule().fill(Theme.cyan).frame(width: 3, height: 20).offset(x: -1) }
        }
        .contentShape(Rectangle())
    }
}


extension View {
    /// Arquivos (logo, fonte, imagem) podem ser arrastados do Lockd para o Figma, o Finder, o navegador, um e-mail…
    @ViewBuilder func dragFile(_ item: Item) -> some View {
        if item.isFile, let u = item.fileURL, FileManager.default.fileExists(atPath: u.path) {
            self.onDrag { NSItemProvider(contentsOf: u) ?? NSItemProvider() }
        } else { self }
    }
}
