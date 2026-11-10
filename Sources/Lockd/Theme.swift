import SwiftUI
import AppKit
import ImageIO

extension Color {
    init(hex: UInt32, opacity: Double = 1) {
        self.init(.sRGB, red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255, opacity: opacity)
    }
    init?(hexString: String) {
        var s = hexString.trimmingCharacters(in: CharacterSet(charactersIn: "#"))
        if s.count == 3 { s = s.map { "\($0)\($0)" }.joined() }
        guard s.count == 6, let v = UInt32(s, radix: 16) else { return nil }
        self.init(hex: v)
    }
    /// Cor que troca sozinha entre claro e escuro.
    static func dynamic(light: UInt32, dark: UInt32, lightAlpha: Double = 1, darkAlpha: Double = 1) -> Color {
        Color(nsColor: NSColor(name: nil) { a in
            let isDark = a.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            let v = isDark ? dark : light
            return NSColor(srgbRed: CGFloat((v >> 16) & 0xFF) / 255, green: CGFloat((v >> 8) & 0xFF) / 255,
                           blue: CGFloat(v & 0xFF) / 255, alpha: isDark ? darkAlpha : lightAlpha)
        })
    }
}

/// Identidade: verde mineral + branco névoa + vidro. Nomes antigos mantidos (cyan = cor principal).
enum Theme {
    // marca
    static let brand = Color(hex: 0x168F83)
    static let mint = Color(hex: 0xA8E6D9)
    static let deep = Color(hex: 0x123D38)
    static let mist = Color(hex: 0xF5F8F7)

    // superfícies
    static let bg = Color.dynamic(light: 0xF5F8F7, dark: 0x262624)
    static let panel = Color.dynamic(light: 0xFFFFFF, dark: 0x30302E, lightAlpha: 0.72, darkAlpha: 1)
    static let raised = Color.dynamic(light: 0xE9EFED, dark: 0x3B3B38)
    static let hover = Color.dynamic(light: 0x168F83, dark: 0x3CC2B2, lightAlpha: 0.10, darkAlpha: 0.16)
    static let line = Color.dynamic(light: 0x123D38, dark: 0xFFFFFF, lightAlpha: 0.09, darkAlpha: 0.08)

    // texto
    static let text = Color.dynamic(light: 0x202A28, dark: 0xF0EEE6)
    static let dim = Color.dynamic(light: 0x788680, dark: 0xA8A59C)
    static let faint = Color.dynamic(light: 0xA3AEA9, dark: 0x7A776E)

    // destaque (no escuro o verde clareia p/ manter contraste)
    static let cyan = Color.dynamic(light: 0x168F83, dark: 0x3CC2B2)
    static let cyanSoft = Color.dynamic(light: 0x168F83, dark: 0x3CC2B2, lightAlpha: 0.12, darkAlpha: 0.16)
    static let danger = Color(hex: 0xD6455D)
    static let amber = Color(hex: 0xC98A14)
    static let onBrand = Color.white
}

// MARK: - Liquid Glass

extension View {
    /// Liquid Glass no macOS 26; material translúcido nas versões anteriores.
    /// `scrim` põe uma base do tema sob o vidro p/ o texto nunca perder contraste sobre fundos agitados.
    @ViewBuilder func lockdGlass(radius: CGFloat, scrim: Double = 0) -> some View {
        let shape = RoundedRectangle(cornerRadius: radius, style: .continuous)
        if #available(macOS 26.0, *) {
            self.background(Theme.bg.opacity(scrim), in: shape).glassEffect(.regular, in: shape)
        } else {
            self.background(.ultraThinMaterial, in: shape)
                .background(Theme.bg.opacity(scrim), in: shape)
                .overlay(shape.stroke(Theme.line))
        }
    }
}

// MARK: - Símbolo: disco de vidro verde com o L vazado

struct LShape: Shape {
    func path(in r: CGRect) -> Path {
        let w = r.width, h = r.height
        var p = Path()
        p.addRoundedRect(in: CGRect(x: r.minX + w * 0.15, y: r.minY + h * 0.04, width: w * 0.30, height: h * 0.92),
                         cornerSize: CGSize(width: w * 0.07, height: w * 0.07), style: .continuous)
        p.addRoundedRect(in: CGRect(x: r.minX + w * 0.15, y: r.minY + h * 0.66, width: w * 0.72, height: h * 0.30),
                         cornerSize: CGSize(width: w * 0.07, height: w * 0.07), style: .continuous)
        return p
    }
}

struct LogoMark: View {
    var size: CGFloat = 40
    var body: some View {
        ZStack {
            Circle().fill(LinearGradient(colors: [Theme.mint, Color(hex: 0x3FB8A8), Color(hex: 0x0F6F66)],
                                         startPoint: .topLeading, endPoint: .bottomTrailing))
            Circle().stroke(LinearGradient(colors: [.white.opacity(0.7), .white.opacity(0.05)], startPoint: .topLeading, endPoint: .bottomTrailing),
                            lineWidth: size * 0.035)
            Ellipse().fill(LinearGradient(colors: [.white.opacity(0.45), .clear], startPoint: .top, endPoint: .bottom))
                .frame(width: size * 0.62, height: size * 0.3).offset(y: -size * 0.28)
            LShape().fill(Theme.mist).frame(width: size * 0.3, height: size * 0.34)
                .shadow(color: Theme.deep.opacity(0.35), radius: size * 0.02, y: size * 0.015)
                .offset(x: size * 0.015)
        }
        .frame(width: size, height: size)
        .shadow(color: Theme.deep.opacity(0.18), radius: size * 0.08, y: size * 0.04)
    }
}

/// Arte final da marca, usada direto (sem passar pelo ícone do sistema) para nunca virar "base dentro de base".
/// A imagem é reduzida UMA vez, com filtro de boa qualidade, para o tamanho exato em pixels: o SwiftUI sozinho
/// serrilha ao reduzir 512 px para 40 pt.
enum AppIconArt {
    nonisolated(unsafe) private static var cache: [Int: NSImage] = [:]
    static var url: URL? { Bundle.main.url(forResource: "AppIconUI", withExtension: "png") }

    static func image(points: CGFloat, scale: CGFloat) -> NSImage? {
        guard let url else { return nil }
        let px = Int((points * max(scale, 2)).rounded())
        if let c = cache[px] { return c }
        guard let src = CGImageSourceCreateWithURL(url as CFURL, nil) else { return nil }
        let opts: [CFString: Any] = [kCGImageSourceCreateThumbnailFromImageAlways: true, kCGImageSourceThumbnailMaxPixelSize: px,
                                     kCGImageSourceCreateThumbnailWithTransform: true, kCGImageSourceShouldCacheImmediately: true]
        guard let cg = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary) else { return nil }
        let img = NSImage(cgImage: cg, size: NSSize(width: points, height: points))
        cache[px] = img
        return img
    }
}

struct AppIconTile: View {
    var size: CGFloat = 38
    @Environment(\.displayScale) private var scale
    var body: some View {
        if let img = AppIconArt.image(points: size, scale: scale) {
            Image(nsImage: img).resizable().interpolation(.high).frame(width: size, height: size)
        } else {
            LogoMark(size: size * 0.9).frame(width: size, height: size)   // modo snapshot, sem bundle
        }
    }
}

// MARK: - Componentes

struct Chip: View {
    var text: String
    var tint: Color = Theme.dim
    var body: some View {
        Text(text)
            .font(.system(size: 10.5, weight: .medium))
            .foregroundStyle(tint)
            .padding(.horizontal, 7).padding(.vertical, 2.5)
            .background(tint.opacity(0.13), in: Capsule())
    }
}

struct PressStyle: ButtonStyle {
    var prominent = false
    func makeBody(configuration: Configuration) -> some View { PressBody(configuration: configuration, prominent: prominent) }

    private struct PressBody: View {
        let configuration: ButtonStyleConfiguration
        let prominent: Bool
        @Environment(\.isEnabled) private var enabled
        var body: some View {
            configuration.label
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(prominent ? Theme.onBrand : Theme.text)
                .padding(.horizontal, 11).padding(.vertical, 5.5)
                .background(prominent ? Theme.brand : Theme.raised, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).stroke(prominent ? .clear : Theme.line))
                .opacity(enabled ? 1 : 0.4)
                .scaleEffect(configuration.isPressed ? 0.95 : 1)
                .animation(.spring(response: 0.25, dampingFraction: 0.6), value: configuration.isPressed)
        }
    }
}

/// Thumbnail pequeno de arquivo (imagem/SVG), com cache.
final class ThumbCache {
    static let shared = ThumbCache()
    private let cache = NSCache<NSString, NSImage>()
    func image(for path: String, size: CGFloat = 96) -> NSImage? {
        if let c = cache.object(forKey: path as NSString) { return c }
        guard let img = NSImage(contentsOfFile: path), img.size.width > 0 else { return nil }
        let ratio = min(size / img.size.width, size / img.size.height, 1)
        let target = NSSize(width: max(1, img.size.width * ratio), height: max(1, img.size.height * ratio))
        let out = NSImage(size: target)
        out.lockFocus(); img.draw(in: NSRect(origin: .zero, size: target)); out.unlockFocus()
        cache.setObject(out, forKey: path as NSString)
        return out
    }
}

struct ThumbView: View {
    let path: String
    @State private var img: NSImage?
    var body: some View {
        Group {
            if let img { Image(nsImage: img).resizable().scaledToFit() } else { Color.clear }
        }
        .task(id: path) { img = await Task.detached { ThumbCache.shared.image(for: path) }.value }
    }
}
