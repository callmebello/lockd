import AppKit

/// Ícone da barra de menu: o disco do logo com o MESMO "L" vazado. Imagem template (segue o tema da barra).
/// O L é "furado" com composição `.clear` em duas barras: sem regra par-ímpar, então o canto onde elas se encontram não fecha.
enum StatusIcon {
    static func make(points s: CGFloat = 18) -> NSImage {
        let img = NSImage(size: NSSize(width: s, height: s), flipped: false) { _ in
            guard let ctx = NSGraphicsContext.current else { return false }
            let d = s - 2
            let disc = NSRect(x: 1, y: 1, width: d, height: d)
            NSColor.black.setFill()
            NSBezierPath(ovalIn: disc).fill()

            // L do logo: barra vertical + pé, ~54% da altura do disco, traço ~15%
            let h = d * 0.56, w = d * 0.42, t = d * 0.17, r = t * 0.32
            let x = disc.midX - w / 2 + d * 0.03, y = disc.midY - h / 2
            ctx.compositingOperation = .clear
            NSBezierPath(roundedRect: NSRect(x: x, y: y, width: t, height: h), xRadius: r, yRadius: r).fill()
            NSBezierPath(roundedRect: NSRect(x: x, y: y, width: w, height: t), xRadius: r, yRadius: r).fill()
            ctx.compositingOperation = .sourceOver
            return true
        }
        img.isTemplate = true
        return img
    }
}
