import SwiftUI
import AppKit
import LockdCore

struct ToastAction: Identifiable {
    let id = UUID()
    var label: String
    var prominent = false
    var run: () -> Void
}

struct ToastModel {
    var icon: String = "lock.fill"
    var title: String
    var subtitle: String = ""
    var tint: Color = Theme.cyan
    var actions: [ToastAction] = []
    /// Menu "mudar projeto": devolve o nome escolhido (nil = Inbox)
    var changeProject: ((String?) -> Void)?
    var currentProject: String?
    var duration: Double = 6
    /// Arquivo de imagem a mostrar no lugar do ícone do app (logo/asset reconhecido).
    var thumbPath: String?
}

final class ToastVM: ObservableObject {
    @Published var model: ToastModel
    @Published var visible = false
    @Published var progress: CGFloat = 1
    @Published var hovering = false { didSet { onHover?(hovering) } }
    var onHover: ((Bool) -> Void)?
    var onClose: (() -> Void)?
    init(_ m: ToastModel) { model = m }
}

struct ToastView: View {
    @ObservedObject var vm: ToastVM
    @State private var drag: CGFloat = 0

    var body: some View {
        let m = vm.model
        HStack(alignment: .center, spacing: 11) {
            if let t = m.thumbPath {
                ThumbView(path: t).padding(5).frame(width: 38, height: 38)
                    .background(Color.white.opacity(0.9), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).stroke(Theme.line))
            } else { AppIconTile(size: 38) }

            VStack(alignment: .leading, spacing: 1.5) {
                Text(m.title).font(.system(size: 13, weight: .semibold)).foregroundStyle(.primary).lineLimit(1)
                if !m.subtitle.isEmpty {
                    Text(m.subtitle).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 8)

            HStack(spacing: 6) {
                if let change = m.changeProject {
                    Menu {
                        Button("Inbox") { change(nil) }
                        Divider()
                        ForEach(Store.shared.knownProjects(), id: \.self) { p in Button(p) { change(p) } }
                    } label: {
                        HStack(spacing: 3) {
                            Text(m.currentProject ?? "Inbox").lineLimit(1)
                            Image(systemName: "chevron.up.chevron.down").font(.system(size: 7.5, weight: .bold))
                        }
                        .font(.system(size: 11.5, weight: .medium)).foregroundStyle(.secondary)
                        .padding(.horizontal, 9).padding(.vertical, 5)
                        .background(Color.primary.opacity(0.07), in: Capsule())
                    }
                    .menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).fixedSize()
                }
                ForEach(m.actions) { a in
                    Button(a.label) { a.run(); vm.onClose?() }
                        .buttonStyle(.plain)
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(a.prominent ? Theme.cyan : Color.primary)
                        .padding(.horizontal, 10).padding(.vertical, 5)
                        .background(Color.primary.opacity(0.07), in: Capsule())
                }
            }
        }
        .padding(.horizontal, 13).padding(.vertical, 11)
        .frame(width: 400)
        .lockdGlass(radius: 22)
        .shadow(color: .black.opacity(0.12), radius: 16, y: 6)
        .overlay(alignment: .topLeading) { closeButton.offset(x: -7, y: -7) }
        .padding(22)
        .offset(x: (vm.visible ? 0 : 60) + max(0, drag))
        .opacity((vm.visible ? 1 : 0) * (1 - min(Double(max(0, drag)) / 260, 0.7)))
        .simultaneousGesture(
            DragGesture(minimumDistance: 10)
                .onChanged { drag = $0.translation.width }
                .onEnded { v in
                    if v.translation.width > 70 || v.predictedEndTranslation.width > 170 { vm.onClose?() }
                    else { withAnimation(.spring(response: 0.35, dampingFraction: 0.75)) { drag = 0 } }
                }
        )
        .animation(.spring(response: 0.45, dampingFraction: 0.82), value: vm.visible)
        .onHover { vm.hovering = $0 }
    }

    /// "x" como nas notificações do Mac: aparece ao passar o mouse.
    private var closeButton: some View {
        Button { vm.onClose?() } label: {
            Image(systemName: "xmark").font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary)
                .frame(width: 20, height: 20).background(.regularMaterial, in: Circle()).overlay(Circle().stroke(Theme.line))
        }
        .buttonStyle(.plain)
        .opacity(vm.hovering ? 1 : 0).scaleEffect(vm.hovering ? 1 : 0.5)
        .animation(.spring(response: 0.28, dampingFraction: 0.7), value: vm.hovering)
        .help("Dismiss")
    }
}

final class ToastPanel: NSPanel {
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

final class ToastController {
    static let shared = ToastController()
    private var panel: ToastPanel?
    private var vm: ToastVM?
    private var timer: Timer?
    private var remaining: Double = 0
    private var total: Double = 0

    func show(_ model: ToastModel) {
        DispatchQueue.main.async { self.present(model) }
    }

    private func present(_ model: ToastModel) {
        timer?.invalidate()
        let vm = ToastVM(model)
        vm.onClose = { [weak self] in self?.dismiss() }
        vm.onHover = { [weak self] h in h ? self?.timer?.invalidate() : self?.startTimer() }

        let host = NSHostingView(rootView: ToastView(vm: vm))
        host.frame = NSRect(origin: .zero, size: host.fittingSize)

        let p = panel ?? ToastPanel(contentRect: host.frame, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        p.contentView = host
        p.setContentSize(host.fittingSize)
        p.isOpaque = false; p.backgroundColor = .clear; p.hasShadow = false
        p.level = .statusBar; p.isFloatingPanel = true; p.hidesOnDeactivate = false
        p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        if let screen = NSScreen.main {
            let f = screen.visibleFrame, s = p.frame.size
            p.setFrameOrigin(NSPoint(x: f.maxX - s.width + 8, y: f.maxY - s.height + 8))
        }
        p.orderFrontRegardless()
        panel = p; self.vm = vm
        DispatchQueue.main.async { vm.visible = true }

        total = model.duration; remaining = total; vm.progress = 1
        startTimer()
    }

    private func startTimer() {
        timer?.invalidate()
        let step = 0.05
        timer = Timer.scheduledTimer(withTimeInterval: step, repeats: true) { [weak self] t in
            guard let self, let vm = self.vm else { t.invalidate(); return }
            self.remaining -= step
            if self.remaining <= 0 { t.invalidate(); self.dismiss() }
        }
    }

    func dismiss() {
        timer?.invalidate()
        vm?.visible = false
        let p = panel
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { [weak self] in
            if self?.vm?.visible == false { p?.orderOut(nil) }
        }
    }
}
