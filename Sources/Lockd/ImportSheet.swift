import SwiftUI
import AppKit
import LockdCore

struct RootChoice: Identifiable { let id = UUID(); var url: URL; var on: Bool }

final class ScanModel: ObservableObject {
    enum Phase { case choose, scanning, review, done(ImportResult) }
    @Published var phase: Phase = .choose
    @Published var roots: [RootChoice] = ProjectScanner.defaultRoots().map { RootChoice(url: $0, on: true) }
    @Published var projects: [ScannedProject] = []
    @Published var current = ""
    private var token = UUID()

    init(preloaded: ScannedProject? = nil) { if let p = preloaded { projects = [p]; phase = .review } }

    var selectedCount: Int { projects.reduce(0) { $0 + $1.keys.filter(\.selected).count + $1.assets.filter(\.selected).count } }

    func addFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true; panel.canChooseFiles = false; panel.allowsMultipleSelection = true
        panel.prompt = "Add"; panel.message = "Folders that contain your projects"
        if panel.runModal() == .OK { for u in panel.urls where !roots.contains(where: { $0.url == u }) { roots.append(RootChoice(url: u, on: true)) } }
    }

    func scan() {
        let t = UUID(); token = t; phase = .scanning; current = ""
        let chosen = roots.filter(\.on).map(\.url)
        DispatchQueue.global(qos: .userInitiated).async {
            let found = ProjectScanner.scan(roots: chosen, progress: { name in DispatchQueue.main.async { if self.token == t { self.current = name } } })
            DispatchQueue.main.async { guard self.token == t else { return }; self.projects = found; self.phase = .review }
        }
    }

    func cancel() { token = UUID(); phase = .choose }

    func setProject(_ i: Int, _ on: Bool) {
        for k in projects[i].keys.indices where !projects[i].keys[k].alreadyInLockd { projects[i].keys[k].selected = on }
        for a in projects[i].assets.indices { projects[i].assets[a].selected = on }
    }

    func runImport() {
        let snapshot = projects
        let r = ProjectImporter.importProjects(snapshot)
        phase = .done(r)
    }
}

struct ImportSheet: View {
    @StateObject private var model: ScanModel
    var onClose: () -> Void
    init(model: ScanModel, onClose: @escaping () -> Void) { _model = StateObject(wrappedValue: model); self.onClose = onClose }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Theme.line)
            Group {
                switch model.phase {
                case .choose: choose
                case .scanning: scanning
                case .review: review
                case .done(let r): done(r)
                }
            }
            .transition(.opacity.combined(with: .offset(y: 8)))
        }
        .frame(width: 720, height: 600)
        .background(Theme.bg)
        .animation(.smooth(duration: 0.25), value: String(describing: model.phase))
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "tray.and.arrow.down.fill").font(.system(size: 18)).foregroundStyle(Theme.cyan)
            VStack(alignment: .leading, spacing: 2) {
                Text("Import from your projects").font(.system(size: 16, weight: .bold)).foregroundStyle(Theme.text)
                Text("Finds .env keys and brand assets you already have. Nothing leaves your Mac and your files stay where they are.")
                    .font(.system(size: 11.5)).foregroundStyle(Theme.dim)
            }
            Spacer()
            Button { onClose() } label: { Image(systemName: "xmark").font(.system(size: 11, weight: .bold)).foregroundStyle(Theme.dim) }.buttonStyle(.plain)
        }
        .padding(.horizontal, 22).padding(.vertical, 16)
    }

    // 1) escolher pastas
    private var choose: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Where do you keep your code?").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
            ScrollView {
                VStack(spacing: 6) {
                    ForEach($model.roots) { $r in
                        HStack(spacing: 10) {
                            Toggle("", isOn: $r.on).labelsHidden().toggleStyle(.checkbox)
                            Image(systemName: "folder.fill").foregroundStyle(Theme.cyan)
                            Text((r.url.path as NSString).abbreviatingWithTildeInPath).font(.system(size: 12.5, design: .monospaced)).foregroundStyle(Theme.text)
                            Spacer()
                        }
                        .padding(.horizontal, 12).padding(.vertical, 9).background(Theme.raised, in: RoundedRectangle(cornerRadius: 10))
                    }
                    if model.roots.isEmpty { Text("No usual code folders found. Add one.").font(.system(size: 12.5)).foregroundStyle(Theme.dim).padding(.top, 20) }
                }
            }
            Button { model.addFolder() } label: { Label("Add folder…", systemImage: "plus") }.buttonStyle(PressStyle())
            Text("Lockd reads .env files (not .env.example) and brand files such as logos, icons, SVGs and fonts. Keys are encrypted for your Mac's Secure Enclave before anything is saved; you review everything first.")
                .font(.system(size: 11.5)).foregroundStyle(Theme.faint)
            HStack { Spacer()
                Button("Cancel") { onClose() }.buttonStyle(PressStyle())
                Button("Scan") { model.scan() }.buttonStyle(PressStyle(prominent: true)).disabled(!model.roots.contains { $0.on })
            }
        }
        .padding(22)
    }

    // 2) varrendo
    private var scanning: some View {
        VStack(spacing: 14) {
            ProgressView().controlSize(.large)
            Text("Looking for projects…").font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
            Text(model.current).font(.system(size: 12, design: .monospaced)).foregroundStyle(Theme.dim).lineLimit(1)
            Button("Cancel") { model.cancel() }.buttonStyle(PressStyle())
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // 3) revisão
    private var review: some View {
        VStack(spacing: 0) {
            if model.projects.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "magnifyingglass").font(.system(size: 28)).foregroundStyle(Theme.faint)
                    Text("Nothing to import").font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.dim)
                    Text("No .env keys or brand files found in those folders.").font(.system(size: 12)).foregroundStyle(Theme.faint)
                    Button("Back") { model.phase = .choose }.buttonStyle(PressStyle())
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        ForEach(Array(model.projects.enumerated()), id: \.element.id) { i, p in projectCard(i, p).staggerIn(i) }
                    }.padding(18)
                }
                Divider().overlay(Theme.line)
                HStack {
                    Text("\(model.selectedCount) selected").font(.system(size: 12.5)).foregroundStyle(Theme.dim)
                    Spacer()
                    Button("Back") { model.phase = .choose }.buttonStyle(PressStyle())
                    Button("Import \(model.selectedCount) item\(model.selectedCount == 1 ? "" : "s")") { model.runImport() }
                        .buttonStyle(PressStyle(prominent: true)).disabled(model.selectedCount == 0)
                }.padding(.horizontal, 22).padding(.vertical, 14)
            }
        }
    }

    private func projectCard(_ i: Int, _ p: ScannedProject) -> some View {
        let allOn = p.keys.allSatisfy { $0.selected || $0.alreadyInLockd } && p.assets.allSatisfy(\.selected)
        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Toggle("", isOn: Binding(get: { allOn }, set: { model.setProject(i, $0) })).labelsHidden().toggleStyle(.checkbox)
                Image(systemName: "folder.fill").foregroundStyle(ProjectPalette.tint(p.name))
                VStack(alignment: .leading, spacing: 1) {
                    Text(p.name).font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
                    Text((p.path.path as NSString).abbreviatingWithTildeInPath).font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.faint).lineLimit(1)
                }
                Spacer()
                Text(p.summary).font(.system(size: 11.5)).foregroundStyle(Theme.dim)
            }
            ForEach(p.keys.indices, id: \.self) { k in
                let key = p.keys[k]
                HStack(spacing: 10) {
                    Toggle("", isOn: $model.projects[i].keys[k].selected).labelsHidden().toggleStyle(.checkbox).disabled(key.alreadyInLockd)
                    Image(systemName: "key.fill").font(.system(size: 11)).foregroundStyle(Theme.cyan).frame(width: 16)
                    Text(key.envName).font(.system(size: 12.5, weight: .medium, design: .monospaced)).foregroundStyle(Theme.text)
                    Chip(text: key.service, tint: Theme.cyan)
                    Spacer()
                    if key.alreadyInLockd { Chip(text: "already in Lockd") }
                    Text(key.preview).font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.faint)
                    Text(key.file).font(.system(size: 11)).foregroundStyle(Theme.faint)
                }.padding(.leading, 28).opacity(key.alreadyInLockd ? 0.6 : 1)
            }
            if !p.assets.isEmpty {
                ForEach(p.assets.indices, id: \.self) { a in
                    let asset = p.assets[a]
                    HStack(spacing: 10) {
                        Toggle("", isOn: $model.projects[i].assets[a].selected).labelsHidden().toggleStyle(.checkbox)
                        ThumbView(path: asset.url.path).frame(width: 24, height: 24)
                            .background(Theme.raised, in: RoundedRectangle(cornerRadius: 6)).padding(.leading, 0)
                        Text(asset.name).font(.system(size: 12.5)).foregroundStyle(Theme.text)
                        Chip(text: asset.type)
                        Spacer()
                        Text((asset.url.deletingLastPathComponent().path as NSString).abbreviatingWithTildeInPath.replacingOccurrences(of: (p.path.path as NSString).abbreviatingWithTildeInPath, with: "…"))
                            .font(.system(size: 11)).foregroundStyle(Theme.faint).lineLimit(1)
                    }.padding(.leading, 28)
                }
            }
        }
        .padding(14).background(Theme.panel, in: RoundedRectangle(cornerRadius: 14)).overlay(RoundedRectangle(cornerRadius: 14).stroke(Theme.line))
    }

    // 4) pronto
    private func done(_ r: ImportResult) -> some View {
        VStack(spacing: 14) {
            Image(systemName: "checkmark.circle.fill").font(.system(size: 44)).foregroundStyle(Theme.cyan).symbolEffect(.bounce, value: r.keys)
            Text(r.summary).font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.text)
            Text("Keys are sealed with your Mac's Secure Enclave. Agent access stays off until you sign each key's rules.")
                .font(.system(size: 12.5)).foregroundStyle(Theme.dim).multilineTextAlignment(.center).frame(maxWidth: 420)
            if r.failed > 0 { Text("\(r.failed) item\(r.failed == 1 ? "" : "s") couldn't be imported.").font(.system(size: 12)).foregroundStyle(Theme.amber) }
            Button("Done") { onClose() }.buttonStyle(PressStyle(prominent: true))
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Primeira abertura: o que o Lockd faz, o que ele vai pedir e um atalho para importar o que já existe.
struct WelcomeSheet: View {
    var onImport: () -> Void
    var onClose: () -> Void
    @State private var ax = AXIsProcessTrusted()

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 14) {
                AppIconTile(size: 56)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Welcome to Lockd").font(.system(size: 22, weight: .bold)).foregroundStyle(Theme.text)
                    Text("Your keys and brand files, organized by project.").font(.system(size: 13)).foregroundStyle(Theme.dim)
                }
            }
            VStack(alignment: .leading, spacing: 12) {
                step("doc.on.clipboard", "Copy a key and it saves itself", "Lockd spots the service and project. You get a notice with Undo.")
                step("photo.on.rectangle.angled", "Logos and fonts file themselves", "Download or drop them. They go to ~/Lockd/<Project>.")
                step("touchid", "Touch ID guards every use", "Saving is instant; opening a key or letting an agent use it needs your fingerprint.")
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("PERMISSIONS").font(.system(size: 10, weight: .bold)).tracking(0.8).foregroundStyle(Theme.faint)
                HStack(spacing: 10) {
                    Image(systemName: ax ? "checkmark.circle.fill" : "exclamationmark.triangle.fill").foregroundStyle(ax ? Theme.cyan : Theme.amber)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Accessibility").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                        Text("Lets Lockd see which project is open and paste with Return.").font(.system(size: 11.5)).foregroundStyle(Theme.dim)
                    }
                    Spacer()
                    if !ax { Button("Allow") { AXIsProcessTrustedWithOptions([kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary) }.buttonStyle(PressStyle()) }
                    Button { ax = AXIsProcessTrusted() } label: { Image(systemName: "arrow.clockwise") }.buttonStyle(.plain).foregroundStyle(Theme.dim)
                }
                Text("macOS will also ask once for access to Downloads and Desktop (to file logos) and for notifications (expiry alarms).")
                    .font(.system(size: 11.5)).foregroundStyle(Theme.faint)
            }
            .padding(14).background(Theme.panel, in: RoundedRectangle(cornerRadius: 12)).overlay(RoundedRectangle(cornerRadius: 12).stroke(Theme.line))
            HStack {
                Spacer()
                Button("Start fresh") { onClose() }.buttonStyle(PressStyle())
                Button { onImport() } label: { Label("Import my projects", systemImage: "tray.and.arrow.down") }.buttonStyle(PressStyle(prominent: true))
            }
        }
        .padding(28).frame(width: 560).background(Theme.bg)
    }

    private func step(_ icon: String, _ title: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).font(.system(size: 15)).foregroundStyle(Theme.cyan).frame(width: 26)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13.5, weight: .semibold)).foregroundStyle(Theme.text)
                Text(text).font(.system(size: 12)).foregroundStyle(Theme.dim)
            }
        }
    }
}
