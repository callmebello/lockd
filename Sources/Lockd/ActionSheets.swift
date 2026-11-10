import SwiftUI
import AppKit
import UniformTypeIdentifiers
import LockdCore

// MARK: - Enviar à Vercel (ação do usuário: você escolhe, você aprova com Touch ID, o envio é um só)

struct VercelSendSheet: View {
    let project: String
    var onClose: () -> Void

    struct Row: Identifiable { let id: UUID; let name: String; let service: String?; var on: Bool }
    enum Phase { case form, sending, results([Broker.VercelSendResult]), error(String) }

    @State private var rows: [Row] = []
    @State private var vercelProject = ""
    @State private var team = ""
    @State private var targets: Set<String> = ["production", "preview", "development"]
    @State private var phase: Phase = .form
    @State private var hasToken = true

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "paperplane.fill").font(.system(size: 17)).foregroundStyle(Theme.cyan)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Send \(project) to Vercel").font(.system(size: 16, weight: .bold)).foregroundStyle(Theme.text)
                    Text("Adds the keys below as encrypted environment variables. One Touch ID for the whole send.").font(.system(size: 11.5)).foregroundStyle(Theme.dim)
                }
                Spacer()
                Button { onClose() } label: { Image(systemName: "xmark").font(.system(size: 11, weight: .bold)).foregroundStyle(Theme.dim) }.buttonStyle(.plain)
            }
            switch phase {
            case .form, .sending: form
            case .results(let r): results(r)
            case .error(let e): errorView(e)
            }
        }
        .padding(24).frame(width: 600).background(Theme.bg)
        .animation(.smooth(duration: 0.25), value: String(describing: phase))
        .onAppear(perform: load)
    }

    private var sending: Bool { if case .sending = phase { return true }; return false }

    private var form: some View {
        VStack(alignment: .leading, spacing: 14) {
            if !hasToken {
                HStack(spacing: 10) {
                    Image(systemName: "key.slash").foregroundStyle(Theme.amber)
                    Text("No Vercel token in Lockd yet. Create one at vercel.com/account/tokens and copy it; Lockd saves it.").font(.system(size: 12.5)).foregroundStyle(Theme.dim)
                }.padding(12).background(Theme.amber.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
            }
            HStack(spacing: 10) {
                field("Vercel project (name or id)", $vercelProject, "my-app  or  prj_abc123")
                field("Team id (optional)", $team, "team_…")
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("ENVIRONMENTS").font(.system(size: 10, weight: .bold)).tracking(0.8).foregroundStyle(Theme.faint)
                HStack(spacing: 8) {
                    ForEach(["production", "preview", "development"], id: \.self) { t in
                        Button { if targets.contains(t) { targets.remove(t) } else { targets.insert(t) } } label: {
                            Text(t.capitalized).font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(targets.contains(t) ? Theme.onBrand : Theme.text)
                                .padding(.horizontal, 12).padding(.vertical, 6)
                                .background(targets.contains(t) ? Theme.brand : Theme.raised, in: Capsule())
                        }.buttonStyle(.plain)
                    }
                }
            }
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("KEYS (\(rows.filter(\.on).count) of \(rows.count))").font(.system(size: 10, weight: .bold)).tracking(0.8).foregroundStyle(Theme.faint)
                    Spacer()
                    Button(rows.allSatisfy(\.on) ? "None" : "All") { let v = !rows.allSatisfy(\.on); for i in rows.indices { rows[i].on = v } }.buttonStyle(.plain).font(.system(size: 11.5)).foregroundStyle(Theme.dim)
                }
                ScrollView {
                    VStack(spacing: 4) {
                        ForEach($rows) { $r in
                            HStack(spacing: 10) {
                                Toggle("", isOn: $r.on).labelsHidden().toggleStyle(.checkbox)
                                Text(r.name).font(.system(size: 12.5, weight: .medium, design: .monospaced)).foregroundStyle(Theme.text)
                                if let s = r.service { Chip(text: s, tint: Theme.cyan) }
                                Spacer()
                            }.padding(.horizontal, 10).padding(.vertical, 6)
                        }
                        if rows.isEmpty { Text("This project has no keys yet.").font(.system(size: 12.5)).foregroundStyle(Theme.dim).padding(16) }
                    }
                }
                .frame(height: 170).background(Theme.panel, in: RoundedRectangle(cornerRadius: 10)).overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.line))
            }
            HStack {
                Text("Values go straight from your Mac to Vercel's API over HTTPS. Existing variables with the same name are replaced.")
                    .font(.system(size: 11)).foregroundStyle(Theme.faint)
                Spacer()
                Button("Cancel") { onClose() }.buttonStyle(PressStyle())
                Button { send() } label: { HStack(spacing: 6) { if sending { ProgressView().controlSize(.small) }; Text(sending ? "Sending…" : "Send with Touch ID") } }
                    .buttonStyle(PressStyle(prominent: true))
                    .disabled(!canSend)
            }
        }
    }

    private var canSend: Bool {
        hasToken && !sending && !vercelProject.trimmingCharacters(in: .whitespaces).isEmpty && !targets.isEmpty && rows.contains(where: \.on)
    }

    private func results(_ r: [Broker.VercelSendResult]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            let okCount = r.filter(\.ok).count
            HStack(spacing: 10) {
                Image(systemName: okCount == r.count ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.system(size: 22)).foregroundStyle(okCount == r.count ? Theme.cyan : Theme.amber)
                Text("\(okCount) of \(r.count) sent to Vercel").font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(r) { x in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: x.ok ? "checkmark" : "xmark").font(.system(size: 11, weight: .bold)).foregroundStyle(x.ok ? Theme.cyan : Theme.danger).frame(width: 14)
                            Text(x.name).font(.system(size: 12.5, weight: .medium, design: .monospaced)).foregroundStyle(Theme.text)
                            Text(x.detail).font(.system(size: 11.5)).foregroundStyle(Theme.dim)
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(height: 150)
            HStack { Spacer(); Button("Done") { onClose() }.buttonStyle(PressStyle(prominent: true)) }
        }
    }

    private func errorView(_ e: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(e).font(.system(size: 13)).foregroundStyle(Theme.amber)
            HStack { Spacer(); Button("Back") { phase = .form }.buttonStyle(PressStyle()); Button("Close") { onClose() }.buttonStyle(PressStyle()) }
        }
    }

    private func field(_ title: String, _ text: Binding<String>, _ prompt: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.system(size: 11.5, weight: .medium)).foregroundStyle(Theme.dim)
            TextField(prompt, text: text).textFieldStyle(.plain).font(.system(size: 13, design: .monospaced)).padding(10)
                .background(Theme.raised, in: RoundedRectangle(cornerRadius: 9)).overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.line))
        }
    }

    private func load() {
        let all = Store.shared.items
        hasToken = all.contains { $0.kind == .secret && ($0.name.uppercased().contains("VERCEL") || ($0.service ?? "").lowercased() == "vercel") }
        rows = all.filter { $0.kind == .secret && $0.project == project && isEnvName($0.name) && !$0.name.uppercased().contains("VERCEL") && ($0.service ?? "").lowercased() != "vercel" }
            .sorted { $0.name < $1.name }.map { Row(id: $0.id, name: $0.name, service: $0.service, on: true) }
        let link = Store.shared.link(for: project)
        vercelProject = link?.vercelProjectId ?? ""; team = link?.vercelTeamId ?? ""
    }

    private func send() {
        guard let broker = AppDelegate.shared?.broker else { return }
        phase = .sending
        let names = rows.filter(\.on).map(\.name), pid = vercelProject.trimmingCharacters(in: .whitespaces)
        let tm = team.trimmingCharacters(in: .whitespaces).isEmpty ? nil : team.trimmingCharacters(in: .whitespaces)
        let tg = ["production", "preview", "development"].filter { targets.contains($0) }
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let r = try broker.sendToVercel(project: project, names: names, vercelProject: pid, team: tm, targets: tg)
                DispatchQueue.main.async {
                    if r.contains(where: \.ok) {   // lembra o vínculo para a próxima vez
                        let old = Store.shared.link(for: project)
                        Store.shared.setLink(ProjectLink(path: old?.path ?? "", vercelProjectId: pid, vercelTeamId: tm), for: project)
                    }
                    withAnimation { phase = .results(r) }
                }
            } catch { DispatchQueue.main.async { withAnimation { phase = .error(error.localizedDescription) } } }
        }
    }
}

// MARK: - Backup cifrado

enum BackupMode: String, Identifiable { case export, importing; var id: String { rawValue } }

struct BackupSheet: View {
    let mode: BackupMode
    var onClose: () -> Void
    @State private var pass = ""
    @State private var confirm = ""
    @State private var message: String?
    @State private var busy = false
    @State private var file: URL?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: mode == .export ? "square.and.arrow.up" : "square.and.arrow.down").font(.system(size: 17)).foregroundStyle(Theme.cyan)
                Text(mode == .export ? "Export encrypted backup" : "Import backup").font(.system(size: 16, weight: .bold)).foregroundStyle(Theme.text)
                Spacer()
                Button { onClose() } label: { Image(systemName: "xmark").font(.system(size: 11, weight: .bold)).foregroundStyle(Theme.dim) }.buttonStyle(.plain)
            }
            if mode == .export {
                Text("Your keys are sealed to this Mac's Secure Enclave, so a lost or replaced Mac would lose them. This file holds the same keys encrypted with a passphrase you choose. There is no way to recover it if you forget the passphrase. Logos and other files already live in ~/Lockd.")
                    .font(.system(size: 12)).foregroundStyle(Theme.dim)
            } else {
                Text("Pick a .lockdbackup file and enter its passphrase. Keys already in Lockd are skipped. Agent access stays off until you sign each key's rules again.")
                    .font(.system(size: 12)).foregroundStyle(Theme.dim)
                HStack {
                    Button("Choose file…") { choose() }.buttonStyle(PressStyle())
                    if let f = file { Text(f.lastPathComponent).font(.system(size: 12, design: .monospaced)).foregroundStyle(Theme.text) }
                }
            }
            secure("Passphrase (12+ characters)", $pass)
            if mode == .export { secure("Repeat passphrase", $confirm) }
            if let message { Text(message).font(.system(size: 12)).foregroundStyle(message.hasPrefix("✓") ? Theme.cyan : Theme.amber) }
            HStack {
                Spacer()
                Button("Close") { onClose() }.buttonStyle(PressStyle())
                Button { run() } label: { HStack(spacing: 6) { if busy { ProgressView().controlSize(.small) }; Text(mode == .export ? "Export…" : "Import") } }
                    .buttonStyle(PressStyle(prominent: true)).disabled(!canRun)
            }
        }
        .padding(24).frame(width: 520).background(Theme.bg)
    }

    private var canRun: Bool {
        !busy && pass.count >= (mode == .export ? 12 : 1) && (mode == .importing ? file != nil : confirm == pass)
    }

    private func secure(_ title: String, _ text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.system(size: 11.5, weight: .medium)).foregroundStyle(Theme.dim)
            SecureField("", text: text).textFieldStyle(.plain).font(.system(size: 13)).padding(10)
                .background(Theme.raised, in: RoundedRectangle(cornerRadius: 9)).overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.line))
        }
    }

    private func choose() {
        let p = NSOpenPanel(); p.canChooseFiles = true; p.canChooseDirectories = false; p.allowsMultipleSelection = false
        if p.runModal() == .OK { file = p.url }
    }

    private func run() {
        let passphrase = pass
        if mode == .export {
            let panel = NSSavePanel()
            let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"
            panel.nameFieldStringValue = "Lockd-\(f.string(from: Date())).lockdbackup"
            panel.allowedContentTypes = [UTType(filenameExtension: "lockdbackup") ?? .data]
            guard panel.runModal() == .OK, let url = panel.url else { return }
            busy = true; message = nil
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    if !Vault.shared.isUnlocked { try Vault.shared.unlock(reason: "Export an encrypted backup of your Lockd keys") }
                    let n = try Backup.export(passphrase: passphrase, to: url)
                    DispatchQueue.main.async { busy = false; message = "✓ \(n) key\(n == 1 ? "" : "s") saved to \(url.lastPathComponent)"; pass = ""; confirm = "" }
                } catch { DispatchQueue.main.async { busy = false; message = error.localizedDescription } }
            }
        } else if let url = file {
            busy = true; message = nil
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let r = try Backup.importBackup(from: url, passphrase: passphrase)
                    DispatchQueue.main.async { busy = false; message = "✓ " + r.summary; pass = "" }
                } catch { DispatchQueue.main.async { busy = false; message = error.localizedDescription } }
            }
        }
    }
}

// MARK: - Vários itens selecionados

struct BulkView: View {
    let ids: Set<UUID>
    let projects: [String]
    @State private var confirmDelete = false
    @State private var confirmMove: ProjectChoice?
    struct ProjectChoice: Identifiable { let id = UUID(); let project: String? }

    private var items: [Item] { ids.compactMap { Store.shared.item(id: $0) } }
    private var revokes: Bool { items.contains { $0.kind == .secret && Policies.rulesVerified($0) } }

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "checklist").font(.system(size: 34)).foregroundStyle(Theme.cyan)
            Text("\(ids.count) items selected").font(.system(size: 18, weight: .bold)).foregroundStyle(Theme.text)
            Menu {
                Button("Inbox") { move(nil) }
                Divider()
                ForEach(Array(Set(projects + Store.shared.knownProjects())).sorted(), id: \.self) { p in Button(p) { move(p) } }
            } label: { Label("Move to project", systemImage: "folder") }
                .menuStyle(.button).buttonStyle(PressStyle()).fixedSize()
            Button(role: .destructive) { confirmDelete = true } label: { Label("Delete…", systemImage: "trash") }
                .buttonStyle(.plain).foregroundStyle(Theme.danger).font(.system(size: 13, weight: .semibold))
            Text("⌘-click to add, ⇧-click for a range, ⌘A for all.").font(.system(size: 11.5)).foregroundStyle(Theme.faint)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity).background(Theme.bg)
        .alert("Delete \(ids.count) items?", isPresented: $confirmDelete) {
            Button("Cancel", role: .cancel) { }
            Button("Delete", role: .destructive) { items.forEach { Ingestor.delete($0) } }
        } message: { Text("Keys are removed from Lockd. Files go to the Trash.") }
        .alert("Move and turn off agent access?", isPresented: Binding(get: { confirmMove != nil }, set: { if !$0 { confirmMove = nil } })) {
            Button("Cancel", role: .cancel) { confirmMove = nil }
            Button("Move", role: .destructive) { if let c = confirmMove { apply(c.project) }; confirmMove = nil }
        } message: { Text("Some keys have signed rules that include their project. After moving them, agents can't use them until you sign the rules again with Touch ID.") }
    }

    private func move(_ p: String?) { if revokes { confirmMove = ProjectChoice(project: p) } else { apply(p) } }

    private func apply(_ p: String?) {
        for it in items {
            if it.isFile { Ingestor.reassign(it, to: p) } else { Store.shared.update(id: it.id) { $0.project = p } }
        }
    }
}
