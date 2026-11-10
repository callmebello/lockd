import SwiftUI
import AppKit
import LockdCore

/// Ler/copiar uma chave pela interface também passa pelo Touch ID (uma vez por sessão).
enum Unlock {
    static func value(of item: Item, reason: String, _ done: @escaping (String?) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                if !Vault.shared.isUnlocked { try Vault.shared.unlock(reason: reason) }
                let v = try Store.shared.secretValue(item)
                DispatchQueue.main.async { done(v) }
            } catch {
                DispatchQueue.main.async {
                    done(nil)
                    ToastController.shared.show(ToastModel(icon: "lock.fill", title: "Not unlocked",
                                                           subtitle: error.localizedDescription, duration: 3.5))
                }
            }
        }
    }
}

/// Regras do que o Claude pode fazer com esta chave.
struct AccessBlock: View {
    let item: Item
    @State private var programs = ""
    @State private var hosts = ""
    @State private var allowEnv = false
    @State private var confirmWildcard = false
    @State private var message: String?
    @State private var methods = ""
    @State private var paths = ""
    @State private var saving = false

    var body: some View {
        let pol = Policies.effective(item)
        VStack(alignment: .leading, spacing: 10) {
            Text("CLAUDE ACCESS").font(.system(size: 10, weight: .bold)).tracking(0.8).foregroundStyle(Theme.faint)
            HStack(spacing: 8) {
                Image(systemName: !Policies.rulesVerified(item) ? "hand.raised.fill" : "checkmark.shield.fill")
                    .foregroundStyle(!Policies.rulesVerified(item) ? Theme.amber : Theme.cyan)
                Text(Policies.rulesVerified(item) ? "Signed access rules. HTTP uses exact hosts; programs require advanced mode." : "Agent access is off until you review and sign these rules.")
                    .font(.system(size: 12)).foregroundStyle(Theme.dim)
            }
            if !Policies.rulesVerified(item) {
                Text("Rules missing or invalid. Agent access is off. Review and sign below.")
                    .font(.system(size: 12)).foregroundStyle(Theme.amber)
            }
            field("Programs it may run", $programs, "curl")
            field("Hosts it may reach", $hosts, "api.anthropic.com, abcd.supabase.co")
            field("HTTP methods (blank = all supported)", $methods, "GET, POST")
            field("HTTP path prefixes (blank = any path)", $paths, (item.service ?? "").lowercased() == "supabase" ? "/v1/projects/abcdefghijklmnopqrst  ← required: pin to your project ref" : "/v1/models, /v1/messages")
            Toggle("Allow .env / hosting: files become readable by your user and the agent", isOn: $allowEnv)
                .toggleStyle(.switch).tint(Theme.cyan).font(.system(size: 12.5))
            HStack(spacing: 8) {
                Button(saving ? "Saving rules…" : "Save rules (Touch ID)") { save() }.buttonStyle(PressStyle(prominent: true))
                Button("Use suggested defaults") {
                    var draft = item
                    draft.allowCommands = nil; draft.allowHosts = nil; draft.allowEnv = nil
                    load(Policies.proposed(draft)); methods = ""; paths = ""
                    message = "Suggestion only — sign to approve."
                }.buttonStyle(PressStyle())
                if let message { Text(message).font(.system(size: 11.5)).foregroundStyle(Theme.dim) }
            }
            Text("Use lockd_http with exact hosts. Programs are an optional advanced mode, off by default. Only validated curl is supported. Use exact hosts. For Supabase project APIs, add your exact project host (e.g. abcd.supabase.co); api.supabase.com covers management only. Wildcards require confirmation and may allow another tenant to receive the key. .env is off by default and a new destination requires fresh authentication.")
                .font(.system(size: 10.5)).foregroundStyle(Theme.faint)
        }
        .disabled(saving)
        .onAppear {
            load(Policies.rulesVerified(item) ? pol : Policies.proposed(item))
            if (item.allowHosts ?? []).contains(where: { $0.hasPrefix("*.") && !(item.confirmedWildcardHosts ?? []).contains($0) }) {
                message = "Unconfirmed wildcard hosts are disabled. Re-enter and confirm to enable."
            }
        }
        .alert("Confirmar curinga de host?", isPresented: $confirmWildcard) {
            Button("Cancelar", role: .cancel) { }
            Button("Confirmar e salvar", role: .destructive) { save(confirmedWildcard: true) }
        } message: {
            Text("qualquer inquilino deste serviço poderia receber a chave")
        }
    }

    private func load(_ p: Policy) {
        programs = p.commands.joined(separator: ", "); hosts = p.hosts.joined(separator: ", "); allowEnv = p.allowEnv
        methods = (item.allowedMethods ?? []).joined(separator: ", ")
        paths = (item.allowedPathPrefixes ?? []).joined(separator: ", ")
    }

    private func split(_ s: String) -> [String] {
        s.split(whereSeparator: { ",; \n".contains($0) }).map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty }
    }

    private func save(confirmedWildcard: Bool = false) {
        let wantedCmds = split(programs), wantedHosts = split(hosts)
        let cmds = wantedCmds.filter { $0 == "curl" }
        let hs = wantedHosts.filter(Policies.validPattern)
        let wildcards = hs.filter { $0.hasPrefix("*.") }
        if !wildcards.isEmpty && !confirmedWildcard { confirmWildcard = true; return }
        let dropped = (wantedCmds.count - cmds.count) + (wantedHosts.count - hs.count)
        let allowedMethods = split(methods).map { $0.uppercased() }
        let pathPrefixes = paths.split(whereSeparator: { ",; \n".contains($0) }).map(String.init)
        guard allowedMethods.allSatisfy({ ["GET", "POST", "PUT", "PATCH", "DELETE"].contains($0) }),
              pathPrefixes.allSatisfy({ $0.hasPrefix("/") && !$0.contains("..") && !$0.contains("%") }) else {
            message = "Invalid HTTP method or path prefix."; return
        }
        let env = allowEnv, expected = item
        saving = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try Store.shared.authorizeRules([expected.id], expected: [expected]) {
                    $0.allowCommands = cmds; $0.allowHosts = hs; $0.allowEnv = env; $0.confirmedWildcardHosts = wildcards
                    $0.allowedMethods = allowedMethods.isEmpty ? nil : allowedMethods
                    $0.allowedPathPrefixes = pathPrefixes.isEmpty ? nil : pathPrefixes
                }
                if !wildcards.isEmpty {
                    var entry = AuditEntry(tool: "policy_wildcard", status: "ok", project: expected.project,
                        secrets: [expected.name], detail: "qualquer inquilino deste serviço poderia receber a chave")
                    entry.hosts = wildcards; entry.approvedBy = "touch-id"; Audit.write(entry)
                }
                DispatchQueue.main.async { saving = false; message = dropped > 0 ? "Signed; ignored \(dropped) invalid entries." : "Rules signed." }
            } catch {
                DispatchQueue.main.async { saving = false; message = "Not signed: " + error.localizedDescription }
            }
        }
    }

    private func field(_ title: String, _ text: Binding<String>, _ prompt: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 11.5, weight: .medium)).foregroundStyle(Theme.dim)
            TextField(prompt, text: text).textFieldStyle(.plain).font(.system(size: 12.5, design: .monospaced))
                .padding(9).background(Theme.raised, in: RoundedRectangle(cornerRadius: 8)).overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.line))
        }
    }
}

/// Tudo que o Claude fez com as suas chaves.
struct ActivityView: View {
    @State private var rows: [AuditEntry] = []
    @State private var unlocked = Vault.shared.isUnlocked

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Activity").font(.system(size: 20, weight: .bold))
                Spacer()
                HStack(spacing: 6) {
                    Image(systemName: unlocked ? "lock.open.fill" : "lock.fill").foregroundStyle(unlocked ? Theme.cyan : Theme.dim)
                    Text(unlocked ? "Unlocked · \(Int(Vault.shared.unlockedRemaining / 60)) min left" : "Locked").font(.system(size: 12)).foregroundStyle(Theme.dim)
                    if unlocked { Button("Lock now") { Vault.shared.lockNow(); unlocked = false }.buttonStyle(PressStyle()) }
                }
            }
            .padding(.horizontal, 28).padding(.top, 22).padding(.bottom, 14)
            Divider().overlay(Theme.line)
            if rows.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "list.bullet.rectangle").font(.system(size: 28)).foregroundStyle(Theme.faint)
                    Text("Nothing yet").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.dim)
                    Text("Every time Claude uses a key, it shows up here.").font(.system(size: 11.5)).foregroundStyle(Theme.faint)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) { ForEach(rows) { row($0); Divider().overlay(Theme.line) } }
                }
            }
        }
        .background(Theme.bg)
        .onAppear(perform: reload)
        .onReceive(NotificationCenter.default.publisher(for: Store.didChange)) { _ in reload() }
    }

    private func reload() { rows = Audit.recent(limit: 200); unlocked = Vault.shared.isUnlocked }

    private func row(_ e: AuditEntry) -> some View {
        let tint: Color = e.status == "ok" ? Theme.cyan : e.status == "denied" ? Theme.amber : Theme.danger
        return HStack(alignment: .top, spacing: 12) {
            Image(systemName: e.status == "ok" ? "checkmark.circle.fill" : e.status == "denied" ? "hand.raised.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(tint).padding(.top, 2)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(e.tool).font(.system(size: 12.5, weight: .semibold, design: .monospaced)).foregroundStyle(Theme.text)
                    ForEach(e.secrets, id: \.self) { Chip(text: $0, tint: Theme.cyan) }
                    if let p = e.project { Chip(text: p) }
                }
                if let c = e.command { Text(c).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Theme.dim).lineLimit(2) }
                if let d = e.detail { Text(d).font(.system(size: 11.5)).foregroundStyle(tint).lineLimit(3) }
                if !e.contacted.isEmpty || !e.blocked.isEmpty {
                    HStack(spacing: 8) {
                        if !e.contacted.isEmpty { Text("reached \(e.contacted.joined(separator: ", "))").foregroundStyle(Theme.dim) }
                        if !e.blocked.isEmpty { Text("blocked \(e.blocked.joined(separator: ", "))").foregroundStyle(Theme.danger) }
                    }.font(.system(size: 11))
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text(e.date.formatted(date: .omitted, time: .shortened)).font(.system(size: 11.5)).foregroundStyle(Theme.dim)
                if let a = e.approvedBy { Text(a == "touch-id" ? "Touch ID" : "session").font(.system(size: 10.5)).foregroundStyle(Theme.faint) }
            }
        }
        .padding(.horizontal, 28).padding(.vertical, 12)
    }
}
