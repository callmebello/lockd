import SwiftUI
import LockdCore

struct SecuritySettingsBlock: View {
    @State private var advanced = BrokerSettings.programsEnabled
    @State private var confirmAdvanced = false
    @State private var review: [Item] = []
    @State private var showReview = false
    @State private var busy = false
    @State private var message: String?
    @State private var keyIssue = Vault.shared.keyIssue
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("AGENT ACCESS").font(.system(size: 10, weight: .bold)).foregroundStyle(Theme.faint)
            Toggle("Permitir programas (avançado)", isOn: Binding(get: { advanced }, set: { value in
                if value { confirmAdvanced = true }
                else { advanced = false; BrokerSettings.programsEnabled = false }
            })).toggleStyle(.switch).tint(Theme.cyan)
            Text("Prefer lockd_http. Programs run as child processes with environment variables and broader file access. Filtering is not a guarantee against every disclosure.")
                .font(.system(size: 11)).foregroundStyle(Theme.dim)
            Button("Review and approve existing rules…") {
                review = Store.shared.items.filter { $0.kind == .secret }
                showReview = true
            }.buttonStyle(PressStyle()).disabled(busy)
            if let message { Text(message).font(.system(size: 11)).foregroundStyle(Theme.dim) }
            if let keyIssue {
                Text(keyIssue).font(.system(size: 12)).foregroundStyle(Theme.amber)
                Text("Keep the original key files. Recovery requires a prior portable backup; see docs/BACKUP-OPTIONS.md.")
                    .font(.system(size: 11)).foregroundStyle(Theme.dim)
            }
            Button("Check vault key status") {
                DispatchQueue.global().async {
                    _ = Vault.shared.prepare()
                    DispatchQueue.main.async { keyIssue = Vault.shared.keyIssue }
                }
            }.buttonStyle(PressStyle())
        }
        .alert("Enable advanced programs?", isPresented: $confirmAdvanced) {
            Button("Cancel", role: .cancel) { }
            Button("Accept risk and enable", role: .destructive) { advanced = true; BrokerSettings.programsEnabled = true }
        } message: { Text("This exposes lockd_run in MCP. Child processes receive secrets and can access files allowed by the sandbox. Use only with trusted configurations.") }
        .sheet(isPresented: $showReview) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Review rules before signing").font(.headline)
                Text("Approve only destinations you recognize. Existing unsigned/invalid rules stay inactive until you approve. Legacy ciphertexts will be migrated to v3. One authentication for this batch.").font(.caption)
                ScrollView {
                    ForEach(review) { item in
                        let policy = Policies.proposed(item)
                        VStack(alignment: .leading) {
                            Text(item.name + " · " + (item.project ?? "Inbox")).bold()
                            Text("Hosts: " + policy.hosts.joined(separator: ", "))
                            if policy.hosts.contains(where: { $0.hasPrefix("*.") }) {
                                Text("qualquer inquilino deste serviço poderia receber a chave").foregroundStyle(Theme.amber)
                            }
                            Text("Programs: " + policy.commands.joined(separator: ", ") + " · .env: " + (policy.allowEnv ? "ON — readable by the agent" : "OFF"))
                            Text("Methods: " + (item.allowedMethods?.joined(separator: ", ") ?? "all supported"))
                            Text("Paths: " + (item.allowedPathPrefixes?.joined(separator: ", ") ?? "any"))
                        }.font(.system(size: 12)).padding(.bottom, 8)
                    }
                }
                HStack {
                    Button("Cancel") { showReview = false }
                    Spacer()
                    Button("Approve reviewed rules with Touch ID") {
                        let snapshot = review
                        busy = true; showReview = false
                        DispatchQueue.global(qos: .userInitiated).async {
                            do {
                                try Store.shared.authorizeRules(snapshot.map(\.id), expected: snapshot)
                                DispatchQueue.main.async { busy = false; message = "Reviewed rules signed." }
                            } catch {
                                DispatchQueue.main.async { busy = false; message = "Not signed: " + error.localizedDescription }
                            }
                        }
                    }.disabled(review.isEmpty)
                }
            }.padding(24).frame(width: 620, height: 460)
        }
    }
}
