import SwiftUI
import AppKit
import LockdCore

extension Notification.Name {
    static let lockdImport = Notification.Name("lockd.import")        // userInfo["project"]: String?
    static let lockdAddSecret = Notification.Name("lockd.addSecret")  // userInfo["value"]: String
}

/// Enquanto você desenvolve: ao entrar num projeto que o Lockd conhece, avisa das chaves do .env que ainda não estão guardadas.
enum Suggestions {
    private static let snoozeHours: Double = 12

    static func projectChanged(_ project: String) {
        guard Prefs.suggestions, let link = Store.shared.link(for: project), !link.path.isEmpty else { return }
        let key = "suggest.\(project)"
        if let last = UserDefaults.standard.object(forKey: key) as? Date, Date().timeIntervalSince(last) < snoozeHours * 3600 { return }
        DispatchQueue.global(qos: .utility).async {
            let missing = ProjectScanner.missingKeys(project: project, link: link)
            guard !missing.isEmpty else { return }
            DispatchQueue.main.async {
                UserDefaults.standard.set(Date(), forKey: key)
                let names = missing.prefix(3).map(\.envName).joined(separator: ", ") + (missing.count > 3 ? "…" : "")
                ToastController.shared.show(ToastModel(
                    icon: "key.viewfinder", title: "\(project): \(missing.count) key\(missing.count == 1 ? "" : "s") not in Lockd",
                    subtitle: names + " · found in .env",
                    actions: [ToastAction(label: "Review", prominent: true) { AppDelegate.shared?.openLibrary(importProject: project) }],
                    duration: 12))
            }
        }
    }
}
