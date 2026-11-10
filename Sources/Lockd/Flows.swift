import AppKit
import SwiftUI
import UniformTypeIdentifiers
import LockdCore

/// O que acontece quando algo é detectado: salvar, avisar, permitir desfazer.
enum Flows {
    nonisolated(unsafe) static var onSaved: (() -> Void)?

    static func handleSecrets(_ dets: [Detection], source: String?) {
        let ctx = ProjectTracker.shared.current()
        let sure = dets.filter(\.confident), unsure = dets.filter { !$0.confident }

        var saved: [Item] = [], dupes = 0
        var failure: Error?
        for d in sure {
            do {
                let r = try Store.shared.saveSecret(d, project: ctx.project, source: source)
                if r.isNew { saved.append(r.item) } else { dupes += 1 }
            } catch { failure = error; NSLog("[lockd] couldn't save %@: %@", d.envName, String(describing: error)) }
        }
        if let failure, saved.isEmpty {
            ToastController.shared.show(ToastModel(icon: "exclamationmark.triangle.fill", title: "Couldn't save the key",
                                                   subtitle: failure.localizedDescription, tint: Theme.danger, duration: 8))
            return
        }

        if !saved.isEmpty {
            onSaved?()
            if saved.count == 1, let it = saved.first {
                toastSaved(title: "Saved \(it.service ?? "secret") \(it.type)",
                           subtitle: it.name, items: saved, project: ctx.project, icon: "lock.fill")
            } else {
                toastSaved(title: "Saved \(saved.count) secrets",
                           subtitle: saved.prefix(3).map(\.name).joined(separator: ", ") + (saved.count > 3 ? "…" : ""),
                           items: saved, project: ctx.project, icon: "lock.fill")
            }
        } else if dupes > 0 {
            ToastController.shared.show(ToastModel(icon: "checkmark.seal.fill", title: "Already in Lockd",
                                                   subtitle: "Same key, nothing duplicated", tint: Theme.dim, duration: 2.5))
        }

        if saved.isEmpty, dupes == 0, let u = unsure.first {
            ToastController.shared.show(ToastModel(
                icon: "questionmark.key.fill", title: "Looks like a key", subtitle: "\(Detector.preview(u.value)) · save it?",
                tint: Theme.amber,
                actions: [ToastAction(label: "Save", prominent: true) {
                    if let r = try? Store.shared.saveSecret(u, project: ctx.project, source: source), r.isNew {
                        Store.shared.update(id: r.item.id) { $0.name = "UNNAMED_KEY"; $0.service = nil; $0.type = "Secret" }
                        onSaved?()
                    }
                }], duration: 7))
        }
    }

    static func toastSaved(title: String, subtitle: String, items: [Item], project: String?, icon: String, thumb: String? = nil) {
        var m = ToastModel(icon: icon, title: title, subtitle: subtitle)
        m.thumbPath = thumb
        m.currentProject = project ?? "Inbox"
        m.changeProject = { newProject in
            for it in items {
                if it.isFile { if let cur = Store.shared.item(id: it.id) { Ingestor.reassign(cur, to: newProject) } }
                else { Store.shared.update(id: it.id) { $0.project = newProject } }
            }
            var again = m; again.currentProject = newProject ?? "Inbox"; again.changeProject = nil
            again.title = "Moved to \(newProject ?? "Inbox")"; again.icon = "arrow.right.circle.fill"; again.duration = 2.2; again.actions = []
            ToastController.shared.show(again)
        }
        m.actions = [ToastAction(label: "Undo") {
            for it in items { if it.isFile { Ingestor.undo(it) } else if it.type == RecoveryCodes.type { RecoveryCodes.undo(it) } else { Store.shared.remove(id: it.id) } }
        }]
        ToastController.shared.show(m)
    }

    // MARK: Arquivos

    /// Arquivo novo apareceu em Downloads/Desktop.
    static func handleWatchedFile(_ url: URL) {
        let verdict = FileClassifier.classify(url)
        guard !verdict.ignore else { return }
        let ctx = ProjectTracker.shared.current()
        let byName = Store.shared.matchProject(in: url.deletingPathExtension().lastPathComponent)
        let project = byName ?? ctx.project
        // Por que esse projeto: deixa a sugestão explicável ("você está em X").
        let why = byName.map { "name matches \($0)" } ?? ctx.project.map { "you're working on \($0)" } ?? "no project detected → Inbox"
        let image = ["Logo", "Vector", "Image"].contains(verdict.type)

        if verdict.confident {
            ingest([url], project: project, verdicts: [url: verdict], why: why)
        } else {
            var m = ToastModel(icon: "photo.badge.plus", title: url.lastPathComponent,
                               subtitle: "Looks like \(verdict.type.lowercased()) · \(why)", tint: Theme.cyan,
                               actions: [ToastAction(label: "File it", prominent: true) { ingest([url], project: project, verdicts: [url: verdict], why: why) }],
                               duration: 10)
            if image { m.thumbPath = url.path }
            ToastController.shared.show(m)
        }
    }

    /// Arrastar/soltar manual: sempre organiza.
    static func ingestDropped(_ urls: [URL], project: String?) {
        var all: [URL] = []
        for u in urls {
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: u.path, isDirectory: &isDir), isDir.boolValue {
                let kids = FileManager.default.enumerator(at: u, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles])
                while let k = kids?.nextObject() as? URL, all.count < 300 {
                    if (try? k.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true { all.append(k) }
                }
            } else { all.append(u) }
        }
        var verdicts: [URL: FileVerdict] = [:]
        for u in all {
            var v = FileClassifier.classify(u)
            if v.ignore { v = FileVerdict(category: "Other", type: u.pathExtension.isEmpty ? "File" : u.pathExtension.uppercased(),
                                          kind: .asset, confident: true, ignore: false) }
            verdicts[u] = v
        }
        ingest(all, project: project, verdicts: verdicts)
    }

    static func ingest(_ urls: [URL], project: String?, verdicts: [URL: FileVerdict], why: String? = nil) {
        var moved: [Item] = [], dupes = 0
        for u in urls {
            do { moved.append(try Ingestor.ingest(u, project: project, verdict: verdicts[u])) }
            catch IngestError.duplicate { dupes += 1 }
            catch { continue }
        }
        if !moved.isEmpty {
            onSaved?()
            if moved.count == 1, let it = moved.first {
                let colors = (it.colors ?? []).prefix(3).joined(separator: " ")
                toastSaved(title: "Filed \(it.type.lowercased()): \(it.name)",
                           subtitle: [it.kind == .secret ? "Encrypted · original file is in the Trash" : colors.isEmpty ? "→ ~/Lockd/\(Ingestor.folderName(project))" : colors, why].compactMap { $0 }.joined(separator: " · "),
                           items: moved, project: project, icon: it.kind == .secret ? "key.fill" : it.kind == .credential ? "lock.doc.fill" : "photo.fill",
                           thumb: ["Logo", "Vector", "Image"].contains(it.type) ? it.path : nil)
            } else {
                toastSaved(title: "Filed \(moved.count) files", subtitle: "→ ~/Lockd/\(Ingestor.folderName(project))",
                           items: moved, project: project, icon: "tray.full.fill")
            }
        } else if dupes > 0 {
            ToastController.shared.show(ToastModel(icon: "checkmark.seal.fill", title: "Already in Lockd", tint: Theme.dim, duration: 2.5))
        }
    }
}

enum DropIngest {
    static func handle(_ providers: [NSItemProvider], project: String?) {
        var urls: [URL] = []
        let group = DispatchGroup()
        for p in providers {
            group.enter()
            p.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, _ in
                if let d = item as? Data, let u = URL(dataRepresentation: d, relativeTo: nil) { DispatchQueue.main.async { urls.append(u) } }
                group.leave()
            }
        }
        group.notify(queue: .main) { Flows.ingestDropped(urls, project: project) }
    }
}
