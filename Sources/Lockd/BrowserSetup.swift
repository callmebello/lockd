import AppKit
import LockdCore

/// Liga o Lockd ao Chrome: registra o host nativo, copia a extensão para um lugar estável e abre a página de extensões.
enum BrowserSetup {
    static var supportDir: URL { LockdPaths.support }

    @MainActor static func run() -> String {
        guard let ctl = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("lockdctl"),
              FileManager.default.isExecutableFile(atPath: ctl.path) else { return "lockdctl wasn't found inside the app." }
        guard let src = Bundle.main.resourceURL?.appendingPathComponent("chrome-extension"),
              FileManager.default.fileExists(atPath: src.path) else { return "This build doesn't include the browser extension." }
        let dest = supportDir.appendingPathComponent("chrome-extension")
        do {
            try? FileManager.default.removeItem(at: dest)
            try FileManager.default.copyItem(at: src, to: dest)
            let browsers = try BrowserInstaller.installHost(executable: ctl.path)
            guard !browsers.isEmpty else { return "No Chrome, Brave or Edge found. Install one, then try again." }
            NSWorkspace.shared.activateFileViewerSelecting([dest])
            let chrome = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.google.Chrome")
            if let chrome { NSWorkspace.shared.open([URL(string: "chrome://extensions")!], withApplicationAt: chrome, configuration: NSWorkspace.OpenConfiguration()) }
            return "Done for \(browsers.joined(separator: ", ")). In the extensions page: turn on Developer mode, click Load unpacked, and pick the folder that just opened (chrome-extension). Then restart the browser once."
        } catch { return "Couldn't set it up: \(error.localizedDescription)" }
    }
}
