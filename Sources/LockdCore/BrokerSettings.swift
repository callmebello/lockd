import Foundation

public enum BrokerSettings {
    /// Preferência do app, desligada por padrão. Os testes não alteram UserDefaults real.
    public static var programsEnabled: Bool {
        get {
            if ProcessInfo.processInfo.environment["LOCKD_HOME"] != nil { return testProgramsEnabled }
            return UserDefaults.standard.bool(forKey: "allowAdvancedPrograms")
        }
        set {
            if ProcessInfo.processInfo.environment["LOCKD_HOME"] != nil { testProgramsEnabled = newValue }
            else { UserDefaults.standard.set(newValue, forKey: "allowAdvancedPrograms") }
        }
    }
    private static var testProgramsEnabled = false
}
