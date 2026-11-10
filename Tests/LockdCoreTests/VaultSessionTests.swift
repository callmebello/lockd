import XCTest
@testable import LockdCore

final class VaultSessionTests: XCTestCase {
    private let itemID = UUID()
    private var home: String!
    private var previous: String?
    override func setUp() {
        previous = ProcessInfo.processInfo.environment["LOCKD_HOME"]
        home = NSTemporaryDirectory() + "lockd-session-\(UUID().uuidString)"
        setenv("LOCKD_HOME", home, 1)
    }
    override func tearDown() {
        try? FileManager.default.removeItem(atPath: home)
        if let previous { setenv("LOCKD_HOME", previous, 1) } else { unsetenv("LOCKD_HOME") }
    }
    func testCacheExpiresIncludingSecretsSavedDuringSession() throws {
        var clock = Date(timeIntervalSince1970: 1000)
        let vault = Vault(now: { clock }, simulatedSession: true)
        vault.sessionSeconds = 30
        let beforeUnlock = try vault.encrypt("fake-before-session", itemID: itemID)
        XCTAssertThrowsError(try vault.decrypt(beforeUnlock, itemID: itemID))
        try vault.unlock(reason: "test")
        XCTAssertEqual(try vault.decrypt(beforeUnlock, itemID: itemID), "fake-before-session")
        let duringSession = try vault.encrypt("fake-during-session", itemID: itemID)
        clock.addTimeInterval(30)
        // decrypt itself must revoke, without first querying isUnlocked.
        for cipher in [beforeUnlock, duringSession] {
            XCTAssertThrowsError(try vault.decrypt(cipher, itemID: itemID)) { error in
                guard case Vault.VaultError.locked = error else { return XCTFail("Expected locked") }
            }
        }
        XCTAssertFalse(vault.isUnlocked)
        XCTAssertEqual(vault.unlockedRemaining, 0)
        try vault.unlock(reason: "test again")
        XCTAssertEqual(try vault.decrypt(duringSession, itemID: itemID), "fake-during-session")
    }
    func testLockNowRevokesCachedValue() throws {
        let vault = Vault(now: Date.init, simulatedSession: true)
        try vault.unlock(reason: "test")
        let cipher = try vault.encrypt("fake-lock-now", itemID: itemID)
        vault.lockNow()
        XCTAssertFalse(vault.isUnlocked)
        XCTAssertThrowsError(try vault.decrypt(cipher, itemID: itemID))
    }
    func testLegacySoftwareModeRemainsSeparate() throws {
        let vault = Vault()
        let cipher = try vault.encrypt("fake-software-mode", itemID: itemID)
        vault.lockNow()
        XCTAssertTrue(vault.isUnlocked)
        XCTAssertEqual(try vault.decrypt(cipher, itemID: itemID), "fake-software-mode")
    }
}
