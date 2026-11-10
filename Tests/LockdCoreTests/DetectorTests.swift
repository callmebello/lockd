import XCTest
@testable import LockdCore

final class DetectorTests: XCTestCase {
    func testAnthropic() {
        let d = Detector.detect(in: "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
        XCTAssertEqual(d.first?.service, "Anthropic")
        XCTAssertEqual(d.first?.envName, "ANTHROPIC_API_KEY")
        XCTAssertTrue(d.first?.confident ?? false)
    }
    func testGeminiAndOpenAI() {
        XCTAssertEqual(Detector.detect(in: "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q")[0].service, "Google Gemini")
        XCTAssertEqual(Detector.detect(in: "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD")[0].service, "OpenAI")
    }
    func testStripeKeepsEnvName() {
        let d = Detector.detect(in: "STRIPE_SECRET_KEY=sk_live_51HabcdefGHIJKLMNopqrst")
        XCTAssertEqual(d.first?.envName, "STRIPE_SECRET_KEY")
        XCTAssertEqual(d.first?.service, "Stripe")
    }
    func testEnvFileMultiLine() {
        let d = Detector.detect(in: "FOO=bar\nANTHROPIC_API_KEY=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123\nDATABASE_URL=postgres://u:p@host:5432/db\n")
        XCTAssertEqual(d.count, 2)
    }
    func testPlainTextIsIgnored() {
        XCTAssertTrue(Detector.detect(in: "oi, tudo bem? me manda o link do projeto amanhã").isEmpty)
        XCTAssertTrue(Detector.detect(in: "https://github.com/anthropics/claude-code/issues/12345").isEmpty)
        XCTAssertTrue(Detector.detect(in: "3f786850e387550fdab836ed7e6dc881de23001b").isEmpty)
    }
    func testPrivateKey() {
        let d = Detector.detect(in: "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49\n-----END PRIVATE KEY-----")
        XCTAssertEqual(d.first?.type, "Private key (.p8)")
    }
    func testSupabaseJWT() {
        // header.payload.sig com iss=supabase, role=service_role
        let payload = Data(#"{"iss":"supabase","role":"service_role","ref":"abcd"}"#.utf8).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        let jwt = "eyJhbGciOiJIUzI1NiJ9.\(payload).c2lnbmF0dXJlLXNpZ25hdHVyZQ"
        let d = Detector.detect(in: jwt)
        XCTAssertEqual(d.first?.envName, "SUPABASE_SERVICE_ROLE_KEY")
    }
    func testVaultRoundTrip() throws {
        setenv("LOCKD_HOME", NSTemporaryDirectory() + "lockd-test-\(UUID().uuidString)", 1)
        let id = UUID()
        let c = try Vault.shared.encrypt("segredo", itemID: id)
        XCTAssertNotEqual(c, "segredo")
        XCTAssertEqual(try Vault.shared.decrypt(c, itemID: id), "segredo")
    }
    func testClassifier() {
        XCTAssertEqual(FileClassifier.classify(URL(fileURLWithPath: "/x/priva-logo.png")).category, "Logos")
        XCTAssertTrue(FileClassifier.classify(URL(fileURLWithPath: "/x/Screenshot 2026-10-22.png")).ignore)
        XCTAssertEqual(FileClassifier.classify(URL(fileURLWithPath: "/x/AuthKey_ABC.p8")).kind, .credential)
    }
}
