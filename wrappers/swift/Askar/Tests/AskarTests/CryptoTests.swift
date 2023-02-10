import XCTest
@testable import Askar

final class CryptoTests: XCTestCase {
    func testCryptoBoxSeal() throws {
        let key = try Key.generate(alg: .X25519)
        let message = "test message".data(using: .utf8)!
        let enc = try Crypto.boxSeal(receiverKey: key, message: message)
        let dec = try Crypto.boxSealOpen(receiverKey: key, message: enc)
        XCTAssertEqual(message, dec)
    }

    func testCryptoBox() throws {
        let senderKey = try Key.generate(alg: .X25519)
        let receiverKey = try Key.generate(alg: .X25519)
        let message = "test message".data(using: .utf8)!
        let nonce = try Crypto.randomNonce()
        let enc = try Crypto.box(receiverKey: receiverKey, senderKey: senderKey, message: message, nonce: nonce)
        let dec = try Crypto.boxOpen(receiverKey: receiverKey, senderKey: senderKey, message: enc, nonce: nonce)
        XCTAssertEqual(message, dec)
    }
}
