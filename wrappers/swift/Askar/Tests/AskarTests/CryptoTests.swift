import XCTest
@testable import Askar

final class CryptoTests: XCTestCase {
    let keyFactory = LocalKeyFactory()
    let crypto = AskarCrypto()

    func testCryptoBoxSeal() throws {
        let key = try keyFactory.generate(alg: .x25519, ephemeral: false)
        let message = "test message".data(using: .utf8)!
        let enc = try crypto.boxSeal(receiverKey: key, message: [UInt8](message))
        let dec = try crypto.boxSealOpen(receiverKey: key, ciphertext: [UInt8](enc))
        XCTAssertEqual(message, Data(dec))
    }

    func testCryptoBox() throws {
        let senderKey = try keyFactory.generate(alg: .x25519, ephemeral: false)
        let receiverKey = try keyFactory.generate(alg: .x25519, ephemeral: false)
        let message = "test message".data(using: .utf8)!
        let nonce = try crypto.randomNonce()
        let enc = try crypto.cryptoBox(receiverKey: receiverKey, senderKey: senderKey, message: [UInt8](message), nonce: nonce)
        let dec = try crypto.boxOpen(receiverKey: receiverKey, senderKey: senderKey, message: enc, nonce: nonce)
        XCTAssertEqual(message, Data(dec))
    }
}
