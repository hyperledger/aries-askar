import XCTest
@testable import Askar

final class KeyTests: XCTestCase {
    let keyFactory = LocalKeyFactory()

    func testAesCbcHmac() throws {
        let key = try keyFactory.generate(alg: .a128CbcHs256, ephemeral: false)
        XCTAssertEqual(key.algorithm(), .a128CbcHs256)

        let data = "test message".data(using: .utf8)!
        let nonce = try key.aeadRandomNonce()
        let params = try key.aeadParams()
        XCTAssertEqual(params.nonceLength, 16)
        XCTAssertEqual(params.tagLength, 16)
        let enc = try key.aeadEncrypt(message: [UInt8](data), nonce: nonce, aad: [UInt8]("aad".utf8))
        let dec = try key.aeadDecrypt(ciphertext: [UInt8](enc.ciphertext()), tag: [UInt8](enc.tag()), nonce: nonce, aad: [UInt8]("aad".utf8))
        XCTAssertEqual(data, Data(dec))
    }

    func testAesGcm() throws {
        let key = try keyFactory.generate(alg: .a128Gcm, ephemeral: false)
        XCTAssertEqual(key.algorithm(), .a128Gcm)

        let data = "test message".data(using: .utf8)!
        let nonce = try key.aeadRandomNonce()
        let params = try key.aeadParams()
        XCTAssertEqual(params.nonceLength, 12)
        XCTAssertEqual(params.tagLength, 16)
        let enc = try key.aeadEncrypt(message: [UInt8](data), nonce: nonce, aad: [UInt8]("aad".utf8))
        let dec = try key.aeadDecrypt(ciphertext: [UInt8](enc.ciphertext()), tag: [UInt8](enc.tag()), nonce: nonce, aad: [UInt8]("aad".utf8))
        XCTAssertEqual(data, Data(dec))
    }

    func testBlsKeygen() throws {
        let key = try keyFactory.fromSeed(alg: .bls12381g1g2, seed: [UInt8]("testseed000000000000000000000001".utf8), method: .blsKeyGen)
        XCTAssertEqual(try key.toJwkPublic(alg: .bls12381g1),
                       "{\"crv\":\"BLS12381_G1\",\"kty\":\"OKP\",\"x\":" +
                       "\"h56eYI8Qkq5hitICb-ik8wRTzcn6Fd4iY8aDNVc9q1xoPS3lh4DB_B4wNtar1HrV\"}")
        XCTAssertEqual(try key.toJwkPublic(alg: .bls12381g2),
                       "{\"crv\":\"BLS12381_G2\",\"kty\":\"OKP\"," +
                       "\"x\":\"iZIOsO6BgLV72zCrBE2ym3DEhDYcghnUMO4O8IVVD8yS-C_zu6OA3L-ny-AO4" +
                       "rbkAo-WuApZEjn83LY98UtoKpTufn4PCUFVQZzJNH_gXWHR3oDspJaCbOajBfm5qj6d\"}")
        XCTAssertEqual(try key.toJwkPublic(alg: nil),
                       "{\"crv\":\"BLS12381_G1G2\",\"kty\":\"OKP\"," +
                       "\"x\":\"h56eYI8Qkq5hitICb-ik8wRTzcn6Fd4iY8aDNVc9q1xoPS3lh4DB_B4wNtar1H" +
                       "rViZIOsO6BgLV72zCrBE2ym3DEhDYcghnUMO4O8IVVD8yS-C_zu6OA3L-ny-AO4rbk" +
                       "Ao-WuApZEjn83LY98UtoKpTufn4PCUFVQZzJNH_gXWHR3oDspJaCbOajBfm5qj6d\"}")
    }

    func testEd25519() throws {
        let key = try keyFactory.generate(alg: .ed25519, ephemeral: false)
        XCTAssertEqual(key.algorithm(), .ed25519)
        let message = "test message".data(using: .utf8)!
        let sig = try key.signMessage(message: [UInt8](message), sigType: nil)
        XCTAssertTrue(try key.verifySignature(message: [UInt8](message), signature: sig, sigType: nil))

        let x25519_key = try key.convertKey(alg: .x25519)
        let x25519_key_2 = try keyFactory.generate(alg: .x25519, ephemeral: false)
        let kex = try x25519_key.toKeyExchange(alg: .xc20p, pk: x25519_key_2)
        XCTAssertNotNil(kex)

        let jwk = try JSONSerialization.jsonObject(with: key.toJwkPublic(alg: nil).data(using: .utf8)!) as! [String: Any]
        XCTAssertEqual(jwk["kty"] as! String, "OKP")
        XCTAssertEqual(jwk["crv"] as! String, "Ed25519")

        let jwk2 = try JSONSerialization.jsonObject(with: Data(key.toJwkSecret())) as! [String: Any]
        XCTAssertEqual(jwk2["kty"] as! String, "OKP")
        XCTAssertEqual(jwk2["crv"] as! String, "Ed25519")
    }
}
