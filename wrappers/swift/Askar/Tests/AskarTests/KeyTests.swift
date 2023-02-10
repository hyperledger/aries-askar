import XCTest
@testable import Askar

final class KeyTests: XCTestCase {
    func testAesCbcHmac() throws {
        let key = try Key.generate(alg: .A128CBC_HS256)
        XCTAssertEqual(try key.algorithm, .A128CBC_HS256)

        let data = "test message".data(using: .utf8)!
        let nonce = try key.aeadRandomNonce()
        let params = try key.aeadParams()
        XCTAssertEqual(params.nonce_length, 16)
        XCTAssertEqual(params.tag_length, 16)
        let enc = try key.aeadEncrypt(message: data, nonce: nonce, aad: "aad".data(using: .utf8)!)
        let dec = try key.aeadDecrypt(encrypted: enc, nonce: nonce, aad: "aad".data(using: .utf8)!)
        XCTAssertEqual(data, dec)
    }

    func testAesGcm() throws {
        let key = try Key.generate(alg: .A128GCM)
        XCTAssertEqual(try key.algorithm, .A128GCM)

        let data = "test message".data(using: .utf8)!
        let nonce = try key.aeadRandomNonce()
        let params = try key.aeadParams()
        XCTAssertEqual(params.nonce_length, 12)
        XCTAssertEqual(params.tag_length, 16)
        let enc = try key.aeadEncrypt(message: data, nonce: nonce, aad: "aad".data(using: .utf8)!)
        let dec = try key.aeadDecrypt(encrypted: enc, nonce: nonce, aad: "aad".data(using: .utf8)!)
        XCTAssertEqual(data, dec)
    }

    func testBlsKeygen() throws {
        let key = try Key.fromSeed("testseed000000000000000000000001", alg: .BLS12_381_G1G2, method: .BlsKeyGen)
        XCTAssertEqual(try key.getJwkPublic(alg: KeyAlg.BLS12_381_G1),
                       "{\"crv\":\"BLS12381_G1\",\"kty\":\"OKP\",\"x\":" +
                       "\"h56eYI8Qkq5hitICb-ik8wRTzcn6Fd4iY8aDNVc9q1xoPS3lh4DB_B4wNtar1HrV\"}")
        XCTAssertEqual(try key.getJwkPublic(alg: KeyAlg.BLS12_381_G2),
                       "{\"crv\":\"BLS12381_G2\",\"kty\":\"OKP\"," +
                       "\"x\":\"iZIOsO6BgLV72zCrBE2ym3DEhDYcghnUMO4O8IVVD8yS-C_zu6OA3L-ny-AO4" +
                       "rbkAo-WuApZEjn83LY98UtoKpTufn4PCUFVQZzJNH_gXWHR3oDspJaCbOajBfm5qj6d\"}")
        XCTAssertEqual(try key.getJwkPublic(),
                       "{\"crv\":\"BLS12381_G1G2\",\"kty\":\"OKP\"," +
                       "\"x\":\"h56eYI8Qkq5hitICb-ik8wRTzcn6Fd4iY8aDNVc9q1xoPS3lh4DB_B4wNtar1H" +
                       "rViZIOsO6BgLV72zCrBE2ym3DEhDYcghnUMO4O8IVVD8yS-C_zu6OA3L-ny-AO4rbk" +
                       "Ao-WuApZEjn83LY98UtoKpTufn4PCUFVQZzJNH_gXWHR3oDspJaCbOajBfm5qj6d\"}")
    }

    func testEd25519() throws {
        let key = try Key.generate(alg: .ED25519)
        XCTAssertEqual(try key.algorithm, .ED25519)
        let message = "test message".data(using: .utf8)!
        let sig = try key.signMessage(message)
        XCTAssertTrue(try key.verifySignature(message: message, signature: sig))

        let x25519_key = try key.convertKey(alg: KeyAlg.X25519)
        let x25519_key_2 = try Key.generate(alg: KeyAlg.X25519)
        let kex = try x25519_key.keyExchange(alg: KeyAlg.XC20P, pk: x25519_key_2)
        XCTAssertNotNil(kex)

        let jwk = try JSONSerialization.jsonObject(with: key.getJwkPublic().data(using: .utf8)!) as! [String: Any]
        XCTAssertEqual(jwk["kty"] as! String, "OKP")
        XCTAssertEqual(jwk["crv"] as! String, "Ed25519")

        let jwk2 = try JSONSerialization.jsonObject(with: key.getJwkSecret()) as! [String: Any]
        XCTAssertEqual(jwk2["kty"] as! String, "OKP")
        XCTAssertEqual(jwk2["crv"] as! String, "Ed25519")
    }
}
