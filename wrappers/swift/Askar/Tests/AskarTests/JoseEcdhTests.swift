import XCTest
@testable import Askar

extension String {
    func base64url() -> String {
        return self.data(using: .utf8)!.base64url()
    }
}

extension Data {
    func base64url() -> String {
        let base64url = self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return base64url
    }

    static func fromHex(_ string: String) -> Data? {
        let len = string.count / 2
        var data = Data(capacity: len)
        for i in 0..<len {
            let j = string.index(string.startIndex, offsetBy: i*2)
            let k = string.index(j, offsetBy: 2)
            let bytes = string[j..<k]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
        }
        return data
    }
}

final class JoseEcdhTests: XCTestCase {
    func testEcdhEsDirect() throws {
        let bobKey = try Key.generate(alg: .P256)
        let bobJwk = try bobKey.getJwkPublic()
        let ephemKey = try Key.generate(alg: .P256)
        let message = "Hello there".data(using: .utf8)!
        let alg = "ECDH-ES"
        let enc = "A256GCM"
        let apu = "Alice"
        let apv = "Bob"
        let protectedB64 = "{\"alg\":\"\(alg)\",\"enc\":\"\(enc)\",\"apu\":\"\(apu.base64url())\",\"apv\":\"\(apv.base64url())\",\"epk\":\(bobJwk)}".data(using: .utf8)!
        let encryptedMsg = try EcdhEs(algId: enc, apu: apu, apv: apv).encryptDirect(
            encAlg: .A256GCM, ephemeralKey: ephemKey, receiverKey: bobKey, message: message, aad: protectedB64)
        let (ciphertext, tag, nonce) = encryptedMsg.parts

        let messageRecv = try EcdhEs(algId: enc, apu: apu, apv: apv).decryptDirect(
            encAlg: .A256GCM, ephemeralKey: ephemKey, receiverKey: bobKey, ciphertext: ciphertext, nonce: nonce, tag: tag, aad: protectedB64)
        XCTAssertEqual(message, messageRecv)
    }

    func testEcdhEsWrapped() throws {
        let bobKey = try Key.generate(alg: .X25519)
        let ephemKey = try Key.generate(alg: .X25519)
        let ephemJwk = try ephemKey.getJwkPublic()
        let message = "Hello there".data(using: .utf8)!
        let alg = "ECDH-ES+A128KW"
        let enc = "A256GCM"
        let apu = "Alice"
        let apv = "Bob"
        let protectedB64 = "{\"alg\":\"\(alg)\",\"enc\":\"\(enc)\",\"apu\":\"\(apu.base64url())\",\"apv\":\"\(apv.base64url())\",\"epk\":\(ephemJwk)}".data(using: .utf8)!
        let cek = try Key.generate(alg: .A256GCM)
        let encryptedMsg = try cek.aeadEncrypt(message: message, aad: protectedB64)
        let (ciphertext, tag, nonce) = encryptedMsg.parts
        let encryptedKey = try EcdhEs(algId: alg, apu: apu, apv: apv).senderWrapKey(
            wrapAlg: .A128KW, ephemeralKey: ephemKey, receiverKey: bobKey, cek: cek)
        let encryptedKeyCiphertext = encryptedKey.ciphertext

        let cekRecv = try EcdhEs(algId: alg, apu: apu, apv: apv).receiverUnwrapKey(
            wrapAlg: .A128KW,
            encAlg: .A256GCM,
            ephemeralKey: ephemKey,
            receiverKey: bobKey,
            ciphertext: encryptedKeyCiphertext)
        let messageRecv = try cekRecv.aeadDecrypt(
            ciphertext: ciphertext, nonce: nonce, tag: tag, aad: protectedB64)
        XCTAssertEqual(message, messageRecv)
    }

    func testEcdh1puDirect() throws {
        let aliceKey = try Key.generate(alg: .P256)
        let bobKey = try Key.generate(alg: .P256)
        let ephemKey = try Key.generate(alg: .P256)
        let ephemJwk = try ephemKey.getJwkPublic()
        let message = "Hello there".data(using: .utf8)!
        let alg = "ECDH-1PU"
        let enc = "A256GCM"
        let apu = "Alice"
        let apv = "Bob"
        let protectedB64 = "{\"alg\":\"\(alg)\",\"enc\":\"\(enc)\",\"apu\":\"\(apu.base64url())\",\"apv\":\"\(apv.base64url())\",\"epk\":\(ephemJwk)}".data(using: .utf8)!
        let encryptedMsg = try Ecdh1PU(algId: enc, apu: apu, apv: apv).encryptDirect(
            encAlg: .A256GCM, ephemeralKey: ephemKey, senderKey: aliceKey, receiverKey: bobKey, message: message, aad: protectedB64)
        let (ciphertext, tag, nonce) = encryptedMsg.parts

        let messageRecv = try Ecdh1PU(algId: enc, apu: apu, apv: apv).decryptDirect(
            encAlg: .A256GCM, ephemeralKey: ephemKey, senderKey: aliceKey, receiverKey: bobKey, ciphertext: ciphertext, nonce: nonce, tag: tag, aad: protectedB64)
        XCTAssertEqual(message, messageRecv)
    }

    func testEcdh1puWrappedExpected() throws {
        let ephem = try Key.fromJwk(
            """
            {"kty": "OKP",
            "crv": "X25519",
            "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
            "d": "x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8"}
        """.data(using: .utf8)!)
        let alice = try Key.fromJwk(
            """
            {"kty": "OKP",
            "crv": "X25519",
            "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
            "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU"}
        """.data(using: .utf8)!)
        let bob = try Key.fromJwk(
            """
            {"kty": "OKP",
            "crv": "X25519",
            "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
            "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg"}
        """.data(using: .utf8)!)

        let alg = "ECDH-1PU+A128KW"
        let enc = "A256CBC-HS512"
        let apu = "Alice"
        let apv = "Bob and Charlie"
        let protected = """
            {"alg":"\(alg)",
            "enc":"\(enc)",
            "apu":"\(apu.base64url())",
            "apv":"\(apv.base64url())",
            "epk":
            {"kty":"OKP",
            "crv":"X25519",
            "x":"k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc"}}
            """.replacingOccurrences(of: "\n", with: "")
        let protectedB64 = protected.base64url().data(using: .utf8)!

        let cek = try Key.fromSecretBytes(
            Data.fromHex(
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" +
                "efeeedecebeae9e8e7e6e5e4e3e2e1e0" +
                "dfdedddcdbdad9d8d7d6d5d4d3d2d1d0" +
                "cfcecdcccbcac9c8c7c6c5c4c3c2c1c0")!,
            alg: .A256CBC_HS512)
        let iv = Data.fromHex("000102030405060708090a0b0c0d0e0f")!
        let message = "Three is a magic number.".data(using: .utf8)!

        let encrypted = try cek.aeadEncrypt(message: message, nonce: iv, aad: protectedB64)
        let ciphertext = encrypted.ciphertext
        let ccTag = encrypted.tag
        XCTAssertEqual(ciphertext.base64url() , "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw")
        XCTAssertEqual(ccTag.base64url() , "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ")

        let derived = try Ecdh1PU(algId: alg, apu: apu, apv: apv).deriveKey(
            encAlg: .A128KW,
            ephemeralKey: ephem,
            senderKey: alice,
            receiverKey: bob,
            ccTag: ccTag,
            receive: false)
        XCTAssertEqual(try derived.getSecretBytes(), Data.fromHex("df4c37a0668306a11e3d6b0074b5d8df"))

        let encryptedKey = try derived.wrapKey(other: cek).ciphertextAndTag
        XCTAssertEqual(encryptedKey.base64url(), "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN")

        let encryptedKey2 = try Ecdh1PU(algId: alg, apu: apu, apv: apv).senderWrapKey(
            wrapAlg: .A128KW,
            ephemeralKey: ephem,
            senderKey: alice,
            receiverKey: bob,
            cek: cek,
            ccTag: ccTag)
        XCTAssertEqual(encryptedKey2.ciphertextAndTag, encryptedKey)

        let derivedRecv = try Ecdh1PU(algId: alg, apu: apu, apv: apv).deriveKey(
            encAlg: .A128KW,
            ephemeralKey: ephem,
            senderKey: alice,
            receiverKey: bob,
            ccTag: ccTag,
            receive: true)
        let cekRecv = try derivedRecv.unwrapKey(alg: .A256CBC_HS512, ciphertext: encryptedKey)
        XCTAssertEqual(try cekRecv.getJwkSecret(), try cek.getJwkSecret())

        let messageRecv = try cekRecv.aeadDecrypt(ciphertext: ciphertext, nonce: iv, tag: ccTag, aad: protectedB64)
        XCTAssertEqual(messageRecv, message)

        let cekRecv2 = try Ecdh1PU(algId: alg, apu: apu, apv: apv).receiverUnwrapKey(
            wrapAlg: .A256CBC_HS512,
            encAlg: .A128KW,
            ephemeralKey: ephem,
            senderKey: alice,
            receiverKey: bob,
            ciphertext: encryptedKey,
            ccTag: ccTag)
        XCTAssertEqual(try cekRecv2.getJwkSecret(), try cek.getJwkSecret())
    }
}
