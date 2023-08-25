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
    let keyFactory = LocalKeyFactory()

    func testEcdhEsDirect() throws {
        let bobKey = try keyFactory.generate(alg: .p256, ephemeral: false)
        let bobJwk = try bobKey.toJwkPublic(alg: nil)
        let ephemKey = try keyFactory.generate(alg: .p256, ephemeral: false)
        let message = "Hello there".data(using: .utf8)!
        let alg = "ECDH-ES"
        let enc = "A256GCM"
        let apu = "Alice"
        let apv = "Bob"
        let protectedB64 = "{\"alg\":\"\(alg)\",\"enc\":\"\(enc)\",\"apu\":\"\(apu.base64url())\",\"apv\":\"\(apv.base64url())\",\"epk\":\(bobJwk)}".data(using: .utf8)!
        let encryptedMsg = try AskarEcdhEs(algId: enc, apu: apu, apv: apv).encryptDirect(
            encAlg: .a256Gcm, ephemeralKey: ephemKey, receiverKey: bobKey, message: [UInt8](message), nonce: nil, aad: [UInt8](protectedB64))

        let messageRecv = try AskarEcdhEs(algId: enc, apu: apu, apv: apv).decryptDirect(
            encAlg: .a256Gcm, ephemeralKey: ephemKey, receiverKey: bobKey, ciphertext: encryptedMsg.ciphertext(), tag: encryptedMsg.tag(), nonce: encryptedMsg.nonce(), aad: [UInt8](protectedB64))
        XCTAssertEqual(message, Data(messageRecv))
    }

    func testEcdhEsWrapped() throws {
        let bobKey = try keyFactory.generate(alg: .x25519, ephemeral: false)
        let ephemKey = try keyFactory.generate(alg: .x25519, ephemeral: false)
        let ephemJwk = try ephemKey.toJwkPublic(alg: nil)
        let message = "Hello there".data(using: .utf8)!
        let alg = "ECDH-ES+A128KW"
        let enc = "A256GCM"
        let apu = "Alice"
        let apv = "Bob"
        let protectedB64 = "{\"alg\":\"\(alg)\",\"enc\":\"\(enc)\",\"apu\":\"\(apu.base64url())\",\"apv\":\"\(apv.base64url())\",\"epk\":\(ephemJwk)}".data(using: .utf8)!
        let cek = try keyFactory.generate(alg: .a256Gcm, ephemeral: false)
        let encryptedMsg = try cek.aeadEncrypt(message: [UInt8](message), nonce: nil, aad: [UInt8](protectedB64))
        let encryptedKey = try AskarEcdhEs(algId: alg, apu: apu, apv: apv).senderWrapKey(
            wrapAlg: .a128Kw, ephemeralKey: ephemKey, receiverKey: bobKey, cek: cek)
        let encryptedKeyCiphertext = encryptedKey.ciphertext()

        let cekRecv = try AskarEcdhEs(algId: alg, apu: apu, apv: apv).receiverUnwrapKey(
            wrapAlg: .a128Kw,
            encAlg: .a256Gcm,
            ephemeralKey: ephemKey,
            receiverKey: bobKey,
            ciphertext: encryptedKeyCiphertext,
            nonce: nil,
            tag: nil)
        let messageRecv = try cekRecv.aeadDecrypt(
            ciphertext: encryptedMsg.ciphertext(), tag: encryptedMsg.tag(), nonce: encryptedMsg.nonce(), aad: [UInt8](protectedB64))
        XCTAssertEqual(message, Data(messageRecv))
    }

    func testEcdh1puDirect() throws {
        let aliceKey = try keyFactory.generate(alg: .p256, ephemeral: false)
        let bobKey = try keyFactory.generate(alg: .p256, ephemeral: false)
        let ephemKey = try keyFactory.generate(alg: .p256, ephemeral: false)
        let ephemJwk = try ephemKey.toJwkPublic(alg: nil)
        let message = "Hello there".data(using: .utf8)!
        let alg = "ECDH-1PU"
        let enc = "A256GCM"
        let apu = "Alice"
        let apv = "Bob"
        let protectedB64 = "{\"alg\":\"\(alg)\",\"enc\":\"\(enc)\",\"apu\":\"\(apu.base64url())\",\"apv\":\"\(apv.base64url())\",\"epk\":\(ephemJwk)}".data(using: .utf8)!
        let encryptedMsg = try AskarEcdh1Pu(algId: enc, apu: apu, apv: apv).encryptDirect(
            encAlg: .a256Gcm, ephemeralKey: ephemKey, senderKey: aliceKey, receiverKey: bobKey, message: [UInt8](message), nonce: nil, aad: [UInt8](protectedB64))

        let messageRecv = try AskarEcdh1Pu(algId: enc, apu: apu, apv: apv).decryptDirect(
            encAlg: .a256Gcm, ephemeralKey: ephemKey, senderKey: aliceKey, receiverKey: bobKey, ciphertext: encryptedMsg.ciphertext(), tag: encryptedMsg.tag(), nonce: encryptedMsg.nonce(), aad: [UInt8](protectedB64))
        XCTAssertEqual(message, Data(messageRecv))
    }

    func testEcdh1puWrappedExpected() throws {
        let ephem = try keyFactory.fromJwk(jwk:
            """
            {"kty": "OKP",
            "crv": "X25519",
            "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
            "d": "x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8"}
        """)
        let alice = try keyFactory.fromJwk(jwk:
            """
            {"kty": "OKP",
            "crv": "X25519",
            "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
            "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU"}
        """)
        let bob = try keyFactory.fromJwk(jwk:
            """
            {"kty": "OKP",
            "crv": "X25519",
            "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
            "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg"}
        """)

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

        let cek = try keyFactory.fromSecretBytes(
            alg: .a256CbcHs512,
            bytes: [UInt8](Data.fromHex(
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" +
                "efeeedecebeae9e8e7e6e5e4e3e2e1e0" +
                "dfdedddcdbdad9d8d7d6d5d4d3d2d1d0" +
                "cfcecdcccbcac9c8c7c6c5c4c3c2c1c0")!))
        let iv = Data.fromHex("000102030405060708090a0b0c0d0e0f")!
        let message = "Three is a magic number.".data(using: .utf8)!

        let encrypted = try cek.aeadEncrypt(message: [UInt8](message), nonce: [UInt8](iv), aad: [UInt8](protectedB64))
        let ciphertext = encrypted.ciphertext()
        let ccTag = encrypted.tag()
        XCTAssertEqual(Data(ciphertext).base64url() , "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw")
        XCTAssertEqual(Data(ccTag).base64url() , "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ")

        let derived = try AskarEcdh1Pu(algId: alg, apu: apu, apv: apv).deriveKey(
            encAlg: .a128Kw,
            ephemeralKey: ephem,
            senderKey: alice,
            receiverKey: bob,
            ccTag: ccTag,
            receive: false)
        XCTAssertEqual(try Data(derived.toSecretBytes()), Data.fromHex("df4c37a0668306a11e3d6b0074b5d8df"))

        let encryptedKey = try derived.wrapKey(key: cek, nonce: nil).ciphertextTag()
        XCTAssertEqual(Data(encryptedKey).base64url(), "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN")

        let encryptedKey2 = try AskarEcdh1Pu(algId: alg, apu: apu, apv: apv).senderWrapKey(
            wrapAlg: .a128Kw,
            ephemeralKey: ephem,
            senderKey: alice,
            receiverKey: bob,
            cek: cek,
            ccTag: ccTag)
        XCTAssertEqual(encryptedKey2.ciphertextTag(), encryptedKey)

        let derivedRecv = try AskarEcdh1Pu(algId: alg, apu: apu, apv: apv).deriveKey(
            encAlg: .a128Kw,
            ephemeralKey: ephem,
            senderKey: alice,
            receiverKey: bob,
            ccTag: ccTag,
            receive: true)
        let cekRecv = try derivedRecv.unwrapKey(alg: .a256CbcHs512, ciphertext: encryptedKey, tag: nil, nonce: nil)
        XCTAssertEqual(try cekRecv.toJwkSecret(), try cek.toJwkSecret())

        let messageRecv = try cekRecv.aeadDecrypt(ciphertext: ciphertext, tag: ccTag, nonce: [UInt8](iv), aad: [UInt8](protectedB64))
        XCTAssertEqual(Data(messageRecv), message)

        let cekRecv2 = try AskarEcdh1Pu(algId: alg, apu: apu, apv: apv).receiverUnwrapKey(
            wrapAlg: .a256CbcHs512,
            encAlg: .a128Kw,
            ephemeralKey: ephem,
            senderKey: alice,
            receiverKey: bob,
            ciphertext: encryptedKey,
            ccTag: ccTag,
            nonce: nil,
            tag: nil)
        XCTAssertEqual(try cekRecv2.toJwkSecret(), try cek.toJwkSecret())
    }
}
