import { Ecdh1PU, EcdhEs, Jwk, Key, KeyAlgs } from '@hyperledger/aries-askar-shared'

import { base64url } from './utils'

describe('jose ecdh', () => {
  beforeAll(() => {
    require('@hyperledger/aries-askar-nodejs')
  })

  test('ecdh es direct', () => {
    const bobKey = Key.generate(KeyAlgs.EcSecp256r1)
    const bobJwk = bobKey.jwkPublic
    const ephemeralKey = Key.generate(KeyAlgs.EcSecp256r1)
    const ephemeralJwk = ephemeralKey.jwkPublic
    const messageString = 'Helo there'
    const message = Uint8Array.from(Buffer.from(messageString))
    const alg = 'ECDH-ES'
    const apu = 'Alice'
    const apv = 'Bob'
    const encAlg = KeyAlgs.AesA256Gcm

    const protectedJson = {
      alg,
      enc: encAlg,
      apu: base64url(apu),
      apv: base64url(apv),
      epk: ephemeralKey,
    }
    const protectedB64 = base64url(JSON.stringify(protectedJson))

    const encryptedMessage = new EcdhEs({
      algId: Uint8Array.from(Buffer.from(encAlg)),
      apu: Uint8Array.from(Buffer.from(apu)),
      apv: Uint8Array.from(Buffer.from(apv)),
    }).encryptDirect({
      encAlg,
      ephemeralKey,
      message,
      recipientKey: bobJwk,
      aad: Uint8Array.from(Buffer.from(protectedB64)),
    })

    const { nonce, tag, ciphertext } = encryptedMessage.parts

    const messageReceived = new EcdhEs({
      algId: Uint8Array.from(Buffer.from(encAlg)),
      apu: Uint8Array.from(Buffer.from(apu)),
      apv: Uint8Array.from(Buffer.from(apv)),
    }).decryptDirect({
      encAlg,
      ephemeralKey: ephemeralJwk,
      recipientKey: bobKey,
      ciphertext,
      nonce,
      tag,
      aad: Uint8Array.from(Buffer.from(protectedB64)),
    })
    expect(Buffer.from(messageReceived).toString()).toStrictEqual(messageString)
    ephemeralKey.handle.free()
    bobKey.handle.free()
  })

  test('ecdh es wrapped', () => {
    const bobKey = Key.generate(KeyAlgs.X25519)
    const bobJwk = bobKey.jwkPublic
    const ephemeralKey = Key.generate(KeyAlgs.X25519)
    const ephemeralJwk = ephemeralKey.jwkPublic
    const message = Uint8Array.from(Buffer.from('Hello there'))
    const alg = 'ECDH-ES+A128KW'
    const enc = 'A256GCM'
    const apu = 'Alice'
    const apv = 'bob'

    const protectedJson = {
      alg,
      enc,
      apu: base64url(apu),
      apv: base64url(apv),
      epk: ephemeralJwk,
    }
    const protectedString = JSON.stringify(protectedJson)
    const protectedB64 = Buffer.from(protectedString).toString('base64url')
    const protectedB64Bytes = Uint8Array.from(Buffer.from(protectedB64))

    const cek = Key.generate(KeyAlgs.AesA256Gcm)

    const encryptedMessage = cek.aeadEncrypt({ message, aad: protectedB64Bytes })
    const { tag, nonce, ciphertext } = encryptedMessage.parts
    const encryptedKey = new EcdhEs({
      algId: Uint8Array.from(Buffer.from(alg)),
      apu: Uint8Array.from(Buffer.from(apu)),
      apv: Uint8Array.from(Buffer.from(apv)),
    }).senderWrapKey({
      wrapAlg: KeyAlgs.AesA128Kw,
      ephemeralKey,
      recipientKey: Key.fromJwk({ jwk: bobJwk }),
      cek,
    }).ciphertext

    const cekReceiver = new EcdhEs({
      algId: Uint8Array.from(Buffer.from(alg)),
      apu: Uint8Array.from(Buffer.from(apu)),
      apv: Uint8Array.from(Buffer.from(apv)),
    }).receiverUnwrapKey({
      wrapAlg: KeyAlgs.AesA128Kw,
      encAlg: KeyAlgs.AesA256Gcm,
      ephemeralKey: Key.fromJwk({ jwk: ephemeralJwk }),
      recipientKey: bobKey,
      ciphertext: encryptedKey,
    })

    const messageReceived = cekReceiver.aeadDecrypt({ ciphertext, tag, nonce, aad: protectedB64Bytes })

    expect(messageReceived).toStrictEqual(message)
    ephemeralKey.handle.free()
    bobKey.handle.free()
    cek.handle.free()
    cekReceiver.handle.free()
  })

  test('ecdh 1pu direct', () => {
    const aliceKey = Key.generate(KeyAlgs.EcSecp256r1)
    const aliceJwk = aliceKey.jwkPublic
    const bobKey = Key.generate(KeyAlgs.EcSecp256r1)
    const bobJwk = bobKey.jwkPublic
    const ephemeralKey = Key.generate(KeyAlgs.EcSecp256r1)
    const ephemeralJwk = ephemeralKey.jwkPublic
    const message = Uint8Array.from(Buffer.from('Hello there'))
    const alg = 'ECDH-1PU'
    const enc = 'A256GCM'
    const apu = 'Alice'
    const apv = 'Bob'
    const protectedJson = {
      alg,
      enc,
      apu: base64url(apu),
      apv: base64url(apv),
      epk: ephemeralJwk,
    }
    const protectedString = JSON.stringify(protectedJson)
    const protectedB64 = Buffer.from(protectedString).toString('base64url')
    const protectedB64Bytes = Uint8Array.from(Buffer.from(protectedB64))

    const encrypedMessage = new Ecdh1PU({
      algId: Uint8Array.from(Buffer.from(enc)),
      apu: Uint8Array.from(Buffer.from(apu)),
      apv: Uint8Array.from(Buffer.from(apv)),
    }).encryptDirect({
      encAlg: KeyAlgs.AesA256Gcm,
      ephemeralKey,
      message,
      senderKey: aliceKey,
      recipientKey: Key.fromJwk({ jwk: bobJwk }),
      aad: protectedB64Bytes,
    })

    const { nonce, tag, ciphertext } = encrypedMessage.parts

    const messageReceived = new Ecdh1PU({
      algId: Uint8Array.from(Buffer.from(enc)),
      apu: Uint8Array.from(Buffer.from(apu)),
      apv: Uint8Array.from(Buffer.from(apv)),
    }).decryptDirect({
      encAlg: KeyAlgs.AesA256Gcm,
      ephemeralKey,
      senderKey: Key.fromJwk({ jwk: aliceJwk }),
      recipientKey: bobKey,
      ciphertext,
      nonce,
      tag,
      aad: protectedB64Bytes,
    })

    expect(messageReceived).toStrictEqual(message)
    aliceKey.handle.free()
    bobKey.handle.free()
    ephemeralKey.handle.free()
  })

  /**
   *
   * These tests have been implemented as a copy from the python wapper.
   * The test vectores have been taken from:
   * https://www.ietf.org/archive/id/draft-madden-jose-ecdh-1pu-04.txt
   */
  test('ecdh 1pu wrapped expected', () => {
    const ephemeral = Key.fromJwk({
      jwk: Jwk.fromJson({
        crv: 'X25519',
        kty: 'OKP',
        d: 'x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8',
        x: 'k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc',
      }),
    })

    const alice = Key.fromJwk({
      jwk: Jwk.fromJson({
        crv: 'X25519',
        kty: 'OKP',
        d: 'i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU',
        x: 'Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4',
      }),
    })

    const bob = Key.fromJwk({
      jwk: Jwk.fromJson({
        crv: 'X25519',
        kty: 'OKP',
        d: '1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg',
        x: 'BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw',
      }),
    })

    const alg = 'ECDH-1PU+A128KW'
    const apu = 'Alice'
    const apv = 'Bob and Charlie'
    const base64urlApu = base64url(apu)
    const base64urlApv = base64url(apv)

    expect(base64urlApu).toStrictEqual('QWxpY2U')
    expect(base64urlApv).toStrictEqual('Qm9iIGFuZCBDaGFybGll')

    const protectedJson = {
      alg: 'ECDH-1PU+A128KW',
      enc: 'A256CBC-HS512',
      apu: 'QWxpY2U',
      apv: 'Qm9iIGFuZCBDaGFybGll',
      epk: { kty: 'OKP', crv: 'X25519', x: 'k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc' },
    }
    const protectedString = JSON.stringify(protectedJson)
    const protectedB64 = Buffer.from(protectedString).toString('base64url')
    const protectedB64Bytes = Uint8Array.from(Buffer.from(protectedB64))

    const cek = Key.fromSecretBytes({
      algorithm: KeyAlgs.AesA256CbcHs512,
      secretKey: Uint8Array.from(
        Buffer.from(
          'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0',
          'hex'
        )
      ),
    })

    const iv = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    const message = Uint8Array.from(Buffer.from('Three is a magic number.'))

    const enc = cek.aeadEncrypt({ message, nonce: iv, aad: protectedB64Bytes })

    const { ciphertext, tag: ccTag } = enc.parts

    expect(Buffer.from(ciphertext).toString('base64url')).toStrictEqual('Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw')
    expect(Buffer.from(ccTag).toString('base64url')).toStrictEqual('HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ')

    const derived = new Ecdh1PU({
      apv: Uint8Array.from(Buffer.from(apv)),
      apu: Uint8Array.from(Buffer.from(apu)),
      algId: Uint8Array.from(Buffer.from(alg)),
    }).deriveKey({
      encAlg: KeyAlgs.AesA128Kw,
      recipientKey: bob,
      senderKey: alice,
      ccTag,
      ephemeralKey: ephemeral,
      receive: false,
    })

    expect(derived.secretBytes).toStrictEqual(Uint8Array.from(Buffer.from('df4c37a0668306a11e3d6b0074b5d8df', 'hex')))

    const encryptedKey = derived.wrapKey({ other: cek }).ciphertextWithTag
    expect(encryptedKey).toStrictEqual(
      Uint8Array.from(
        Buffer.from(
          'pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN',
          'base64url'
        )
      )
    )

    const encryptedKey2 = new Ecdh1PU({
      apv: Uint8Array.from(Buffer.from(apv)),
      apu: Uint8Array.from(Buffer.from(apu)),
      algId: Uint8Array.from(Buffer.from(alg)),
    }).senderWrapKey({
      wrapAlg: KeyAlgs.AesA128Kw,
      cek,
      ephemeralKey: ephemeral,
      ccTag,
      senderKey: alice,
      recipientKey: bob,
    })

    expect(encryptedKey2.ciphertextWithTag).toStrictEqual(encryptedKey)

    const derivedReceiver = new Ecdh1PU({
      apv: Uint8Array.from(Buffer.from(apv)),
      apu: Uint8Array.from(Buffer.from(apu)),
      algId: Uint8Array.from(Buffer.from(alg)),
    }).deriveKey({
      encAlg: KeyAlgs.AesA128Kw,
      ephemeralKey: ephemeral,
      senderKey: alice,
      recipientKey: bob,
      ccTag,
      receive: true,
    })

    const cekReceiver = derivedReceiver.unwrapKey({ algorithm: KeyAlgs.AesA256CbcHs512, ciphertext: encryptedKey })

    const messageReceived = cekReceiver.aeadDecrypt({
      ciphertext,
      nonce: iv,
      aad: protectedB64Bytes,
      tag: ccTag,
    })

    expect(messageReceived).toStrictEqual(message)

    const cekReceiver2 = new Ecdh1PU({
      apv: Uint8Array.from(Buffer.from(apv)),
      apu: Uint8Array.from(Buffer.from(apu)),
      algId: Uint8Array.from(Buffer.from(alg)),
    }).receiverUnwrapKey({
      wrapAlg: KeyAlgs.AesA128Kw,
      encAlg: KeyAlgs.AesA256CbcHs512,
      ephemeralKey: ephemeral,
      senderKey: alice,
      recipientKey: bob,
      ciphertext: encryptedKey,
      ccTag,
    })

    expect(cekReceiver2.jwkSecret).toStrictEqual(cek.jwkSecret)
    cek.handle.free()
    cekReceiver.handle.free()
    cekReceiver2.handle.free()
    derived.handle.free()
  })
})
