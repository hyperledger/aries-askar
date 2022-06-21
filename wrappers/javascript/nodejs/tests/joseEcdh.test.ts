import { Ecdh1PU, EcdhEs, Jwk, Key, KeyAlgs } from 'aries-askar-shared'

import { base64url, setup } from './utils'

describe('jose ecdh', () => {
  beforeAll(() => setup())

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

    const encryptedMessage = new EcdhEs({ apv, apu, algId: encAlg }).encryptDirect({
      encAlg,
      ephemeralKey,
      message,
      receiverKey: bobJwk,
      aad: Uint8Array.from(Buffer.from(protectedB64)),
    })

    const { nonce, tag, ciphertext } = encryptedMessage.parts

    const messageReceived = new EcdhEs({ algId: encAlg, apu, apv }).decryptDirect({
      encAlg,
      ephemeralKey: ephemeralJwk,
      receiverKey: bobKey,
      ciphertext,
      nonce,
      tag,
      aad: Uint8Array.from(Buffer.from(protectedB64)),
    })
    expect(Buffer.from(messageReceived).toString()).toStrictEqual(messageString)
  })

  test('ecdh 1pu wrapped expected', () => {
    const ephem = Jwk.fromJson({
      crv: 'X25519',
      kty: 'OKP',
      d: 'x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8',
      x: 'k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc',
    }).toKey()

    const alice = Jwk.fromJson({
      crv: 'X25519',
      kty: 'OKP',
      d: 'i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU',
      x: 'Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4',
    }).toKey()

    const bob = Jwk.fromJson({
      crv: 'X25519',
      kty: 'OKP',
      d: '1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg',
      x: 'BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw',
    }).toKey()

    const alg = 'ECDH-1PU+A128KW'
    const enc = KeyAlgs.AesA256CbcHs512
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
      alg: KeyAlgs.AesA256CbcHs512,
      secretKey: Uint8Array.from(
        Buffer.from(
          'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0',
          'hex'
        )
      ),
    })

    const iv = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    const message = Uint8Array.from(Buffer.from('Three is a magic number.'))

    const encoded = cek.aeadEncrypt({ message, nonce: iv, aad: protectedB64Bytes })

    const ciphertext = encoded.ciphertext
    const ccTag = encoded.tag

    const expectedCiphertext = Uint8Array.from(Buffer.from('Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw', 'base64url'))
    const expectedCcTag = Uint8Array.from(Buffer.from('HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ', 'base64url'))

    expect(ciphertext).toStrictEqual(expectedCiphertext)
    expect(ccTag).toStrictEqual(expectedCcTag)

    // TODO: this should also accept a string
    const derived = new Ecdh1PU({
      apv: Uint8Array.from(Buffer.from(apv)),
      apu: Uint8Array.from(Buffer.from(apu)),
      algId: Uint8Array.from(Buffer.from(alg)),
    })
  })
})
