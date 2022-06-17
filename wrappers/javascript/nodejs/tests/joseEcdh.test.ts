import { Ecdh1PU, EcdhEs, Jwk, Key, KeyAlgs, registerAriesAskar } from 'aries-askar-shared'
import base64url from 'base64url'

import { NodeJSAriesAskar } from '../src'

describe('jose ecdh', () => {
  beforeAll(() => {
    registerAriesAskar({ askar: new NodeJSAriesAskar() })
  })
  xtest('ecdh es direct', () => {
    const bobKey = Key.generate(KeyAlgs.EcSecp256r1)
    const ephemeralKey = Key.generate(KeyAlgs.EcSecp256r1)
    const message = Buffer.from('Hello there')
    const apu = 'Alice'
    const apv = 'Bob'
    const enc = 'A256GCM'

    const encryptedMessage = new EcdhEs({ apv, apu, algId: enc }).encryptDirect({
      encAlg: KeyAlgs.AesA256Gcm,
      ephemeralKey,
      message,
      receiverKey: bobKey,
    })

    console.log(encryptedMessage)
  })

  test('ecdh 1pu wrapped expected', () => {
    const ephemJwk = Jwk.fromJson({
      crv: 'X25519',
      kty: 'OKP',
      d: 'x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8',
      x: 'k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc',
    })

    const ephem = Key.fromJwk({ jwk: ephemJwk })

    const aliceJwk = Jwk.fromJson({
      crv: 'X25519',
      kty: 'OKP',
      d: 'i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU',
      x: 'Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4',
    })

    const alice = Key.fromJwk({ jwk: aliceJwk })

    const bobJwk = Jwk.fromJson({
      crv: 'X25519',
      kty: 'OKP',
      d: '1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg',
      x: 'BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw',
    })

    const bob = Key.fromJwk({ jwk: bobJwk })

    const alg = 'ECDH-1PU+A128KW'
    const enc = 'A256CBC-HS512'
    const apu = 'Alice'
    const apv = 'Bob and Charlie'

    const protectedJson = {
      alg,
      enc,
      apu: base64url(apu),
      apv: base64url(apv),
      epk: {
        kty: 'OKP',
        crv: 'X25519',
        x: 'k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc',
      },
    }
    const protectedString = JSON.stringify(protectedJson)
    const protectedB64 = base64url(protectedString)
    const protectedB64Buffer = Buffer.from(protectedB64)

    expect(protectedJson).toMatchObject({
      apu: 'QWxpY2U', // Alice
      apv: 'Qm9iIGFuZCBDaGFybGll', // Bob and Charlie
    })

    const cek = Key.fromSecretBytes({
      alg: KeyAlgs.AesA256CbcHs512,
      secretKey: Uint8Array.from(
        Buffer.from(
          'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0',
          'hex'
        )
      ),
    })
    const iv = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex')
    const message = Uint8Array.from(Buffer.from('Three is a magic number'))

    // TODO:
    const encoded = cek.aeadEncrypt({ message, nonce: iv, aad: Uint8Array.from(protectedB64Buffer) })
    const cipherText = encoded.buffer
    const tag = encoded.tagPos

    // TODO: this should also accept a string
    const derived = new Ecdh1PU({
      apv: Uint8Array.from(Buffer.from(apv)),
      apu: Uint8Array.from(Buffer.from(apu)),
      algId: Uint8Array.from(Buffer.from(alg)),
    })
  })
})
