import { Key, KeyAlgs } from 'aries-askar-shared'

import { setup } from './utils'

describe('keys', () => {
  beforeAll(() => setup())
  test('aes cbc hmac', () => {
    const key = Key.generate(KeyAlgs.AesA128CbcHs256)
    expect(key.algorithm).toStrictEqual(KeyAlgs.AesA128CbcHs256)

    const message = new Uint8Array(32).fill(1)
    const aad = new Uint8Array(32).fill(1)
    const nonce = key.aeadRandomNonce
    const params = key.aeadParams
    expect(params.nonceLength).toStrictEqual(16)
    expect(params.tagLength).toStrictEqual(16)
    const enc = key.aeadEncrypt({ message, nonce, aad })
    console.log(enc)
    // const dec = key.aeadDecrypt({ ciphertext: enc.buffer, nonce, aad })
  })

  test('Key wrap Key', () => {
    const key = Key.generate(KeyAlgs.AesA128CbcHs256)
    const nonce = key.aeadRandomNonce
    const key2 = Key.generate(KeyAlgs.AesA128CbcHs256)
    const key3 = key.wrapKey({ other: key2, nonce })
    console.log(key3)
  })
})
