import { Key, KeyAlgs } from 'aries-askar-shared'

import { setup } from './utils'

describe('keys', () => {
  beforeAll(() => setup())
  test('aes cbc hmac', () => {
    const key = Key.generate(KeyAlgs.AesA128CbcHs256)
    expect(key.algorithm).toStrictEqual(KeyAlgs.AesA128CbcHs256)

    const message = Buffer.from('test message')
    const aad = Buffer.from('aad')
    const nonce = key.aeadRandomNonce
    const params = key.aeadParams
    expect(params.nonceLength).toStrictEqual(16)
    expect(params.tagLength).toStrictEqual(16)
    const enc = key.aeadEncrypt({ message, nonce, aad })
    // TODO: why is this empty at all properties
    console.log(enc)
    // const dec = key.aeadDecrypt({ ciphertext: enc.buffer, nonce, aad })
  })
})
