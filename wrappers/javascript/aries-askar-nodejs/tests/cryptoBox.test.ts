import { CryptoBox, Key, KeyAlgs } from '@hyperledger/aries-askar-shared'

describe('CryptoBox', () => {
  beforeAll(() => {
    require('@hyperledger/aries-askar-nodejs')
  })

  test('seal', () => {
    const x25519Key = Key.generate(KeyAlgs.X25519)

    const message = Uint8Array.from(Buffer.from('foobar'))
    const sealed = CryptoBox.seal({ recipientKey: x25519Key, message })

    const opened = CryptoBox.sealOpen({ recipientKey: x25519Key, ciphertext: sealed })
    expect(opened).toStrictEqual(message)
    x25519Key.handle.free()
  })
})
