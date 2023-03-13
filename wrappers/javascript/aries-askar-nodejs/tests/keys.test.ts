import { Key, KeyAlgs, KeyMethod } from '@hyperledger/aries-askar-shared'

describe('keys', () => {
  beforeAll(() => {
    require('@hyperledger/aries-askar-nodejs')
  })

  test('aes cbc hmac', () => {
    const key = Key.generate(KeyAlgs.AesA128CbcHs256)
    expect(key.algorithm).toStrictEqual(KeyAlgs.AesA128CbcHs256)

    const messageString = 'test message'
    const message = Uint8Array.from(Buffer.from(messageString))
    const aeadNonce = key.aeadRandomNonce
    const params = key.aeadParams
    expect(params.nonceLength).toStrictEqual(16)
    expect(params.tagLength).toStrictEqual(16)
    const enc = key.aeadEncrypt({ message, nonce: aeadNonce })
    const dec = key.aeadDecrypt(enc.parts)
    expect(dec).toStrictEqual(message)
  })

  test('Bls G2 Keygen', () => {
    const seed = Uint8Array.from(Buffer.from('testseed000000000000000000000001'))
    const key = Key.fromSeed({ algorithm: KeyAlgs.Bls12381G2, seed })

    expect(key.jwkPublic).toMatchObject({
      crv: 'BLS12381_G2',
      kty: 'OKP',
      x: 'lH6hIRPzjlKW6LvPm0sHqyEbGqf8ag7UWpA_GFfefwq_kzDXSHmls9Yoza_be23zEw-pSOmKI_MGR1DahBa7Jbho2BGwDNV_QmyhxMYBwTH12Ltk_GLyPD4AP6pQVgge',
    })
  })

  test('Bls G1 Keygen', () => {
    const seed = Uint8Array.from(Buffer.from('testseed000000000000000000000001'))
    const key = Key.fromSeed({ algorithm: KeyAlgs.Bls12381G1, seed })

    expect(key.jwkPublic).toMatchObject({
      crv: 'BLS12381_G1',
      kty: 'OKP',
      x: 'hsjb9FSBUJXuB1fCluEcUBLeAPgIbnZGfxPKyeN3LVjQaKFWzXfNtMFAY8VL-eu-',
    })
  })

  test('Bls G1G2 Keygen', () => {
    const seed = Uint8Array.from(Buffer.from('testseed000000000000000000000001'))
    const key = Key.fromSeed({ algorithm: KeyAlgs.Bls12381G1G2, seed, method: KeyMethod.BlsKeygen })

    expect(key.jwkPublic).toMatchObject({
      crv: 'BLS12381_G1G2',
      kty: 'OKP',
      x: 'h56eYI8Qkq5hitICb-ik8wRTzcn6Fd4iY8aDNVc9q1xoPS3lh4DB_B4wNtar1HrViZIOsO6BgLV72zCrBE2ym3DEhDYcghnUMO4O8IVVD8yS-C_zu6OA3L-ny-AO4rbkAo-WuApZEjn83LY98UtoKpTufn4PCUFVQZzJNH_gXWHR3oDspJaCbOajBfm5qj6d',
    })
  })

  test('ed25519', () => {
    const key = Key.generate(KeyAlgs.Ed25519)
    expect(key.algorithm).toStrictEqual(KeyAlgs.Ed25519)
    const message = Uint8Array.from(Buffer.from('test message'))
    const signature = key.signMessage({ message })
    expect(key.verifySignature({ message, signature })).toStrictEqual(true)

    const x25519Key = key.convertkey({ algorithm: KeyAlgs.X25519 })
    const x25519Key2 = Key.generate(KeyAlgs.X25519)

    const kex = x25519Key.keyFromKeyExchange({ algorithm: KeyAlgs.Chacha20XC20P, publicKey: x25519Key2 })
    expect(kex).toBeInstanceOf(Key)

    expect(key.jwkPublic).toMatchObject({
      kty: 'OKP',
      crv: 'Ed25519',
    })

    expect(key.jwkSecret).toMatchObject({
      kty: 'OKP',
      crv: 'Ed25519',
    })
  })
})
