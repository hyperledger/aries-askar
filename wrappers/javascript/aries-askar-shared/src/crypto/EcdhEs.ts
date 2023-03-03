import type { KeyAlgs } from '../enums'

import { ariesAskar } from '../ariesAskar'

import { Jwk } from './Jwk'
import { Key } from './Key'

// Tests
export class EcdhEs {
  private algId: Uint8Array
  private apu: Uint8Array
  private apv: Uint8Array

  public constructor({ apv, apu, algId }: { algId: Uint8Array; apu: Uint8Array; apv: Uint8Array }) {
    this.algId = algId
    this.apu = apu
    this.apv = apv
  }

  private deriveKey({
    encAlg,
    ephemeralKey,
    recipientKey,
    receive,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key
    recipientKey: Key
    receive: boolean
  }): Key {
    return new Key(
      ariesAskar.keyDeriveEcdhEs({
        algId: this.algId,
        receive,
        apv: this.apv,
        apu: this.apu,
        algorithm: encAlg,
        ephemeralKey,
        recipientKey,
      })
    )
  }

  public encryptDirect({
    encAlg,
    recipientKey,
    ephemeralKey,
    message,
    aad,
    nonce,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key | Jwk
    recipientKey: Key | Jwk
    message: Uint8Array
    aad?: Uint8Array
    nonce?: Uint8Array
  }) {
    const eKey = ephemeralKey instanceof Jwk ? Key.fromJwk({ jwk: ephemeralKey }) : ephemeralKey
    const rKey = recipientKey instanceof Jwk ? Key.fromJwk({ jwk: recipientKey }) : recipientKey
    const derived = this.deriveKey({ encAlg, ephemeralKey: eKey, recipientKey: rKey, receive: false })
    const encryptedBuffer = derived.aeadEncrypt({ message, aad, nonce })
    derived.handle.free()
    return encryptedBuffer
  }

  public decryptDirect({
    nonce,
    encAlg,
    recipientKey,
    ciphertext,
    ephemeralKey,
    tag,
    aad,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key | Jwk
    recipientKey: Key | Jwk
    ciphertext: Uint8Array
    nonce: Uint8Array
    tag: Uint8Array
    aad?: Uint8Array
  }) {
    const eKey = ephemeralKey instanceof Jwk ? Key.fromJwk({ jwk: ephemeralKey }) : ephemeralKey
    const rKey = recipientKey instanceof Jwk ? Key.fromJwk({ jwk: recipientKey }) : recipientKey
    const derived = this.deriveKey({ encAlg, ephemeralKey: eKey, recipientKey: rKey, receive: true })
    const encryptedBuffer = derived.aeadDecrypt({ tag, nonce, ciphertext, aad })
    derived.handle.free()
    return encryptedBuffer
  }

  public senderWrapKey({
    wrapAlg,
    ephemeralKey,
    recipientKey,
    cek,
  }: {
    wrapAlg: KeyAlgs
    ephemeralKey: Key
    recipientKey: Key
    cek: Key
  }) {
    const derived = this.deriveKey({ encAlg: wrapAlg, ephemeralKey, recipientKey, receive: false })
    const encryptedBuffer = derived.wrapKey({ other: cek })
    derived.handle.free()
    return encryptedBuffer
  }

  public receiverUnwrapKey({
    recipientKey,
    wrapAlg,
    ephemeralKey,
    encAlg,
    ciphertext,
    nonce,
    tag,
  }: {
    wrapAlg: KeyAlgs
    encAlg: KeyAlgs
    ephemeralKey: Key
    recipientKey: Key
    ciphertext: Uint8Array
    nonce?: Uint8Array
    tag?: Uint8Array
  }) {
    const derived = this.deriveKey({ encAlg: wrapAlg, ephemeralKey, recipientKey, receive: true })
    const encryptedBuffer = derived.unwrapKey({ tag, nonce, ciphertext, algorithm: encAlg })
    derived.handle.free()
    return encryptedBuffer
  }
}
