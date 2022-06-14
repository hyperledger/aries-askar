import type { KeyAlgs } from '../enums'

import { ariesAskar } from '../ariesAskar'

import { Key } from './Key'

// Tests
export class EcdhEs {
  // TODO: what type
  private algId: string
  private apu: string
  private apv: string

  public constructor({ apv, apu, algId }: { algId: string; apu: string; apv: string }) {
    this.algId = algId
    this.apu = apu
    this.apv = apv
  }

  private deriveKey({
    encAlg,
    ephemeralKey,
    receiverKey,
    receive,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key
    receiverKey: Key
    receive: boolean
  }): Key {
    return new Key(
      ariesAskar.keyDeriveEcdhEs({
        algId: this.algId,
        receive,
        apv: this.apv,
        apu: this.apu,
        alg: encAlg,
        ephemKey: ephemeralKey.handle,
        recipKey: receiverKey.handle,
      })
    )
  }

  public encryptDirect({
    encAlg,
    receiverKey,
    ephemeralKey,
    message,
    aad,
    nonce,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key
    receiverKey: Key
    message: Uint8Array
    aad?: Uint8Array
    nonce?: Uint8Array
  }) {
    const derived = this.deriveKey({ encAlg, ephemeralKey, receiverKey, receive: false })
    return derived.aeadEncrypt({ message, aad, nonce })
  }

  public decryptDirect({
    nonce,
    encAlg,
    receiverKey,
    ciphertext,
    ephemeralKey,
    tag,
    aad,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key
    receiverKey: Key
    ciphertext: Uint8Array
    nonce: Uint8Array
    tag: Uint8Array
    aad?: Uint8Array
  }) {
    const derived = this.deriveKey({ encAlg, ephemeralKey, receiverKey, receive: true })
    return derived.aeadDecrypt({ tag, nonce, ciphertext, aad })
  }

  public senderWrapKey({
    wrapAlg,
    ephemeralKey,
    receiverKey,
    cek,
  }: {
    wrapAlg: KeyAlgs
    ephemeralKey: Key
    receiverKey: Key
    cek: Key
  }) {
    const derived = this.deriveKey({ encAlg: wrapAlg, ephemeralKey, receiverKey, receive: false })
    return derived.wrapKey({ other: cek })
  }

  public receiverWrapKey({
    receiverKey,
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
    receiverKey: Key
    ciphertext: Uint8Array
    nonce?: Uint8Array
    tag?: Uint8Array
  }) {
    const derived = this.deriveKey({ encAlg: wrapAlg, ephemeralKey, receiverKey, receive: true })
    derived.unwrapKey({ tag, nonce, ciphertext, alg: encAlg })
  }
}
