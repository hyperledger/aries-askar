import type { KeyAlgs } from '../enums'

import { ariesAskar } from '../ariesAskar'

import { Key } from './Key'

// Tests
export class Ecdh1PU {
  // TODO: what type
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
    receiverKey,
    senderKey,
    receive,
    ccTag,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key
    receiverKey: Key
    senderKey: Key
    receive: boolean
    ccTag?: Uint8Array
  }): Key {
    return new Key(
      ariesAskar.keyDeriveEcdh1pu({
        algId: this.algId,
        receive,
        apv: this.apv,
        apu: this.apu,
        alg: encAlg,
        ephemKey: ephemeralKey.handle,
        recipKey: receiverKey.handle,
        senderKey: senderKey.handle,
        ccTag,
      })
    )
  }

  public encryptDirect({
    encAlg,
    receiverKey,
    ephemeralKey,
    senderKey,
    message,
    aad,
    nonce,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key
    receiverKey: Key
    senderKey: Key
    message: Uint8Array
    aad?: Uint8Array
    nonce?: Uint8Array
  }) {
    const derived = this.deriveKey({ encAlg, ephemeralKey, receiverKey, senderKey, receive: false })
    return derived.aeadEncrypt({ message, aad, nonce })
  }

  public decryptDirect({
    nonce,
    encAlg,
    receiverKey,
    ephemeralKey,
    senderKey,
    ciphertext,
    tag,
    aad,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key
    receiverKey: Key
    senderKey: Key
    ciphertext: Uint8Array
    nonce: Uint8Array
    tag: Uint8Array
    aad?: Uint8Array
  }) {
    const derived = this.deriveKey({ encAlg, ephemeralKey, receiverKey, senderKey, receive: true })
    return derived.aeadDecrypt({ tag, nonce, ciphertext, aad })
  }

  public senderWrapKey({
    wrapAlg,
    ephemeralKey,
    receiverKey,
    senderKey,
    cek,
    ccTag,
  }: {
    wrapAlg: KeyAlgs
    ephemeralKey: Key
    receiverKey: Key
    senderKey: Key
    cek: Key
    ccTag: Uint8Array
  }) {
    const derived = this.deriveKey({ encAlg: wrapAlg, ephemeralKey, receiverKey, senderKey, receive: false, ccTag })
    return derived.wrapKey({ other: cek })
  }

  public receiverWrapKey({
    wrapAlg,
    receiverKey,
    ephemeralKey,
    senderKey,
    encAlg,
    ciphertext,
    nonce,
    tag,
    ccTag,
  }: {
    wrapAlg: KeyAlgs
    encAlg: KeyAlgs
    ephemeralKey: Key
    receiverKey: Key
    senderKey: Key
    ciphertext: Uint8Array
    nonce?: Uint8Array
    tag?: Uint8Array
    ccTag: Uint8Array
  }) {
    const derived = this.deriveKey({ encAlg: wrapAlg, ephemeralKey, receiverKey, receive: true, senderKey, ccTag })
    derived.unwrapKey({ tag, nonce, ciphertext, alg: encAlg })
  }
}
