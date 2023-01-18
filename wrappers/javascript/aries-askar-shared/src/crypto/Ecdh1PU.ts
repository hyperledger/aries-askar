import type { KeyAlgs } from '../enums'

import { ariesAskar } from '../ariesAskar'

import { Key } from './Key'

// Tests
export class Ecdh1PU {
  private algId: Uint8Array
  private apu: Uint8Array
  private apv: Uint8Array

  public constructor({ apv, apu, algId }: { algId: Uint8Array; apu: Uint8Array; apv: Uint8Array }) {
    this.algId = algId
    this.apu = apu
    this.apv = apv
  }

  public deriveKey({
    encAlg,
    ephemeralKey,
    recipientKey,
    senderKey,
    receive,
    ccTag,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key
    recipientKey: Key
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
        algorithm: encAlg,
        ephemeralKey: ephemeralKey,
        recipientKey: recipientKey,
        senderKey: senderKey,
        ccTag,
      })
    )
  }

  public encryptDirect({
    encAlg,
    recipientKey,
    ephemeralKey,
    senderKey,
    message,
    aad,
    nonce,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key
    recipientKey: Key
    senderKey: Key
    message: Uint8Array
    aad?: Uint8Array
    nonce?: Uint8Array
  }) {
    const derived = this.deriveKey({ encAlg, ephemeralKey, recipientKey, senderKey, receive: false })
    return derived.aeadEncrypt({ message, aad, nonce })
  }

  public decryptDirect({
    nonce,
    encAlg,
    recipientKey,
    ephemeralKey,
    senderKey,
    ciphertext,
    tag,
    aad,
  }: {
    encAlg: KeyAlgs
    ephemeralKey: Key
    recipientKey: Key
    senderKey: Key
    ciphertext: Uint8Array
    nonce: Uint8Array
    tag: Uint8Array
    aad?: Uint8Array
  }) {
    const derived = this.deriveKey({ encAlg, ephemeralKey, recipientKey, senderKey, receive: true })
    return derived.aeadDecrypt({ tag, nonce, ciphertext, aad })
  }

  public senderWrapKey({
    wrapAlg,
    ephemeralKey,
    recipientKey,
    senderKey,
    cek,
    ccTag,
  }: {
    wrapAlg: KeyAlgs
    ephemeralKey: Key
    recipientKey: Key
    senderKey: Key
    cek: Key
    ccTag: Uint8Array
  }) {
    const derived = this.deriveKey({
      encAlg: wrapAlg,
      ephemeralKey,
      recipientKey,
      senderKey,
      receive: false,
      ccTag,
    })
    return derived.wrapKey({ other: cek })
  }

  public receiverUnwrapKey({
    wrapAlg,
    encAlg,
    recipientKey,
    ephemeralKey,
    senderKey,
    ciphertext,
    nonce,
    tag,
    ccTag,
  }: {
    wrapAlg: KeyAlgs
    encAlg: KeyAlgs
    ephemeralKey: Key
    recipientKey: Key
    senderKey: Key
    ciphertext: Uint8Array
    nonce?: Uint8Array
    tag?: Uint8Array
    ccTag: Uint8Array
  }) {
    const derived = this.deriveKey({
      encAlg: wrapAlg,
      ephemeralKey,
      recipientKey,
      receive: true,
      senderKey,
      ccTag,
    })
    return derived.unwrapKey({ tag, nonce, ciphertext, algorithm: encAlg })
  }
}
