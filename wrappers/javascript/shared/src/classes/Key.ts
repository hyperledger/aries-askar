import type { KeyAlgs } from '../KeyAlgs'
import type { LocalKeyHandle } from './handles'

import { getKeyAlgs } from '../KeyAlgs'
import type { SigAlgs } from '../SigAlgs'
import { ariesAskar } from '../ariesAskar'

export class Key {
  private localKeyHandle: LocalKeyHandle

  public constructor(handle: LocalKeyHandle) {
    this.localKeyHandle = handle
  }

  public static generate(alg: KeyAlgs, ephemeral = false) {
    return new Key(ariesAskar.keyGenerate({ alg, ephemeral }))
  }

  // TODO: enum the method
  public static fromSeed(alg: KeyAlgs, seed: Uint8Array, method = '') {
    return new Key(ariesAskar.keyFromSeed({ alg, seed, method }))
  }

  public static fromSecretBytes(alg: KeyAlgs, secretKey: Uint8Array) {
    return new Key(ariesAskar.keyFromSecretBytes({ alg, secretKey }))
  }

  public static fromPublicBytes(alg: KeyAlgs, publicKey: Uint8Array) {
    return new Key(ariesAskar.keyFromPublicBytes({ alg, publicKey }))
  }

  // TODO: type of jwk
  public static fromJwk(jwk: Uint8Array) {
    return new Key(ariesAskar.keyFromJwk({ jwk }))
  }

  public convertkey(alg: KeyAlgs) {
    return new Key(ariesAskar.keyConvert({ alg, localKeyHandle: this.handle }))
  }

  public keyFromKeyExchange(alg: KeyAlgs, publicKey: Key) {
    return new Key(ariesAskar.keyFromKeyExchange({ alg, pkHandle: publicKey.handle, skHandle: this.handle }))
  }

  public get handle() {
    return this.localKeyHandle.handle
  }

  public get algorithm() {
    const alg = ariesAskar.keyGetAlgorithm({ localKeyHandle: this.handle })
    return getKeyAlgs(alg)
  }

  public get ephemeral() {
    return Boolean(ariesAskar.keyGetEphemeral({ localKeyHandle: this.handle }))
  }

  public get publicBytes() {
    return ariesAskar.keyGetPublicBytes({ localKeyHandle: this.handle })
  }

  public get secretBytes() {
    return ariesAskar.keyGetSecretBytes({ localKeyHandle: this.handle })
  }

  public get jwkPublic() {
    return ariesAskar.keyGetJwkPublic({ localKeyHandle: this.handle })
  }

  public get jwkSecret() {
    return ariesAskar.keyGetJwkSecret({ localKeyHandle: this.handle })
  }

  public get jwkThumbprint() {
    return ariesAskar.keyGetJwkThumbprint({ localKeyHandle: this.handle })
  }

  public get aeadParams() {
    return ariesAskar.keyAeadGetParams({ localKeyHandle: this.handle })
  }

  public get aeadRandomNonce() {
    return ariesAskar.keyAeadRandomNonce({ localKeyHandle: this.handle })
  }

  public aeadEncrypt(aad: Uint8Array, message: Uint8Array, nonce: Uint8Array) {
    return ariesAskar.keyAeadEncrypt({ localKeyHandle: this.handle, aad, message, nonce })
  }

  public aeadDecrypt(aad: Uint8Array, cipherText: Uint8Array, tag: Uint8Array, nonce: Uint8Array) {
    return ariesAskar.keyAeadDecrypt({ localKeyHandle: this.handle, aad, nonce, cipherText, tag })
  }

  public signMessage(message: Uint8Array, sigType?: SigAlgs) {
    return ariesAskar.keySignMessage({ localKeyHandle: this.handle, message, sigType })
  }

  public verifyMessage(message: Uint8Array, signature: Uint8Array, sigType?: SigAlgs) {
    return ariesAskar.keyVerifySignature({ localKeyHandle: this.handle, sigType, signature, message })
  }

  public wrapKey(other: Key, nonce: Uint8Array) {
    return ariesAskar.keyWrapKey({ localKeyHandle: this.handle, nonce, other: other.handle })
  }

  public unwrapKey(alg: KeyAlgs, tag: Uint8Array, ciphertext: Uint8Array, nonce: Uint8Array) {
    return ariesAskar.keyUnwrapKey({ localKeyHandle: this.handle, nonce, tag, alg, ciphertext })
  }
}
