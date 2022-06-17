import type { KeyAlgs, SigAlgs } from '../enums'
import type { Jwk } from './Jwk'
import type { LocalKeyHandle } from './handles'

import { ariesAskar } from '../ariesAskar'
import { KeyMethod, keyAlgFromString } from '../enums'

// TODO: is this jwk type correct?

export class Key {
  private localKeyHandle: LocalKeyHandle

  public constructor(handle: LocalKeyHandle) {
    this.localKeyHandle = handle
  }

  public static generate(alg: KeyAlgs, ephemeral = false) {
    return new Key(ariesAskar.keyGenerate({ alg, ephemeral }))
  }

  // TODO: enum the method
  public static fromSeed({
    method = KeyMethod.None,
    alg,
    seed,
  }: {
    alg: KeyAlgs
    seed: Uint8Array
    method?: KeyMethod
  }) {
    return new Key(ariesAskar.keyFromSeed({ alg, method, seed }))
  }

  public static fromSecretBytes(options: { alg: KeyAlgs; secretKey: Uint8Array }) {
    return new Key(ariesAskar.keyFromSecretBytes(options))
  }

  public static fromPublicBytes(options: { alg: KeyAlgs; publicKey: Uint8Array }) {
    return new Key(ariesAskar.keyFromPublicBytes(options))
  }

  public static fromJwk(options: { jwk: Jwk }) {
    return new Key(ariesAskar.keyFromJwk(options))
  }

  public convertkey(options: { alg: KeyAlgs }) {
    return new Key(ariesAskar.keyConvert({ localKeyHandle: this.handle, ...options }))
  }

  public keyFromKeyExchange({ alg, publicKey }: { alg: KeyAlgs; publicKey: Key }) {
    return new Key(ariesAskar.keyFromKeyExchange({ skHandle: this.handle, pkHandle: publicKey.handle, alg }))
  }

  public get handle() {
    return this.localKeyHandle.handle
  }

  public get algorithm() {
    const alg = ariesAskar.keyGetAlgorithm({ localKeyHandle: this.handle })
    return keyAlgFromString(alg)
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
    return JSON.parse(ariesAskar.keyGetJwkPublic({ localKeyHandle: this.handle, algorithm: this.algorithm })) as Record<
      string,
      unknown
    >
  }

  public get jwkSecret() {
    return JSON.parse(ariesAskar.keyGetJwkSecret({ localKeyHandle: this.handle })) as Record<string, unknown>
  }

  public get jwkThumbprint() {
    return ariesAskar.keyGetJwkThumbprint({ localKeyHandle: this.handle, algorithm: this.algorithm })
  }

  public get aeadParams() {
    return ariesAskar.keyAeadGetParams({ localKeyHandle: this.handle })
  }

  public get aeadRandomNonce() {
    return ariesAskar.keyAeadRandomNonce({ localKeyHandle: this.handle })
  }

  public aeadEncrypt(options: { message: Uint8Array; nonce?: Uint8Array; aad?: Uint8Array }) {
    return ariesAskar.keyAeadEncrypt({ localKeyHandle: this.handle, ...options })
  }

  public aeadDecrypt(options: { ciphertext: Uint8Array; tag: Uint8Array; nonce: Uint8Array; aad?: Uint8Array }) {
    return ariesAskar.keyAeadDecrypt({ localKeyHandle: this.handle, ...options })
  }

  public signMessage(options: { message: Uint8Array; sigType?: SigAlgs }) {
    return ariesAskar.keySignMessage({ localKeyHandle: this.handle, ...options })
  }

  public verifySignature(options: { message: Uint8Array; signature: Uint8Array; sigType?: SigAlgs }) {
    return ariesAskar.keyVerifySignature({ localKeyHandle: this.handle, ...options })
  }

  public wrapKey({ other, nonce }: { other: Key; nonce?: Uint8Array }) {
    return ariesAskar.keyWrapKey({ localKeyHandle: this.handle, other: other.handle, nonce })
  }

  public unwrapKey(options: { alg: KeyAlgs; tag?: Uint8Array; ciphertext: Uint8Array; nonce?: Uint8Array }) {
    return ariesAskar.keyUnwrapKey({ localKeyHandle: this.handle, ...options })
  }
}
