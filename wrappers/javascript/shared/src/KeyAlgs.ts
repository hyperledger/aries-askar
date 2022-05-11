export enum KeyAlgs {
  AesA128Gcm = 'a128gcm',
  AesA256Gcm = 'a256gcm',
  AesA128CbcHs256 = 'a128cbchs256',
  AesA256CbcHs512 = 'a256cbchs512',
  AesA128Kw = 'a128kw',
  AesA256Kw = 'a256kw',
  Bls12381G1 = 'bls12381g1',
  Bls12381G2 = 'bls12381g2',
  Chacha20C20P = 'c20p',
  Chacha20XC20P = 'xc20p',
  Ed25519 = 'ed25519',
  X25519 = 'x25519',
  EcSecp256k1 = 'k256',
  EcSecp256r1 = 'p256',
}

export type AesA128CbcHs256Inner = {
  key: Uint8Array
}

export type AesA128GcmInner = {
  key: Uint8Array
}

export type AesA128KwInner = {
  key: Uint8Array
}

export type AesA256CbcHs512Inner = {
  key: Uint8Array
}

export type AesA256GcmInner = {
  key: Uint8Array
}

export type AesA256KwInner = {
  key: Uint8Array
}

export type Bls12381G1inner = {
  secret: Uint8Array
  public: {
    x: BigUint64Array
    y: BigUint64Array
  }
}

export type Bls12381G2inner = {
  secret: Uint8Array
  public: {
    x: BigUint64Array
    y: BigUint64Array
  }
}

export type EcSecp256k1Inner = {
  secret: Uint8Array
  public: {
    x: BigUint64Array
    y: BigUint64Array
  }
}

export type EcSecp256r1Inner = {
  secret: Uint8Array
  public: {
    x: BigUint64Array
    y: BigUint64Array
  }
}

export type Chacha20C20PInner = {
  key: Uint8Array
}

export type Chacha20XC20PInner = {
  key: Uint8Array
}

export type Ed25519Inner = {
  secret: Uint8Array
  public: {
    edwardsPoint: {
      x: BigUint64Array
      y: BigUint64Array
      z: BigUint64Array
      t: BigUint64Array
    }
    compressedEdwardsY: Uint8Array
  }
}

export type X25519Inner = {
  secret: Uint8Array
  public: {
    montgomeryPoint: Uint8Array
  }
}
