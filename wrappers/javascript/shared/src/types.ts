import type { KeyAlgs } from './enums'

type ByteBufferOptions = {
  len: number
  data: Uint8Array
}

type SecretBufferOptions = ByteBufferOptions

type EncryptedBufferOptions = {
  buffer: Uint8Array
  tagPos: number
  noncePos: number
}

type AeadParamsOptions = {
  nonce_length: number
  tag_length: number
}

export class ByteBuffer {
  public len: number
  public data: Uint8Array

  public constructor({ data, len }: ByteBufferOptions) {
    this.data = data
    this.len = len
  }

  public static fromUint8Array(data: Uint8Array): ByteBuffer {
    return new ByteBuffer({ data, len: data.length })
  }
}

export class SecretBuffer {
  public len: number
  public data: Uint8Array

  public constructor({ data, len }: SecretBufferOptions) {
    this.data = data
    this.len = len
  }

  public static fromUint8Array(data: Uint8Array): SecretBuffer {
    return new SecretBuffer({ data, len: data.length })
  }
}

export class EncryptedBuffer {
  public buffer: Uint8Array
  public tagPos: number
  public noncePos: number

  public constructor({ noncePos, tagPos, buffer }: EncryptedBufferOptions) {
    this.buffer = buffer
    this.tagPos = tagPos
    this.noncePos = noncePos
  }
}

export class AeadParams {
  public nonceLength: number
  public tagLength: number

  public constructor({ nonce_length, tag_length }: AeadParamsOptions) {
    this.nonceLength = nonce_length
    this.tagLength = tag_length
  }
}

export interface ILocalKeyHandle<K = Record<string, unknown>> {
  alg: KeyAlgs
  inner: K
  ephemeral: boolean
}
