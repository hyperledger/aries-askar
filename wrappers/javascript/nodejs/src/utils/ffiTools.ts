/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import type { SecretBufferType, ByteBufferType } from './ffiTypes'
import type array from 'ref-array-di'
import type { NamedTypeLike, Pointer, Type } from 'ref-napi'

import type { SecretBuffer } from 'aries-askar-shared';
import { ByteBuffer, KeyAlgs } from 'aries-askar-shared'
import { Callback } from 'ffi-napi'
import { refType, alloc } from 'ref-napi'

import { LocalKeyHandleStruct } from '../structures'
import { AesA128CbcHs256 } from '../structures/AesA128CbcHs256'
import { AesA128Gcm } from '../structures/AesA128Gcm'
import { AesA128Kw } from '../structures/AesA128Kw'
import { AesA256CbcHs512 } from '../structures/AesA256CbcHs512'
import { AesA256Gcm } from '../structures/AesA256Gcm'
import { AesA256Kw } from '../structures/AesA256Kw'
import { Bls12381g1 } from '../structures/Bls12381G1'
import { Bls12381g2 } from '../structures/Bls12381G2'
import { Chacha20C20P } from '../structures/Chacha20C20P'
import { Chacha20XC20P } from '../structures/Chacha20XC20P'
import { EcSecp256k1 } from '../structures/EcSecp256k1'
import { EcSecp256r1 } from '../structures/EcSecp256r1'
import { Ed25519KeyPair } from '../structures/Ed25519KeyPair'
import { X25519KeyPair } from '../structures/X25519KeyPair'

import {
  FFI_INT8,
  ByteBufferStruct,
  FFI_CALLBACK_ID,
  FFI_ERROR_CODE,
  FFI_INT32,
  FFI_STRING,
  FFI_VOID,
  SecretBufferStruct,
  EncryptedBufferStruct,
  AeadParamsStruct,
} from './ffiTypes'

export const allocateStringBuffer = (): Buffer => alloc(FFI_STRING)

export const allocateInt32Buffer = (): Buffer => alloc(FFI_INT32)

export const allocateInt8Buffer = (): Buffer => alloc(FFI_INT8)

export const allocateSecretBuffer = (len = 32): Buffer => alloc(SecretBufferStruct(len))

export const allocateEncryptedBuffer = (len = 32): Buffer => alloc(EncryptedBufferStruct(len))

export const allocateAeadParams = (): Buffer => alloc(AeadParamsStruct)

export const allocateLocalKeyHandle = (keyType: NamedTypeLike): Buffer => alloc(LocalKeyHandleStruct(keyType))

export const allocateCallbackBuffer = (callback: Buffer) => setTimeout(() => callback, 1000000)

export const deallocateCallbackBuffer = (id: number) => clearTimeout(id as unknown as NodeJS.Timeout)

export const byteBufferClassToStruct = ({ len, data }: ByteBuffer) =>
  ByteBufferStruct({
    len,
    data: Buffer.from(data) as Pointer<array.TypedArray<number, 32>>,
  })

export const secretBufferToUint8Array = (buffer: SecretBuffer) => {
  return new Uint8Array(buffer.data)
}

export const byteBufferToReference = (byteBuffer: ByteBufferType) =>
  byteBuffer.ref() as unknown as Type<typeof ByteBufferStruct>

export const secretBufferClassToStruct = byteBufferClassToStruct

export const secretBufferToReference = (secretBuffer: SecretBufferType) =>
  secretBuffer.ref() as unknown as Type<typeof SecretBufferStruct>

export const uint8arrayToByteBufferStruct = (buf: Uint8Array) => {
  const byteBuffer = ByteBuffer.fromUint8Array(buf)
  return byteBufferClassToStruct(byteBuffer)
}

export const getStructForKeyAlg = (alg: KeyAlgs) => {
  // Object map
  switch (alg) {
    case KeyAlgs.Ed25519:
      return Ed25519KeyPair
    case KeyAlgs.Chacha20C20P:
      return Chacha20C20P
    case KeyAlgs.Chacha20XC20P:
      return Chacha20XC20P
    case KeyAlgs.Bls12381G1:
      return Bls12381g1
    case KeyAlgs.Bls12381G2:
      return Bls12381g2
    case KeyAlgs.X25519:
      return X25519KeyPair
    case KeyAlgs.EcSecp256k1:
      return EcSecp256k1
    case KeyAlgs.EcSecp256r1:
      return EcSecp256r1
    case KeyAlgs.AesA128Gcm:
      return AesA128Gcm
    case KeyAlgs.AesA256Gcm:
      return AesA256Gcm
    case KeyAlgs.AesA128CbcHs256:
      return AesA128CbcHs256
    case KeyAlgs.AesA256CbcHs512:
      return AesA256CbcHs512
    case KeyAlgs.AesA128Kw:
      return AesA128Kw
    case KeyAlgs.AesA256Kw:
      return AesA256Kw
  }
}

export const getInnerAndEphemeral = <K extends Record<string, unknown>>(buf: Buffer, alg: KeyAlgs) => {
  const base = buf.deref().deref()
  return {
    bufRep: buf.deref(),
    // TODO: not static
    alg,
    inner: base.inner.deref() as K,
    ephemeral: base.ephemeral as boolean,
  }
}

export type NativeCallback = (id: number, errorCode: number) => void
export const toNativeCallback = (cb: NativeCallback) => {
  const nativeCallback = Callback(FFI_VOID, [FFI_CALLBACK_ID, FFI_ERROR_CODE], cb)
  const id = allocateCallbackBuffer(nativeCallback)
  return { nativeCallback, id }
}

export type NativeCallbackWithResponse<R> = (id: number, errorCode: number, response: R) => void
export const toNativeCallbackWithResponse = <R>(cb: NativeCallbackWithResponse<R>) => {
  const nativeCallback = Callback(FFI_VOID, [FFI_CALLBACK_ID, FFI_ERROR_CODE, FFI_STRING], cb)
  const id = allocateCallbackBuffer(nativeCallback)
  return { nativeCallback, id }
}

export type NativeCallbackWithHandle = (id: number, errorCode: number, handle: number) => void
export const toNativeCallbackWithHandle = (cb: NativeCallbackWithHandle) => {
  // TODO: is this int32
  const nativeCallback = Callback(FFI_VOID, [FFI_CALLBACK_ID, FFI_ERROR_CODE, FFI_INT32], cb)
  const id = allocateCallbackBuffer(nativeCallback)
  return { nativeCallback, id }
}

export type NativeCallbackWithIndex = (id: number, errorCode: number, index: number) => void
export const toNativeCallbackWithIndex = (cb: NativeCallbackWithIndex) => {
  // TODO: is this int32
  const nativeCallback = Callback(FFI_VOID, [FFI_CALLBACK_ID, FFI_ERROR_CODE, FFI_INT32], cb)
  const id = allocateCallbackBuffer(nativeCallback)
  return { nativeCallback, id }
}

export type NativeLogCallback = (
  context: unknown,
  level: number,
  target: string,
  message: string,
  modulePath: string,
  file: string,
  line: number
) => void
export const toNativeLogCallback = (cb: NativeLogCallback) => {
  const nativeCallback = Callback(
    FFI_VOID,
    [refType(FFI_VOID), FFI_INT32, FFI_STRING, FFI_STRING, FFI_STRING, FFI_STRING, FFI_INT32],
    cb
  )
  const id = allocateCallbackBuffer(nativeCallback)
  return { nativeCallback, id }
}
