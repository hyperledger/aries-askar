import type { SecretBufferType, ByteBufferType } from './ffiTypes'
import type array from 'ref-array-di'
import type { Pointer, Type } from 'ref-napi'

import { ByteBuffer } from 'aries-askar-shared'
import { Callback } from 'ffi-napi'
import { refType, alloc } from 'ref-napi'

import {
  ByteBufferStruct,
  FFI_CALLBACK_ID,
  FFI_ERROR_CODE,
  FFI_INT32,
  FFI_STRING,
  FFI_VOID,
  SecretBufferStruct,
  EncryptedBufferStruct,
  AeadParamsStruct,
  LocalKeyHandleStruct,
} from './ffiTypes'

export const allocateStringBuffer = (): Buffer => alloc(FFI_STRING)

export const allocateIntBuffer = (): Buffer => alloc(FFI_INT32)

export const allocateSecretBuffer = (): Buffer => alloc(SecretBufferStruct)

export const allocateEncryptedBuffer = (): Buffer => alloc(EncryptedBufferStruct)

export const allocateAeadParams = (): Buffer => alloc(AeadParamsStruct)

export const allocateLocalKeyHandle = (): Buffer => alloc(LocalKeyHandleStruct)

export const allocateCallbackBuffer = (callback: Buffer) => setTimeout(() => callback, 1000000)

export const deallocateCallbackBuffer = (id: number) => clearTimeout(id as unknown as NodeJS.Timeout)

export const byteBufferClassToStruct = ({ len, data }: ByteBuffer) =>
  ByteBufferStruct({
    len,
    data: Buffer.from(data) as Pointer<array.TypedArray<number, 32>>,
  })

export const byteBufferToReference = (byteBuffer: ByteBufferType) =>
  byteBuffer.ref() as unknown as Type<typeof ByteBufferStruct>

export const secretBufferClassToStruct = byteBufferClassToStruct

export const secretBufferToReference = (secretBuffer: SecretBufferType) =>
  secretBuffer.ref() as unknown as Type<typeof SecretBufferStruct>

export const uint8arrayToByteBufferStruct = (buf: Uint8Array) => {
  const byteBuffer = ByteBuffer.fromUint8Array(buf)
  return byteBufferClassToStruct(byteBuffer)
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
