import type { ByteBufferType } from './ffiTypes'
import type { SecretBuffer } from 'aries-askar-shared'
import type array from 'ref-array-di'
import type { Pointer } from 'ref-napi'

import { AriesAskarError, ByteBuffer } from 'aries-askar-shared'
import { Callback } from 'ffi-napi'
import { refType, alloc } from 'ref-napi'

import {
  FFI_VOID,
  FFI_POINTER,
  FFI_INT8,
  ByteBufferStruct,
  FFI_CALLBACK_ID,
  FFI_ERROR_CODE,
  FFI_INT32,
  FFI_STRING,
  SecretBufferStruct,
  EncryptedBufferStruct,
  AeadParamsStruct,
} from './ffiTypes'

export const allocatePointer = (): Buffer => alloc(FFI_POINTER)

export const allocateStringBuffer = (): Buffer => alloc(FFI_STRING)

export const allocateInt32Buffer = (): Buffer => alloc(FFI_INT32)

export const allocateInt8Buffer = (): Buffer => alloc(FFI_INT8)

export const allocateSecretBuffer = (): Buffer => alloc(SecretBufferStruct)

export const allocateEncryptedBuffer = (): Buffer => alloc(EncryptedBufferStruct)

export const allocateAeadParams = (): Buffer => alloc(AeadParamsStruct)

export const allocateLocalKeyHandle = allocatePointer

export const allocateCallbackBuffer = (callback: Buffer) => setTimeout(() => callback, 1000000)

export const deallocateCallbackBuffer = (id: number) => clearTimeout(id as unknown as NodeJS.Timeout)

export const byteBufferClassToStruct = ({ len, data }: ByteBuffer) =>
  ByteBufferStruct({
    len,
    data: Buffer.from(data) as Pointer<array.TypedArray<number, number>>,
  })

export const secretBufferToUint8Array = (buffer: SecretBuffer) => {
  return new Uint8Array(buffer.data)
}

export const byteBufferToReference = (byteBuffer: ByteBufferType) => {
  throw new AriesAskarError({ message: 'Method byteBufferToReference not implemented', code: 100 })
}

export const secretBufferClassToStruct = byteBufferClassToStruct

export const secretBufferToReference = byteBufferToReference

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
export const toNativeCallbackWithResponse = <R>(cb: NativeCallbackWithResponse<R>, responseFfiType = FFI_STRING) => {
  const nativeCallback = Callback(FFI_VOID, [FFI_CALLBACK_ID, FFI_ERROR_CODE, responseFfiType], cb)
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
