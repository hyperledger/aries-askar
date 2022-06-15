import { Callback } from 'ffi-napi'
import { refType } from 'ref-napi'

import { allocateCallbackBuffer } from './alloc'
import { FFI_VOID, FFI_CALLBACK_ID, FFI_ERROR_CODE, FFI_STRING, FFI_INT32 } from './primitives'

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
