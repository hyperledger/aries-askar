import { alloc } from 'ref-napi'

import { FFI_POINTER, FFI_STRING, FFI_INT32, FFI_INT8 } from './primitives'
import { SecretBufferStruct, EncryptedBufferStruct, AeadParamsStruct } from './structures'

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
