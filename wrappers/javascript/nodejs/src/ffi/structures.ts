import refArray from 'ref-array-di'
import { default as ref, refType } from 'ref-napi'
import refStruct from 'ref-struct-di'

import { FFI_INT32, FFI_INT64, FFI_UINT8 } from './primitives'

const CStruct = refStruct(ref)
const CArray = refArray(ref)

export const ByteBufferArray = CArray(FFI_UINT8)
export const ByteBufferArrayPtr = refType(ByteBufferArray)

export const ByteBufferStruct = CStruct({
  len: FFI_INT64,
  data: ByteBufferArrayPtr,
})

const ByteBufferStructPtr = ref.refType(ByteBufferStruct)

export const SecretBufferStruct = ByteBufferStruct

export const SecretBufferStructPtr = ByteBufferStructPtr

export const EncryptedBufferStruct = CStruct({
  buffer: SecretBufferStruct,
  tag_pos: FFI_INT64,
  nonce_pos: FFI_INT64,
})

export const EncryptedBufferStructPtr = ref.refType(EncryptedBufferStruct)

export const AeadParamsStruct = CStruct({
  nonceLength: FFI_INT32,
  tagLength: FFI_INT32,
})

export const AeadParamsStructPtr = ref.refType(AeadParamsStruct)

export type ByteBufferType = typeof ByteBufferStruct
export type SecretBufferType = typeof SecretBufferStruct
export type EncryptedBufferType = typeof EncryptedBufferStruct
export type AeadParamsType = typeof AeadParamsStruct
