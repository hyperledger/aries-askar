import { default as array } from 'ref-array-di'
import * as ref from 'ref-napi'
import { default as struct } from 'ref-struct-di'

const CStruct = struct(ref)
const CArray = array(ref)

// Primitives

const FFI_UINT8 = 'uint8'

const FFI_UINT64 = 'uint64'

const FFI_USIZE = 'size_t'

export const FFI_INT8 = 'int8'
export const FFI_INT8_PTR = ref.refType(FFI_INT8)

export const FFI_INT32 = 'int32'
export const FFI_INT32_PTR = ref.refType(FFI_INT32)

export const FFI_INT64 = 'int64'

// TODO: does this make sense? it is not provided by `ref.types.`
export const FFI_STRING = 'string'
export const FFI_STRING_PTR = ref.refType(FFI_STRING)

export const FFI_VOID = 'void'

// TODO: does this make sense? it is not provided by `ref.types.`
export const FFI_POINTER = 'pointer'

// Custom

export const FFI_CALLBACK_ID = FFI_INT64
export const FFI_CALLBACK_PTR = FFI_POINTER

export const ByteBufferArray = CArray(FFI_UINT8)
export const ByteBufferArrayPtr = ref.refType(ByteBufferArray)

export const FFI_ERROR_CODE = FFI_INT64

// Handles

const FFI_ARC_HANDLE = FFI_POINTER
export const FFI_ENTRY_LIST_HANDLE = FFI_ARC_HANDLE
export const FFI_KEY_ENTRY_LIST_HANDLE = FFI_ARC_HANDLE
export const FFI_LOCAL_KEY_HANDLE = FFI_ARC_HANDLE

// TODO: are these numbers
export const FFI_SESSION_HANDLE = FFI_USIZE
export const FFI_SCAN_HANDLE = FFI_USIZE
export const FFI_STORE_HANDLE = FFI_USIZE

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
  nonce_length: FFI_INT64,
  tag_length: FFI_INT64,
})

export const AeadParamsStructPtr = ref.refType(AeadParamsStruct)

export type ByteBufferType = typeof ByteBufferStruct
export type SecretBufferType = typeof SecretBufferStruct
export type EncryptedBufferType = typeof EncryptedBufferStruct
export type AeadParamsType = typeof AeadParamsStruct
