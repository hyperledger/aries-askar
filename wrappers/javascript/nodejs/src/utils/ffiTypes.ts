import { default as array } from 'ref-array-di'
import * as ref from 'ref-napi'
import { default as struct } from 'ref-struct-di'

const CStruct = struct(ref)
const CArray = array(ref)

export const ByteBufferArray = (len: number) => CArray(ref.types.uint8, len)
export const ByteBufferArrayPtr = (len: number) => ref.refType(ByteBufferArray(len))
export const SercetBufferArray = ByteBufferArray
export const SercetBufferArrayPtr = ByteBufferArrayPtr

export const ByteBufferStruct = CStruct({
  len: ref.types.uint64,
  data: ref.refType(CArray(ref.types.uint8)),
})
export type ByteBufferType<T extends number = 32> = struct.StructObject<{
  len: number
  data: ref.Pointer<array.TypedArray<number, T>>
}>

export const SecretBufferStruct = (len = 32) =>
  CStruct({
    len: ref.types.int64,
    data: ByteBufferArrayPtr(len),
  })

export type SecretBufferType = ByteBufferType

export const EncryptedBufferStruct = (len = 32) =>
  CStruct({
    buffer: SecretBufferStruct(len),
    tag_pos: ref.types.int64,
    nonce_pos: ref.types.int64,
  })

export type EncryptedBufferType = struct.StructObject<{
  buffer: SecretBufferType
  tag_pos: number
  nonce_pos: number
}>

export const AeadParamsStruct = CStruct({
  nonce_length: ref.types.int64,
  tag_length: ref.types.int64,
})

export type AeadParamsType = struct.StructObject<{
  nonce_length: number
  tag_length: number
}>

// eslint-disable-next-line @typescript-eslint/ban-types

// TODO: unsure about these typings
export const FfiResultListEntry = CStruct({})
export const FfiResultListKeyEntry = CStruct({})
export const LocalKey = CStruct({})
export const ScanHandle = 'int64'
export const StoreHandle = 'int64'
export const SessionHandle = 'int64'
export const OptionEnabledCallback = CStruct({})
export const OptionFlushCallback = CStruct({})
export const FfiEntryList = FfiResultListEntry
export const ArcHandleFfiEntryList = CStruct({
  FfiEntryList: ref.refType(ref.types.void),
})
export const EntryListHandle = ArcHandleFfiEntryList

// export const ArcHandleLocalKey = CStruct({
//   _0: ref.refType(Root),
// })

// export type LocalKeyHandleType = struct.StructObject<{
//   LocalKey: typeof Ed25519KeyPair
// }>

export const ArcHandleFfiKeyEntryList = CStruct({
  FfiKeyEntryList: ref.refType(ref.types.void),
})
export const KeyEntryListHandle = ArcHandleFfiKeyEntryList

// FFI Type Strings
export const FFI_ERROR_CODE = 'int64'

export const FFI_POINTER = 'pointer'

export const FFI_CALLBACK_ID = 'int64'
export const FFI_CALLBACK_PTR = FFI_POINTER

export const FFI_STRING = 'string'
export const FFI_STRING_PTR = 'char*'

export const FFI_INT8 = 'int8'
export const FFI_INT64 = 'int64'
export const FFI_INT32 = 'int32'
export const FFI_UINT64 = 'uint64'

export const FFI_VOID = 'void'
export const FFI_VOID_PTR = ref.refType(FFI_VOID)

export const FFI_INT32_PTR = ref.refType(FFI_INT32)
export const FFI_INT8_PTR = ref.refType(FFI_INT8)

export const ARC_HANDLE = ref.refType(FFI_POINTER)
export const FFI_LOCAL_KEY_HANDLE = ARC_HANDLE
export const FFI_KEY_ENTRY_LIST_HANDLE = ARC_HANDLE
export const FFI_SCAN_HANDLE = ARC_HANDLE
export const FFI_SESSION_HANDLE = 'int64'
export const FFI_ENTRY_LIST_HANDLE = ARC_HANDLE
export const FFI_STORE_HANDLE = 'int64'
