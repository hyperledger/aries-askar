import type { ByteBufferStruct, SecretBufferStruct } from '../ffi'
import type { ByteBuffer, KeyEntryListHandle, SecretBuffer } from 'aries-askar-shared'

import { Key, ArcHandle, StoreHandle, SessionHandle, ScanHandle, Jwk } from 'aries-askar-shared'
import { NULL } from 'ref-napi'

import { uint8arrayToByteBufferStruct } from '../ffi'

export type Callback = (err: number) => void
export type CallbackWithResponse = (err: number, response: string) => void

type Argument =
  | Record<string, unknown>
  | ArcHandle
  | StoreHandle
  | SessionHandle
  | ScanHandle
  | KeyEntryListHandle
  | Array<unknown>
  | Date
  | Uint8Array
  | SerializedArgument
  | boolean
  | Jwk
  | Key

type SerializedArgument =
  | string
  | number
  | Callback
  | CallbackWithResponse
  | ArrayBuffer
  | typeof ByteBufferStruct
  | typeof SecretBufferStruct
  | Buffer

type SerializedArguments = Record<string, SerializedArgument>

export type SerializedOptions<Type> = Required<{
  [Property in keyof Type]: Type[Property] extends string
    ? string
    : Type[Property] extends number
    ? number
    : Type[Property] extends boolean
    ? number
    : Type[Property] extends boolean | undefined
    ? number
    : Type[Property] extends Record<string, unknown>
    ? string
    : Type[Property] extends Array<unknown>
    ? string
    : Type[Property] extends Array<unknown> | undefined
    ? string
    : Type[Property] extends Record<string, unknown> | undefined
    ? string
    : Type[Property] extends Date
    ? number
    : Type[Property] extends Date | undefined
    ? number
    : Type[Property] extends string | undefined
    ? string
    : Type[Property] extends number | undefined
    ? number
    : Type[Property] extends Callback
    ? Callback
    : Type[Property] extends CallbackWithResponse
    ? CallbackWithResponse
    : Type[Property] extends Buffer
    ? Buffer
    : Type[Property] extends Uint8Array
    ? typeof ByteBufferStruct
    : Type[Property] extends Uint8Array | undefined
    ? typeof ByteBufferStruct
    : Type[Property] extends ByteBuffer
    ? typeof ByteBufferStruct
    : Type[Property] extends SecretBuffer
    ? typeof SecretBufferStruct
    : Type[Property] extends StoreHandle
    ? number
    : Type[Property] extends SessionHandle
    ? number
    : Type[Property] extends ScanHandle
    ? number
    : Type[Property] extends ArcHandle
    ? string
    : Type[Property] extends Jwk
    ? typeof ByteBufferStruct
    : Type[Property] extends Key
    ? Buffer
    : unknown
}>

// TODO: this method needs to be reworked.
// It is very messy
// cannot handle complex data structures well
const serialize = (arg: Argument): SerializedArgument => {
  switch (typeof arg) {
    case 'undefined':
      return NULL
    case 'boolean':
      return +arg
    case 'string':
      return arg
    case 'number':
      return arg
    case 'function':
      return arg
    case 'object':
      if (arg instanceof Date) {
        return arg.valueOf()
      } else if (arg instanceof Key) {
        return arg.handle.handle
      } else if (arg instanceof Buffer) {
        return arg
      } else if (arg instanceof Uint8Array) {
        return uint8arrayToByteBufferStruct(arg) as unknown as typeof ByteBufferStruct
      } else if (arg instanceof Jwk) {
        return uint8arrayToByteBufferStruct(arg.toUint8Array()) as unknown as typeof ByteBufferStruct
      } else if (
        arg instanceof ArcHandle ||
        arg instanceof StoreHandle ||
        arg instanceof SessionHandle ||
        arg instanceof ScanHandle
      ) {
        return arg.handle
      } else {
        return JSON.stringify(arg)
      }
    default:
      throw new Error('could not serialize value')
  }
}

const serializeArguments = <T extends Record<string, Argument> = Record<string, Argument>>(
  args: T
): SerializedOptions<T> => {
  const retVal: SerializedArguments = {}
  Object.entries(args).forEach(([key, val]) => (retVal[key] = serialize(val)))
  return retVal as SerializedOptions<T>
}

export { serializeArguments }
