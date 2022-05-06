import type { SecretBufferStruct, ByteBufferStruct } from './ffiTypes'

import { SecretBuffer, ByteBuffer } from 'aries-askar-shared'
import { NULL } from 'ref-napi'

import { byteBufferClassToStruct, secretBufferClassToStruct, uint8arrayToByteBufferStruct } from './ffiTools'

export type Callback = (err: number) => void
export type CallbackWithResponse = (err: number, response: string) => void

type Argument =
  | Record<string, unknown>
  | Array<unknown>
  | Date
  | Uint8Array
  | SerializedArgument
  | ByteBuffer
  | SecretBuffer

type SerializedArgument =
  | string
  | number
  | Callback
  | CallbackWithResponse
  | ArrayBuffer
  | typeof ByteBufferStruct
  | typeof SecretBufferStruct

type SerializedArguments = Record<string, SerializedArgument>

export type SerializedOptions<Type> = Required<{
  [Property in keyof Type]: Type[Property] extends string
    ? string
    : Type[Property] extends number
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
    : Type[Property] extends Uint8Array
    ? typeof ByteBufferStruct
    : Type[Property] extends ByteBuffer
    ? typeof ByteBufferStruct
    : Type[Property] extends SecretBuffer
    ? typeof SecretBufferStruct
    : unknown
}>

const serialize = (arg: Argument): SerializedArgument => {
  switch (typeof arg) {
    case 'undefined':
      return NULL
    case 'string':
      return arg
    case 'number':
      return arg
    case 'function':
      return arg
    case 'object':
      if (arg instanceof Date) {
        return arg.valueOf()
      } else if (arg instanceof Uint8Array) {
        return uint8arrayToByteBufferStruct(arg) as unknown as typeof ByteBufferStruct
      } else if (arg instanceof ByteBuffer) {
        return byteBufferClassToStruct(arg) as unknown as typeof ByteBufferStruct
      } else if (arg instanceof SecretBuffer) {
        return secretBufferClassToStruct(arg) as unknown as typeof SecretBufferStruct
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
