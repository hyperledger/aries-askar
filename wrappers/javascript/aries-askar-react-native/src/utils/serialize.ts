import { ArcHandle, Jwk, ScanHandle, SessionHandle, StoreHandle, Key } from '@hyperledger/aries-askar-shared'

export type ReturnObject<T = unknown> = {
  errorCode: number
  value?: null | T
}

export type Callback = (o: ReturnObject<never>) => void
export type CallbackWithResponse<T = unknown> = (o: ReturnObject<T>) => void

type Argument =
  | Record<string, unknown>
  | Array<unknown>
  | Date
  | Uint8Array
  | SerializedArgument
  | boolean
  | StoreHandle
  | SessionHandle
  | ScanHandle
  | ArcHandle
  | Key
  | Jwk

type SerializedArgument = string | number | Callback | CallbackWithResponse | ArrayBuffer

type SerializedArguments = Record<string, SerializedArgument>

export type SerializedOptions<Type> = {
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
    ? string | undefined
    : Type[Property] extends Date
    ? number
    : Type[Property] extends Date | undefined
    ? number | undefined
    : Type[Property] extends string | undefined
    ? undefined | string
    : Type[Property] extends number | undefined
    ? undefined | number
    : Type[Property] extends Callback
    ? Callback
    : Type[Property] extends CallbackWithResponse
    ? CallbackWithResponse
    : Type[Property] extends Uint8Array
    ? ArrayBuffer
    : Type[Property] extends Uint8Array | undefined
    ? ArrayBuffer
    : Type[Property] extends StoreHandle
    ? number
    : Type[Property] extends SessionHandle
    ? number
    : Type[Property] extends ScanHandle
    ? number
    : Type[Property] extends ArcHandle
    ? string
    : Type[Property] extends Jwk
    ? string
    : unknown
}

const serialize = (arg: Argument): SerializedArgument => {
  switch (typeof arg) {
    case 'undefined':
      return arg
    case 'string':
      return arg
    case 'boolean':
      return Number(arg)
    case 'number':
      return arg
    case 'function':
      return arg
    case 'object':
      if (arg instanceof Date) {
        return arg.valueOf()
      } else if (arg instanceof Uint8Array) {
        return arg.buffer
      } else if (arg instanceof Jwk) {
        return arg.toUint8Array().buffer
      } else if (arg instanceof Key) {
        return arg.handle.handle
      } else if (
        arg instanceof StoreHandle ||
        arg instanceof SessionHandle ||
        arg instanceof ScanHandle ||
        arg instanceof ArcHandle
      ) {
        return arg.handle
      } else {
        return JSON.stringify(arg)
      }
    default:
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
      throw new Error(`Could not serialize value ${arg}`)
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
