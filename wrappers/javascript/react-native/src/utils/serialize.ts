// export type Callback = (err: number) => void
// export type CallbackWithResponse = (err: number, response: string) => void
//
// type Argument = Record<string, unknown> | Array<unknown> | Date | Uint8Array | SerializedArgument
//
// type SerializedArgument = string | number | Callback | CallbackWithResponse | ArrayBuffer
//
// type SerializedArguments = Record<string, SerializedArgument>
//
// export type SerializedOptions<Type> = {
//   [Property in keyof Type]: Type[Property] extends string
//     ? string
//     : Type[Property] extends number
//     ? number
//     : Type[Property] extends Record<string, unknown>
//     ? string
//     : Type[Property] extends Array<unknown>
//     ? string
//     : Type[Property] extends Array<unknown> | undefined
//     ? string
//     : Type[Property] extends Record<string, unknown> | undefined
//     ? string | undefined
//     : Type[Property] extends Date
//     ? number
//     : Type[Property] extends Date | undefined
//     ? number | undefined
//     : Type[Property] extends string | undefined
//     ? undefined | string
//     : Type[Property] extends number | undefined
//     ? undefined | number
//     : Type[Property] extends Callback
//     ? Callback
//     : Type[Property] extends CallbackWithResponse
//     ? CallbackWithResponse
//     : Type[Property] extends Uint8Array
//     ? ArrayBuffer
//     : unknown
// }
//
// const serialize = (arg: Argument): SerializedArgument => {
//   switch (typeof arg) {
//     case 'string':
//       return arg
//     case 'number':
//       return arg
//     case 'function':
//       return arg
//     case 'object':
//       if (arg instanceof Date) {
//         return arg.valueOf()
//       } else if (arg instanceof Uint8Array) {
//         return arg.buffer
//       } else {
//         return JSON.stringify(arg)
//       }
//     default:
//       throw new Error('could not serialize value')
//   }
// }
//
// const serializeArguments = (args: Record<string, Argument>) => {
//   const retVal: SerializedArguments = {}
//   Object.entries(args).forEach(([key, val]) => (retVal[key] = serialize(val)))
//   return retVal
// }
//
// export { serializeArguments }
