import type { AriesAskar } from 'aries-askar-shared'

interface TypeMap {
  SecretBuffer: Uint8Array
  EntryListHandle: string
  LocalKeyHandle: string
  KeyEntryListHandle: string
  SessionHandle: number
  StoreHandle: number
  ScanHandle: number
  SigAlgs: string
  KeyAlgs: string
  LogLevel: number
  boolean: number
  Key: string
  Jwk: string
  Uint8Array: Uint8Array
  'Record<string, unknown>': string
  string: string
  number: number
}

type Func = (params: Record<string, keyof TypeMap> | never) => unknown

type Params<T> = T extends (...args: infer P) => unknown ? P : never

type MapParams<T extends Record<string, keyof TypeMap>> = {
  [Property in keyof T]: TypeMap[T[Property]]
}

type SerializeTypes<T extends Record<string, Func>> = {
  [Property in keyof T]: Params<T[Property]>[0] extends Record<string, unknown>
    ? (options: MapParams<Params<T[Property]>[0]>) => ReturnType<T[Property]>
    : T[Property]
}

export type NativeBindings = SerializeTypes<AriesAskar>

// export interface NativeBindings {
//   version(options: Record<string, never>): string
//
//   getCurrentError(options: Record<string, never>): string
//
//   setConfig(options: { config: string }): null
//
//   // bufferFree(options: { buffer: any }): void
//
//   clearCustomLogger(options: Record<string, never>): void
//
//   entryListCount(options: {}): number
//
//   entryListFree(options: any): void
//
//   entryListGetCategory(options: any): string
//
//   entryListGetName(options: any): string
//
//   entryListGetTags(options: any): string
//
//   entryListGetValue(options: any): ArrayBuffer
//
//   keyAeadDecrypt(options: any): ArrayBuffer
//
//   keyAeadEncrypt(options: any): { noncePos: number; tagPos: number; buffer: ArrayBuffer }
//
//   keyAeadGetPadding(options: any): number
//
//   keyAeadGetParams(options: any): { nonceLength: number; tagLength: number }
//
//   keyAeadRandomNonce(options: any): ArrayBuffer
//
//   keyConvert(options: any): LocalKeyHandle
//
//   keyCryptoBox(options: any): ArrayBuffer
//
//   keyCryptoBoxOpen(options: any): ArrayBuffer
//
//   keyCryptoBoxRandomNonce(options: Record<string, never>): ArrayBuffer
//
//   keyCryptoBoxSeal(options: any): ArrayBuffer
//
//   keyCryptoBoxSealOpen(options: any): ArrayBuffer
//
//   keyDeriveEcdh1pu(options: any): LocalKeyHandle
//
//   keyDeriveEcdhEs(options: any): LocalKeyHandle
//
//   keyEntryListCount(options: any): number
//
//   keyEntryListFree(options: any): void
//
//   keyEntryListGetAlgorithm(options: any): string
//
//   keyEntryListGetMetadata(options: any): string
//
//   keyEntryListGetName(options: any): string
//
//   keyEntryListGetTags(options: any): string
//
//   keyEntryListLoadLocal(options: any): LocalKeyHandle
//
//   keyFree(options: any): void
//
//   keyFromJwk(options: any): LocalKeyHandle
//
//   keyFromKeyExchange(options: any): LocalKeyHandle
//
//   keyFromPublicBytes(options: any): LocalKeyHandle
//
//   keyFromSecretBytes(options: any): LocalKeyHandle
//
//   keyFromSeed(options: any): LocalKeyHandle
//
//   keyGenerate(options: any): LocalKeyHandle
//
//   keyGetAlgorithm(options: any): string
//
//   keyGetEphemeral(options: any): number
//
//   keyGetJwkPublic(options: any): string
//
//   keyGetJwkSecret(options: any): ArrayBuffer
//
//   keyGetJwkThumbprint(options: any): string
//
//   keyGetPublicBytes(options: any): ArrayBuffer
//
//   keyGetSecretBytes(options: any): ArrayBuffer
//
//   keySignMessage(options: any): ArrayBuffer
//
//   keyUnwrapKey(options: any): LocalKeyHandle
//
//   keyVerifySignature(options: any): number
//
//   keyWrapKey(options: any): { buffer: ArrayBuffer; tagPos: number; noncePos: number }
//
//   scanFree(options: any): void
//
//   scanNext(options: any): void
//
//   scanStart(options: any): number
//
//   sessionClose(options: any): void
//
//   sessionCount(options: any): void
//
//   sessionFetch(options: any): void
//
//   sessionFetchAll(options: any): void
//
//   sessionFetchAllKeys(options: any): void
//
//   sessionFetchKey(options: any): void
//
//   sessionInsertKey(options: any): void
//
//   sessionRemoveAll(options: any): void
//
//   sessionRemoveKey(options: any): void
//
//   sessionStart(options: any): void
//
//   sessionUpdate(options: any): void
//
//   sessionUpdateKey(options: any): void
//
//   setCustomLogger(options: any): void
//
//   setDefaultLogger(options: any): void
//
//   setMaxLogLevel(options: any): void
//
//   storeClose(options: any): void
//
//   storeCreateProfile(options: any): void
//
//   storeGenerateRawKey(options: { seed?: ArrayBuffer }): string
//
//   storeGetProfileName(options: any): void
//
//   storeOpen(options: {
//     specUri: string
//     keyMethod?: string
//     passKey?: string
//     profile?: string
//     cb: CallbackWithResponse<StoreHandle>
//   }): void
//
//   storeProvision(options: any): void
//
//   storeRekey(options: any): void
//
//   storeRemove(options: any): void
//
//   storeRemoveProfile(options: any): void
// }
