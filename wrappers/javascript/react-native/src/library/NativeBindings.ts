/* eslint-disable no-empty-pattern */

type EntryListHandle = number

type LocalKeyHandle = string

export type StoreHandle = number

type Callback = (err: number) => void

type CallbackWithResponse<T = string> = (err: number, response: T) => void

export interface NativeBindings {
  version({}): string

  getCurrentError({}): string

  setConfig(options: { config: string }): null

  bufferFree(options: { buffer: any }): void

  clearCustomLogger(options: any): void

  entryListCount(options: any): number

  entryListFree(options: any): void

  entryListGetCategory(options: any): string

  entryListGetName(options: any): string

  entryListGetTags(options: any): string

  entryListGetValue(options: any): ArrayBuffer

  keyAeadDecrypt(options: any): void

  keyAeadEncrypt(options: any): void

  keyAeadGetPadding(options: any): void

  keyAeadGetParams(options: any): void

  keyAeadRandomNonce(options: any): void

  keyConvert(options: any): LocalKeyHandle

  keyCryptoBox(options: any): ArrayBuffer

  keyCryptoBoxOpen(options: any): ArrayBuffer

  keyCryptoBoxRandomNonce(options: Record<string, never>): ArrayBuffer

  keyCryptoBoxSeal(options: any): ArrayBuffer

  keyCryptoBoxSealOpen(options: any): ArrayBuffer

  keyDeriveEcdh1pu(options: any): LocalKeyHandle

  keyDeriveEcdhEs(options: any): LocalKeyHandle

  keyEntryListCount(options: any): void

  ntryListFree(options: any): void

  keyEntryListGetAlgorithm(options: any): void

  keyEntryListGetMetadata(options: any): void

  keyEntryListGetName(options: any): void

  keyEntryListGetTags(options: any): void

  keyEntryListLoadLocal(options: any): void

  keyFree(options: any): void

  keyFromJwk(options: any): LocalKeyHandle

  keyFromKeyExchange(options: any): LocalKeyHandle

  keyFromPublicBytes(options: any): LocalKeyHandle

  keyFromSecretBytes(options: any): LocalKeyHandle

  keyFromSeed(options: any): LocalKeyHandle

  keyGenerate(options: any): LocalKeyHandle

  keyGetAlgorithm(options: any): string

  keyGetEphemeral(options: any): number

  keyGetJwkPublic(options: any): string

  keyGetJwkSecret(options: any): ArrayBuffer

  keyGetJwkThumbprint(options: any): string

  keyGetPublicBytes(options: any): ArrayBuffer

  keyGetSecretBytes(options: any): ArrayBuffer

  keySignMessage(options: any): ArrayBuffer

  keyUnwrapKey(options: any): LocalKeyHandle

  keyVerifySignature(options: any): number

  keyWrapKey(options: any): { buffer: ArrayBuffer; tagPos: number; noncePos: number }

  scanFree(options: any): void

  scanNext(options: any): void

  scanStart(options: any): number

  sessionClose(options: any): void

  sessionCount(options: any): void

  sessionFetch(options: any): void

  sessionFetchAll(options: any): void

  sessionFetchAllKeys(options: any): void

  sessionFetchKey(options: any): void

  sessionInsertKey(options: any): void

  sessionRemoveAll(options: any): void

  sessionRemoveKey(options: any): void

  sessionStart(options: any): void

  sessionUpdate(options: any): void

  sessionUpdateKey(options: any): void

  setCustomLogger(options: any): void

  setDefaultLogger(options: any): void

  setMaxLogLevel(options: any): void

  storeClose(options: any): void

  storeCreateProfile(options: any): void

  storeGenerateRawKey(options: { seed?: ArrayBuffer }): string

  storeGetProfileName(options: any): void

  storeOpen(options: {
    specUri: string
    keyMethod?: string
    passKey?: string
    profile?: string
    cb: CallbackWithResponse<StoreHandle>
  }): void

  storeProvision(options: any): void

  storeRekey(options: any): void

  storeRemove(options: any): void

  storeRemoveProfile(options: any): void
}
