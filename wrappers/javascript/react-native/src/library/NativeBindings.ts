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

  entryListGetValue(options: any): Uint8Array

  keyAeadDecrypt(options: any): void

  keyAeadEncrypt(options: any): void

  keyAeadGetPadding(options: any): void

  keyAeadGetParams(options: any): void

  keyAeadRandomNonce(options: any): void

  keyConvert(options: any): LocalKeyHandle

  keyCryptoBox(options: any): void

  keyCryptoBoxOpen(options: any): void

  keyCryptoBoxRandomNonce(options: any): void

  keyCryptoBoxSeal(options: any): void

  keyCryptoBoxSealOpen(options: any): void

  keyDeriveEcdh1pu(options: any): void

  keyDeriveEcdhEs(options: any): void

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

  keyGetJwkSecret(options: any): Uint8Array

  keyGetJwkThumbprint(options: any): string

  keyGetPublicBytes(options: any): Uint8Array

  keyGetSecretBytes(options: any): Uint8Array

  keySignMessage(options: any): Uint8Array

  keyUnwrapKey(options: any): LocalKeyHandle

  keyVerifySignature(options: any): number

  keyWrapKey(options: any): { buffer: Uint8Array; tagPos: number; noncePos: number }

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
