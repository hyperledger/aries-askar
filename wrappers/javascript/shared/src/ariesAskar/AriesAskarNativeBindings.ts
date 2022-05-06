/* eslint-disable no-empty-pattern */

type EntryListHandle = number
type LocalKeyHandle = number

type ErrorCode = number

type Callback = (err: number) => void

type CallbackWithResponse = (err: number, response: string) => void

export interface AriesAskarNativeBindings {
  version({}): string

  getCurrentError({}): string

  setConfig(options: { config: string }): null

  bufferFree(options: { buffer: any }): void

  clearCustomLogger(options: any): void

  entryListCount(options: { handle: EntryListHandle; count: number }): ErrorCode

  entryListFree(options: { handle: EntryListHandle }): void

  entryListGetCategory(options: any): ErrorCode

  entryListGetName(options: any): ErrorCode

  entryListGetTags(options: any): ErrorCode

  entryListGetValue(options: any): ErrorCode

  keyAeadDecrypt(options: any): ErrorCode

  keyAeadEncrypt(options: any): ErrorCode

  keyAeadGetPadding(options: any): ErrorCode

  keyAeadGetParams(options: any): ErrorCode

  keyAeadRandomNonce(options: any): ErrorCode

  keyConvert(options: any): ErrorCode

  keyCryptoBox(options: any): ErrorCode

  keyCryptoBoxOpen(options: any): ErrorCode

  keyCryptoBoxRandomNonce(options: any): ErrorCode

  keyCryptoBoxSeal(options: any): ErrorCode

  keyCryptoBoxSealOpen(options: any): ErrorCode

  keyDeriveEcdh1pu(options: any): ErrorCode

  keyDeriveEcdhEs(options: any): ErrorCode

  keyEntryListCount(options: any): ErrorCode

  ntryListFree(options: any): ErrorCode

  keyEntryListGetAlgorithm(options: any): ErrorCode

  keyEntryListGetMetadata(options: any): ErrorCode

  keyEntryListGetName(options: any): ErrorCode

  keyEntryListGetTags(options: any): ErrorCode

  keyEntryListLoadLocal(options: any): ErrorCode

  ree(options: any): ErrorCode

  keyFromJwk(options: any): ErrorCode

  keyFromKeyExchange(options: any): ErrorCode

  keyFromPublicBytes(options: any): ErrorCode

  keyFromSecretBytes(options: any): ErrorCode

  keyFromSeed(options: any): ErrorCode

  keyGenerate(options: any): ErrorCode

  keyGetAlgorithm(options: any): ErrorCode

  keyGetEphemeral(options: any): ErrorCode

  keyGetJwkPublic(options: any): ErrorCode

  keyGetJwkSecret(options: any): ErrorCode

  keyGetJwkThumbprint(options: any): ErrorCode

  keyGetPublicBytes(options: any): ErrorCode

  keyGetSecretBytes(options: any): ErrorCode

  keySignMessage(options: any): ErrorCode

  keyUnwrapKey(options: any): ErrorCode

  keyVerifySignature(options: any): ErrorCode

  keyWrapKey(options: any): ErrorCode

  scanFree(options: any): ErrorCode

  scanNext(options: any): ErrorCode

  scanStart(options: any): ErrorCode

  sessionClose(options: any): ErrorCode

  sessionCount(options: any): ErrorCode

  sessionFetch(options: any): ErrorCode

  sessionFetchAll(options: any): ErrorCode

  sessionFetchAllKeys(options: any): ErrorCode

  sessionFetchKey(options: any): ErrorCode

  sessionInsertKey(options: any): ErrorCode

  sessionRemoveAll(options: any): ErrorCode

  sessionRemoveKey(options: any): ErrorCode

  sessionStart(options: any): ErrorCode

  sessionUpdate(options: any): ErrorCode

  sessionUpdateKey(options: any): ErrorCode

  setCustomLogger(options: any): ErrorCode

  setDefaultLogger(options: any): ErrorCode

  setMaxLogLevel(options: any): ErrorCode

  storeClose(options: any): ErrorCode

  storeCreateProfile(options: any): ErrorCode

  storeGenerateRawKey(options: any): ErrorCode

  storeGetProfileName(options: any): ErrorCode

  storeOpen(options: any): ErrorCode

  storeProvision(options: any): ErrorCode

  storeRekey(options: any): ErrorCode

  storeRemove(options: any): ErrorCode

  storeRemoveProfile(options: any): ErrorCode
}
