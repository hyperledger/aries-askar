import type { CallbackWithResponse, ReturnObject } from '../utils'

type LocalKeyHandle = string

// TODO: convert all any types
export interface NativeBindings {
  version(options: Record<string, never>): string
  getCurrentError(options: Record<string, never>): string

  entryListCount(options: { entryListHandle: string }): ReturnObject<number>
  entryListFree(options: { entryListHandle: string }): ReturnObject<never>
  entryListGetCategory(options: { entryListHandle: string; index: number }): ReturnObject<string>
  entryListGetName(options: { entryListHandle: string; index: number }): ReturnObject<string>
  entryListGetTags(options: { entryListHandle: string; index: number }): ReturnObject<string>
  entryListGetValue(options: { entryListHandle: string; index: number }): ReturnObject<ArrayBuffer>

  keyAeadDecrypt(options: {
    localKeyHandle: string
    ciphertext: ArrayBuffer
    nonce: ArrayBuffer
    tag?: ArrayBuffer
    aad?: ArrayBuffer
  }): ReturnObject<ArrayBuffer>

  keyAeadEncrypt(options: {
    localKeyHandle: string
    message: ArrayBuffer
    nonce?: ArrayBuffer
    aad?: ArrayBuffer
  }): ReturnObject<{
    noncePos: number
    tagPos: number
    buffer: ArrayBuffer
  }>

  keyAeadGetPadding(options: { localKeyHandle: string; msgLen: number }): ReturnObject<number>

  keyAeadGetParams(options: { localKeyHandle: string }): ReturnObject<{ nonceLength: number; tagLength: number }>

  keyAeadRandomNonce(options: any): ReturnObject<ArrayBuffer>

  keyConvert(options: any): ReturnObject<LocalKeyHandle>

  keyCryptoBox(options: any): ReturnObject<ArrayBuffer>

  keyCryptoBoxOpen(options: any): ReturnObject<ArrayBuffer>

  keyCryptoBoxRandomNonce(options: Record<string, never>): ReturnObject<ArrayBuffer>

  keyCryptoBoxSeal(options: any): ReturnObject<ArrayBuffer>

  keyCryptoBoxSealOpen(options: any): ReturnObject<ArrayBuffer>

  keyDeriveEcdh1pu(options: any): ReturnObject<LocalKeyHandle>

  keyDeriveEcdhEs(options: any): ReturnObject<LocalKeyHandle>

  keyEntryListCount(options: any): ReturnObject<number>

  keyEntryListFree(options: any): ReturnObject<never>

  keyEntryListGetAlgorithm(options: any): ReturnObject<string>

  keyEntryListGetMetadata(options: any): ReturnObject<string>

  keyEntryListGetName(options: any): ReturnObject<string>

  keyEntryListGetTags(options: any): ReturnObject<string>

  keyEntryListLoadLocal(options: any): ReturnObject<LocalKeyHandle>

  keyFree(options: any): ReturnObject<never>

  keyFromJwk(options: any): ReturnObject<LocalKeyHandle>

  keyFromKeyExchange(options: any): ReturnObject<LocalKeyHandle>

  keyFromPublicBytes(options: any): ReturnObject<LocalKeyHandle>

  keyFromSecretBytes(options: any): ReturnObject<LocalKeyHandle>

  keyFromSeed(options: any): ReturnObject<LocalKeyHandle>

  keyGenerate(options: any): ReturnObject<LocalKeyHandle>

  keyGetAlgorithm(options: any): ReturnObject<string>

  keyGetEphemeral(options: any): ReturnObject<number>

  keyGetJwkPublic(options: any): ReturnObject<string>

  keyGetJwkSecret(options: any): ReturnObject<ArrayBuffer>

  keyGetJwkThumbprint(options: any): ReturnObject<string>

  keyGetPublicBytes(options: any): ReturnObject<ArrayBuffer>

  keyGetSecretBytes(options: any): ReturnObject<ArrayBuffer>

  keySignMessage(options: any): ReturnObject<ArrayBuffer>

  keyUnwrapKey(options: any): ReturnObject<LocalKeyHandle>

  keyVerifySignature(options: any): ReturnObject<number>

  keyWrapKey(options: any): ReturnObject<{ buffer: ArrayBuffer; tagPos: number; noncePos: number }>

  scanFree(options: any): ReturnObject<never>

  scanNext(options: any): ReturnObject<never>

  scanStart(options: any): ReturnObject<number>

  sessionClose(options: any): ReturnObject<never>

  sessionCount(options: any): ReturnObject<never>

  sessionFetch(options: any): ReturnObject<never>

  sessionFetchAll(options: any): ReturnObject<never>

  sessionFetchAllKeys(options: any): ReturnObject<never>

  sessionFetchKey(options: any): ReturnObject<never>

  sessionInsertKey(options: any): ReturnObject<never>

  sessionRemoveAll(options: any): ReturnObject<never>

  sessionRemoveKey(options: any): ReturnObject<never>

  sessionStart(options: any): ReturnObject<never>

  sessionUpdate(options: any): ReturnObject<never>

  sessionUpdateKey(options: any): ReturnObject<never>

  setCustomLogger(options: any): ReturnObject<never>

  setDefaultLogger(options: any): ReturnObject<never>

  setMaxLogLevel(options: any): ReturnObject<never>

  storeClose(options: any): ReturnObject<never>

  storeCreateProfile(options: any): ReturnObject<never>

  storeGenerateRawKey(options: { seed?: ArrayBuffer }): ReturnObject<string>

  storeGetProfileName(options: any): ReturnObject<never>

  storeOpen(options: {
    specUri: string
    keyMethod?: string
    passKey?: string
    profile?: string
    cb: CallbackWithResponse<number>
  }): ReturnObject<never>

  storeProvision(options: any): ReturnObject<never>

  storeRekey(options: any): ReturnObject<never>

  storeRemove(options: any): ReturnObject<never>

  storeRemoveProfile(options: any): ReturnObject<never>
}
