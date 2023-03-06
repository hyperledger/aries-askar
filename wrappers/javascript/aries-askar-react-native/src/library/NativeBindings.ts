import type { CallbackWithResponse, ReturnObject } from '../utils'

type LocalKeyHandle = string

// TODO: convert all any types
export interface NativeBindings {
  version(options: Record<string, never>): string | null
  getCurrentError(options: Record<string, never>): string | null

  entryListCount(options: { entryListHandle: string }): ReturnObject<number | null>
  entryListFree(options: { entryListHandle: string }): ReturnObject<never>
  entryListGetCategory(options: { entryListHandle: string; index: number }): ReturnObject<string | null>
  entryListGetName(options: { entryListHandle: string; index: number }): ReturnObject<string | null>
  entryListGetTags(options: { entryListHandle: string; index: number }): ReturnObject<string | null>
  entryListGetValue(options: { entryListHandle: string; index: number }): ReturnObject<ArrayBuffer | null>

  keyAeadDecrypt(options: {
    localKeyHandle: string
    ciphertext: ArrayBuffer
    nonce: ArrayBuffer
    tag?: ArrayBuffer
    aad?: ArrayBuffer
  }): ReturnObject<ArrayBuffer | null>

  keyAeadEncrypt(options: {
    localKeyHandle: string
    message: ArrayBuffer
    nonce?: ArrayBuffer
    aad?: ArrayBuffer
  }): ReturnObject<{
    noncePos: number
    tagPos: number
    buffer: ArrayBuffer
  } | null>

  keyAeadGetPadding(options: { localKeyHandle: string; msgLen: number }): ReturnObject<number | null>

  keyAeadGetParams(options: { localKeyHandle: string }): ReturnObject<{ nonceLength: number; tagLength: number } | null>

  keyAeadRandomNonce(options: any): ReturnObject<ArrayBuffer | null>

  keyConvert(options: any): ReturnObject<LocalKeyHandle | null>

  keyCryptoBox(options: any): ReturnObject<ArrayBuffer | null>

  keyCryptoBoxOpen(options: any): ReturnObject<ArrayBuffer | null>

  keyCryptoBoxRandomNonce(options: Record<string, never>): ReturnObject<ArrayBuffer | null>

  keyCryptoBoxSeal(options: any): ReturnObject<ArrayBuffer | null>

  keyCryptoBoxSealOpen(options: any): ReturnObject<ArrayBuffer | null>

  keyDeriveEcdh1pu(options: any): ReturnObject<LocalKeyHandle | null>

  keyDeriveEcdhEs(options: any): ReturnObject<LocalKeyHandle | null>

  keyEntryListCount(options: any): ReturnObject<number | null>

  keyEntryListFree(options: any): ReturnObject<never>

  keyEntryListGetAlgorithm(options: any): ReturnObject<string | null>

  keyEntryListGetMetadata(options: any): ReturnObject<string | null>

  keyEntryListGetName(options: any): ReturnObject<string | null>

  keyEntryListGetTags(options: any): ReturnObject<string | null>

  keyEntryListLoadLocal(options: any): ReturnObject<LocalKeyHandle | null>

  keyFree(options: any): ReturnObject<never>

  keyFromJwk(options: any): ReturnObject<LocalKeyHandle | null>

  keyFromKeyExchange(options: any): ReturnObject<LocalKeyHandle | null>

  keyFromPublicBytes(options: any): ReturnObject<LocalKeyHandle | null>

  keyFromSecretBytes(options: any): ReturnObject<LocalKeyHandle | null>

  keyFromSeed(options: any): ReturnObject<LocalKeyHandle | null>

  keyGenerate(options: any): ReturnObject<LocalKeyHandle | null>

  keyGetAlgorithm(options: any): ReturnObject<string | null>

  keyGetEphemeral(options: any): ReturnObject<number | null>

  keyGetJwkPublic(options: any): ReturnObject<string | null>

  keyGetJwkSecret(options: any): ReturnObject<ArrayBuffer | null>

  keyGetJwkThumbprint(options: any): ReturnObject<string | null>

  keyGetPublicBytes(options: any): ReturnObject<ArrayBuffer | null>

  keyGetSecretBytes(options: any): ReturnObject<ArrayBuffer | null>

  keySignMessage(options: any): ReturnObject<ArrayBuffer | null>

  keyUnwrapKey(options: any): ReturnObject<LocalKeyHandle | null>

  keyVerifySignature(options: any): ReturnObject<number | null>

  keyWrapKey(options: any): ReturnObject<{ buffer: ArrayBuffer; tagPos: number; noncePos: number } | null>

  scanFree(options: any): ReturnObject<never>

  scanNext(options: any): ReturnObject<never>

  scanStart(options: any): ReturnObject<number | null>

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

  storeGenerateRawKey(options: { seed?: ArrayBuffer }): ReturnObject<string | null>

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
