import type { CallbackWithResponse, ReturnObject } from './serialize'

type LocalKeyHandle = string

// TODO: convert all unknown types
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

  keyAeadRandomNonce(options: unknown): ReturnObject<ArrayBuffer>

  keyConvert(options: unknown): ReturnObject<LocalKeyHandle>

  keyCryptoBox(options: unknown): ReturnObject<ArrayBuffer>

  keyCryptoBoxOpen(options: unknown): ReturnObject<ArrayBuffer>

  keyCryptoBoxRandomNonce(options: Record<string, never>): ReturnObject<ArrayBuffer>

  keyCryptoBoxSeal(options: unknown): ReturnObject<ArrayBuffer>

  keyCryptoBoxSealOpen(options: unknown): ReturnObject<ArrayBuffer>

  keyDeriveEcdh1pu(options: unknown): ReturnObject<LocalKeyHandle>

  keyDeriveEcdhEs(options: unknown): ReturnObject<LocalKeyHandle>

  keyEntryListCount(options: unknown): ReturnObject<number>

  keyEntryListFree(options: unknown): ReturnObject<never>

  keyEntryListGetAlgorithm(options: unknown): ReturnObject<string>

  keyEntryListGetMetadata(options: unknown): ReturnObject<string>

  keyEntryListGetName(options: unknown): ReturnObject<string>

  keyEntryListGetTags(options: unknown): ReturnObject<string>

  keyEntryListLoadLocal(options: unknown): ReturnObject<LocalKeyHandle>

  keyFree(options: unknown): ReturnObject<never>

  keyFromJwk(options: unknown): ReturnObject<LocalKeyHandle>

  keyFromKeyExchange(options: unknown): ReturnObject<LocalKeyHandle>

  keyFromPublicBytes(options: unknown): ReturnObject<LocalKeyHandle>

  keyFromSecretBytes(options: unknown): ReturnObject<LocalKeyHandle>

  keyFromSeed(options: unknown): ReturnObject<LocalKeyHandle>

  keyGenerate(options: unknown): ReturnObject<LocalKeyHandle>

  keyGetAlgorithm(options: unknown): ReturnObject<string>

  keyGetEphemeral(options: unknown): ReturnObject<number>

  keyGetJwkPublic(options: unknown): ReturnObject<string>

  keyGetJwkSecret(options: unknown): ReturnObject<ArrayBuffer>

  keyGetJwkThumbprint(options: unknown): ReturnObject<string>

  keyGetPublicBytes(options: unknown): ReturnObject<ArrayBuffer>

  keyGetSecretBytes(options: unknown): ReturnObject<ArrayBuffer>

  keySignMessage(options: unknown): ReturnObject<ArrayBuffer>

  keyUnwrapKey(options: unknown): ReturnObject<LocalKeyHandle>

  keyVerifySignature(options: unknown): ReturnObject<number>

  keyWrapKey(options: unknown): ReturnObject<{ buffer: ArrayBuffer; tagPos: number; noncePos: number }>

  scanFree(options: unknown): ReturnObject<never>

  scanNext(options: unknown): ReturnObject<never>

  scanStart(options: unknown): ReturnObject<number>

  sessionClose(options: unknown): ReturnObject<never>

  sessionCount(options: unknown): ReturnObject<never>

  sessionFetch(options: unknown): ReturnObject<never>

  sessionFetchAll(options: unknown): ReturnObject<never>

  sessionFetchAllKeys(options: unknown): ReturnObject<never>

  sessionFetchKey(options: unknown): ReturnObject<never>

  sessionInsertKey(options: unknown): ReturnObject<never>

  sessionRemoveAll(options: unknown): ReturnObject<never>

  sessionRemoveKey(options: unknown): ReturnObject<never>

  sessionStart(options: unknown): ReturnObject<never>

  sessionUpdate(options: unknown): ReturnObject<never>

  sessionUpdateKey(options: unknown): ReturnObject<never>

  setCustomLogger(options: unknown): ReturnObject<never>

  setDefaultLogger(options: unknown): ReturnObject<never>

  setMaxLogLevel(options: unknown): ReturnObject<never>

  storeClose(options: unknown): ReturnObject<never>

  storeCreateProfile(options: unknown): ReturnObject<never>

  storeGenerateRawKey(options: { seed?: ArrayBuffer }): ReturnObject<string>

  storeGetProfileName(options: unknown): ReturnObject<never>

  storeOpen(options: {
    specUri: string
    keyMethod?: string
    passKey?: string
    profile?: string
    cb: CallbackWithResponse<number>
  }): ReturnObject<never>

  storeProvision(options: unknown): ReturnObject<never>

  storeRekey(options: unknown): ReturnObject<never>

  storeRemove(options: unknown): ReturnObject<never>

  storeRemoveProfile(options: unknown): ReturnObject<never>

  migrateIndySdk(options: unknown): ReturnObject<never>
}
