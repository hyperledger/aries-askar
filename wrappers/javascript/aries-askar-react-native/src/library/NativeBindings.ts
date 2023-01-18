type LocalKeyHandle = string

type CallbackWithResponse<T> = (err: number, response: T) => void
type Callback = (err: number) => void

// TODO: convert all any types
export interface NativeBindings {
  version(options: Record<string, never>): string
  getCurrentError(options: Record<string, never>): string
  setConfig(options: { config: string }): null
  clearCustomLogger(options: Record<string, never>): void

  entryListCount(options: { entryListHandle: string }): number
  entryListFree(options: { entryListHandle: string }): void
  entryListGetCategory(options: { entryListHandle: string; index: number }): string
  entryListGetName(options: { entryListHandle: string; index: number }): string
  entryListGetTags(options: { entryListHandle: string; index: number }): string
  entryListGetValue(options: { entryListHandle: string; index: number }): ArrayBuffer

  keyAeadDecrypt(options: {
    localKeyHandle: string
    ciphertext: ArrayBuffer
    nonce: ArrayBuffer
    tag?: ArrayBuffer
    aad?: ArrayBuffer
  }): ArrayBuffer

  keyAeadEncrypt(options: { localKeyHandle: string; message: ArrayBuffer; nonce?: ArrayBuffer; aad?: ArrayBuffer }): {
    noncePos: number
    tagPos: number
    buffer: ArrayBuffer
  }

  keyAeadGetPadding(options: { localKeyHandle: string; msgLen: number }): number

  keyAeadGetParams(options: { localKeyHandle: string }): { nonceLength: number; tagLength: number }

  keyAeadRandomNonce(options: any): ArrayBuffer

  keyConvert(options: any): LocalKeyHandle

  keyCryptoBox(options: any): ArrayBuffer

  keyCryptoBoxOpen(options: any): ArrayBuffer

  keyCryptoBoxRandomNonce(options: Record<string, never>): ArrayBuffer

  keyCryptoBoxSeal(options: any): ArrayBuffer

  keyCryptoBoxSealOpen(options: any): ArrayBuffer

  keyDeriveEcdh1pu(options: any): LocalKeyHandle

  keyDeriveEcdhEs(options: any): LocalKeyHandle

  keyEntryListCount(options: any): number

  keyEntryListFree(options: any): void

  keyEntryListGetAlgorithm(options: any): string

  keyEntryListGetMetadata(options: any): string

  keyEntryListGetName(options: any): string

  keyEntryListGetTags(options: any): string

  keyEntryListLoadLocal(options: any): LocalKeyHandle

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
    cb: CallbackWithResponse<number>
  }): void

  storeProvision(options: any): void

  storeRekey(options: any): void

  storeRemove(options: any): void

  storeRemoveProfile(options: any): void
}
