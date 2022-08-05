import type {
  EntryListHandle,
  Jwk,
  Key,
  KeyEntryListHandle,
  LocalKeyHandle,
  ScanHandle,
  SessionHandle,
  StoreHandle,
} from '../crypto'
import type { KeyAlgs, LogLevel, SigAlgs } from '../enums'
import type { AeadParams, EncryptedBuffer } from '../types'

export type ErrorCode = number

export type NativeLogCallback = (
  context: unknown,
  level: number,
  target: string,
  message: string,
  modulePath: string,
  file: string,
  line: number
) => void

export type SetCustomLoggerOptions = {
  logLevel: LogLevel
  flush?: boolean
  enabled?: boolean
  logger: NativeLogCallback
}
export type SetMaxLogLevelOptions = { logLevel: number }

export type EntryListCountOptions = { entryListHandle: EntryListHandle }
export type EntryListFreeOptions = { entryListHandle: EntryListHandle }
export type EntryListGetCategoryOptions = { entryListHandle: EntryListHandle; index: number }
export type EntryListGetNameOptions = { entryListHandle: EntryListHandle; index: number }
export type EntryListGetTagsOptions = { entryListHandle: EntryListHandle; index: number }
export type EntryListGetValueOptions = { entryListHandle: EntryListHandle; index: number }

export type KeyAeadDecryptOptions = {
  localKeyHandle: LocalKeyHandle
  ciphertext: Uint8Array
  nonce: Uint8Array
  tag?: Uint8Array
  aad?: Uint8Array
}
export type KeyAeadEncryptOptions = {
  localKeyHandle: LocalKeyHandle
  message: Uint8Array
  nonce?: Uint8Array
  aad?: Uint8Array
}
export type KeyAeadGetPaddingOptions = { localKeyHandle: LocalKeyHandle; msgLen: number }
export type KeyAeadGetParamsOptions = { localKeyHandle: LocalKeyHandle }
export type KeyAeadRandomNonceOptions = { localKeyHandle: LocalKeyHandle }
export type KeyConvertOptions = { localKeyHandle: LocalKeyHandle; algorithm: KeyAlgs }
export type KeyCryptoBoxOptions = {
  recipientKey: Key
  senderKey: Key
  message: Uint8Array
  nonce: Uint8Array
}
export type KeyCryptoBoxOpenOptions = {
  recipientKey: Key
  senderKey: Key
  message: Uint8Array
  nonce: Uint8Array
}
export type KeyCryptoBoxSealOptions = { localKeyHandle: LocalKeyHandle; message: Uint8Array }
export type KeyCryptoBoxSealOpenOptions = { localKeyHandle: LocalKeyHandle; ciphertext: Uint8Array }
export type KeyDeriveEcdh1puOptions = {
  algorithm: KeyAlgs
  ephemeralKey: Key
  senderKey: Key
  recipientKey: Key
  algId: Uint8Array
  apu: Uint8Array
  apv: Uint8Array
  ccTag?: Uint8Array
  receive: boolean
}
export type KeyDeriveEcdhEsOptions = {
  algorithm: KeyAlgs
  ephemeralKey: Key
  recipientKey: Key
  algId: Uint8Array
  apu: Uint8Array
  apv: Uint8Array
  receive: boolean
}
export type KeyEntryListCountOptions = { keyEntryListHandle: KeyEntryListHandle }
export type KeyEntryListFreeOptions = { keyEntryListHandle: KeyEntryListHandle }
export type KeyEntryListGetAlgorithmOptions = { keyEntryListHandle: KeyEntryListHandle; index: number }
export type KeyEntryListGetMetadataOptions = { keyEntryListHandle: KeyEntryListHandle; index: number }
export type KeyEntryListGetNameOptions = { keyEntryListHandle: KeyEntryListHandle; index: number }
export type KeyEntryListGetTagsOptions = { keyEntryListHandle: KeyEntryListHandle; index: number }
export type KeyEntryListLoadLocalOptions = { keyEntryListHandle: KeyEntryListHandle; index: number }
export type KeyFreeOptions = { keyEntryListHandle: KeyEntryListHandle }
export type KeyFromJwkOptions = { jwk: Jwk }
export type KeyFromKeyExchangeOptions = {
  algorithm: KeyAlgs
  skHandle: LocalKeyHandle
  pkHandle: LocalKeyHandle
}
export type KeyFromPublicBytesOptions = { algorithm: KeyAlgs; publicKey: Uint8Array }
export type KeyFromSecretBytesOptions = { algorithm: KeyAlgs; secretKey: Uint8Array }
export type KeyFromSeedOptions = { algorithm: KeyAlgs; seed: Uint8Array; method: string }
export type KeyGenerateOptions = { algorithm: KeyAlgs; ephemeral: boolean }
export type KeyGetAlgorithmOptions = { localKeyHandle: LocalKeyHandle }
export type KeyGetEphemeralOptions = { localKeyHandle: LocalKeyHandle }
export type KeyGetJwkPublicOptions = { localKeyHandle: LocalKeyHandle; algorithm: string }
export type KeyGetJwkSecretOptions = { localKeyHandle: LocalKeyHandle }
export type KeyGetJwkThumbprintOptions = { localKeyHandle: LocalKeyHandle; algorithm: string }
export type KeyGetPublicBytesOptions = { localKeyHandle: LocalKeyHandle }
export type KeyGetSecretBytesOptions = { localKeyHandle: LocalKeyHandle }
export type KeySignMessageOptions = { localKeyHandle: LocalKeyHandle; message: Uint8Array; sigType?: SigAlgs }
export type KeyUnwrapKeyOptions = {
  localKeyHandle: LocalKeyHandle
  algorithm: KeyAlgs
  ciphertext: Uint8Array
  nonce?: Uint8Array
  tag?: Uint8Array
}
export type KeyVerifySignatureOptions = {
  localKeyHandle: LocalKeyHandle
  message: Uint8Array
  signature: Uint8Array
  sigType?: SigAlgs
}
export type KeyWrapKeyOptions = {
  localKeyHandle: LocalKeyHandle
  other: LocalKeyHandle
  nonce?: Uint8Array
}

export type ScanFreeOptions = { scanHandle: ScanHandle }
export type ScanNextOptions = { scanHandle: ScanHandle }
export type ScanStartOptions = {
  storeHandle: StoreHandle
  category: string
  profile?: string
  tagFilter?: Record<string, unknown>
  offset?: number
  limit?: number
}

export type SessionCloseOptions = { sessionHandle: SessionHandle; commit: boolean }
export type SessionCountOptions = {
  sessionHandle: SessionHandle
  category: string
  tagFilter?: Record<string, unknown>
}
export type SessionFetchOptions = {
  sessionHandle: SessionHandle
  category: string
  name: string
  forUpdate: boolean
}
export type SessionFetchAllOptions = {
  sessionHandle: SessionHandle
  category: string
  tagFilter?: Record<string, unknown>
  limit?: number
  forUpdate: boolean
}
export type SessionFetchAllKeysOptions = {
  sessionHandle: SessionHandle
  forUpdate: boolean
  algorithm?: string
  thumbprint?: string
  tagFilter?: Record<string, unknown>
  limit?: number
}
export type SessionFetchKeyOptions = { sessionHandle: SessionHandle; name: string; forUpdate: boolean }
export type SessionInsertKeyOptions = {
  sessionHandle: SessionHandle
  localKeyHandle: LocalKeyHandle
  name: string
  metadata?: string
  tags?: Record<string, unknown>
  expiryMs?: number
}
export type SessionRemoveAllOptions = {
  sessionHandle: SessionHandle
  category: string
  tagFilter?: Record<string, unknown>
}
export type SessionRemoveKeyOptions = { sessionHandle: SessionHandle; name: string }
export type SessionStartOptions = { storeHandle: StoreHandle; profile?: string; asTransaction: boolean }
export type SessionUpdateOptions = {
  sessionHandle: SessionHandle
  operation: number
  category: string
  name: string
  value?: Uint8Array
  tags?: Record<string, unknown>
  expiryMs?: number
}
export type SessionUpdateKeyOptions = {
  sessionHandle: SessionHandle
  name: string
  metadata?: string
  tags?: Record<string, unknown>
  expiryMs?: number
}

export type StoreCloseOptions = { storeHandle: StoreHandle }
export type StoreCreateProfileOptions = { storeHandle: StoreHandle; profile?: string }
export type StoreGenerateRawKeyOptions = { seed?: Uint8Array }
export type StoreGetProfileNameOptions = { storeHandle: StoreHandle }
export type StoreOpenOptions = { specUri: string; keyMethod?: string; passKey?: string; profile?: string }
export type StoreProvisionOptions = {
  specUri: string
  keyMethod?: string
  passKey?: string
  profile?: string
  recreate: boolean
}
export type StoreRekeyOptions = { storeHandle: StoreHandle; keyMethod: string; passKey: string }
export type StoreRemoveOptions = { specUri: string }
export type StoreRemoveProfileOptions = { storeHandle: StoreHandle; profile: string }

export type AriesAskar = {
  version(): string
  getCurrentError(): string
  clearCustomLogger(): void

  setCustomLogger(options: SetCustomLoggerOptions): void
  setDefaultLogger(): void
  setMaxLogLevel(options: SetMaxLogLevelOptions): void

  entryListCount(options: EntryListCountOptions): number
  entryListFree(options: EntryListFreeOptions): void
  entryListGetCategory(options: EntryListGetCategoryOptions): string
  entryListGetName(options: EntryListGetNameOptions): string
  entryListGetTags(options: EntryListGetTagsOptions): string
  entryListGetValue(options: EntryListGetValueOptions): Uint8Array

  keyAeadDecrypt(options: KeyAeadDecryptOptions): Uint8Array
  keyAeadEncrypt(options: KeyAeadEncryptOptions): EncryptedBuffer
  keyAeadGetPadding(options: KeyAeadGetPaddingOptions): number
  keyAeadGetParams(options: KeyAeadGetParamsOptions): AeadParams
  keyAeadRandomNonce(options: KeyAeadRandomNonceOptions): Uint8Array
  keyConvert(options: KeyConvertOptions): LocalKeyHandle
  keyCryptoBox(options: KeyCryptoBoxOptions): Uint8Array
  keyCryptoBoxOpen(options: KeyCryptoBoxOpenOptions): Uint8Array
  keyCryptoBoxRandomNonce(): Uint8Array
  keyCryptoBoxSeal(options: KeyCryptoBoxSealOptions): Uint8Array
  keyCryptoBoxSealOpen(options: KeyCryptoBoxSealOpenOptions): Uint8Array
  keyDeriveEcdh1pu(options: KeyDeriveEcdh1puOptions): LocalKeyHandle
  keyDeriveEcdhEs(options: KeyDeriveEcdhEsOptions): LocalKeyHandle
  keyEntryListCount(options: KeyEntryListCountOptions): number
  keyEntryListFree(options: KeyEntryListFreeOptions): void
  keyEntryListGetAlgorithm(options: KeyEntryListGetAlgorithmOptions): string
  keyEntryListGetMetadata(options: KeyEntryListGetMetadataOptions): string
  keyEntryListGetName(options: KeyEntryListGetNameOptions): string
  keyEntryListGetTags(options: KeyEntryListGetTagsOptions): string
  keyEntryListLoadLocal(options: KeyEntryListLoadLocalOptions): LocalKeyHandle
  keyFree(options: KeyFreeOptions): void
  keyFromJwk(options: KeyFromJwkOptions): LocalKeyHandle
  keyFromKeyExchange(options: KeyFromKeyExchangeOptions): LocalKeyHandle
  keyFromPublicBytes(options: KeyFromPublicBytesOptions): LocalKeyHandle
  keyFromSecretBytes(options: KeyFromSecretBytesOptions): LocalKeyHandle
  keyFromSeed(options: KeyFromSeedOptions): LocalKeyHandle
  keyGenerate(options: KeyGenerateOptions): LocalKeyHandle
  keyGetAlgorithm(options: KeyGetAlgorithmOptions): string
  keyGetEphemeral(options: KeyGetEphemeralOptions): number
  keyGetJwkPublic(options: KeyGetJwkPublicOptions): string
  keyGetJwkSecret(options: KeyGetJwkSecretOptions): Uint8Array
  keyGetJwkThumbprint(options: KeyGetJwkThumbprintOptions): string
  keyGetPublicBytes(options: KeyGetPublicBytesOptions): Uint8Array
  keyGetSecretBytes(options: KeyGetSecretBytesOptions): Uint8Array
  keySignMessage(options: KeySignMessageOptions): Uint8Array
  keyUnwrapKey(options: KeyUnwrapKeyOptions): LocalKeyHandle
  keyVerifySignature(options: KeyVerifySignatureOptions): boolean
  keyWrapKey(options: KeyWrapKeyOptions): EncryptedBuffer

  scanFree(options: ScanFreeOptions): void
  scanNext(options: ScanNextOptions): Promise<EntryListHandle>
  scanStart(options: ScanStartOptions): Promise<ScanHandle>

  sessionClose(options: SessionCloseOptions): Promise<void>
  sessionCount(options: SessionCountOptions): Promise<number>
  sessionFetch(options: SessionFetchOptions): Promise<EntryListHandle>
  sessionFetchAll(options: SessionFetchAllOptions): Promise<EntryListHandle>
  sessionFetchAllKeys(options: SessionFetchAllKeysOptions): Promise<KeyEntryListHandle>
  sessionFetchKey(options: SessionFetchKeyOptions): Promise<KeyEntryListHandle>
  sessionInsertKey(options: SessionInsertKeyOptions): Promise<void>
  sessionRemoveAll(options: SessionRemoveAllOptions): Promise<number>
  sessionRemoveKey(options: SessionRemoveKeyOptions): Promise<void>
  sessionStart(options: SessionStartOptions): Promise<SessionHandle>
  sessionUpdate(options: SessionUpdateOptions): Promise<void>
  sessionUpdateKey(options: SessionUpdateKeyOptions): Promise<void>

  storeClose(options: StoreCloseOptions): Promise<void>
  storeCreateProfile(options: StoreCreateProfileOptions): Promise<string>
  storeGenerateRawKey(options: StoreGenerateRawKeyOptions): string
  storeGetProfileName(options: StoreGetProfileNameOptions): Promise<string>
  storeOpen(options: StoreOpenOptions): Promise<StoreHandle>
  storeProvision(options: StoreProvisionOptions): Promise<StoreHandle>
  storeRekey(options: StoreRekeyOptions): Promise<void>
  storeRemove(options: StoreRemoveOptions): Promise<number>
  storeRemoveProfile(options: StoreRemoveProfileOptions): Promise<number>
}
