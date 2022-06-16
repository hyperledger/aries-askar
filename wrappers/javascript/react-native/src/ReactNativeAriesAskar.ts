import type {
  AeadParams,
  AriesAskar,
  BufferFreeOptions,
  EncryptedBuffer,
  EntryListCountOptions,
  EntryListFreeOptions,
  EntryListGetCategoryOptions,
  EntryListGetNameOptions,
  EntryListGetTagsOptions,
  EntryListGetValueOptions,
  EntryListHandle,
  KeyAeadDecryptOptions,
  KeyAeadEncryptOptions,
  KeyAeadGetPaddingOptions,
  KeyAeadGetParamsOptions,
  KeyAeadRandomNonceOptions,
  KeyConvertOptions,
  KeyCryptoBoxOpenOptions,
  KeyCryptoBoxOptions,
  KeyCryptoBoxSealOpenOptions,
  KeyCryptoBoxSealOptions,
  KeyDeriveEcdh1puOptions,
  KeyDeriveEcdhEsOptions,
  KeyEntryListCountOptions,
  KeyEntryListFreeOptions,
  KeyEntryListGetAlgorithmOptions,
  KeyEntryListGetMetadataOptions,
  KeyEntryListGetNameOptions,
  KeyEntryListGetTagsOptions,
  KeyEntryListHandle,
  KeyEntryListLoadLocalOptions,
  KeyFreeOptions,
  KeyFromJwkOptions,
  KeyFromKeyExchangeOptions,
  KeyFromPublicBytesOptions,
  KeyFromSecretBytesOptions,
  KeyFromSeedOptions,
  KeyGenerateOptions,
  KeyGetAlgorithmOptions,
  KeyGetEphemeralOptions,
  KeyGetJwkPublicOptions,
  KeyGetJwkSecretOptions,
  KeyGetJwkThumbprintOptions,
  KeyGetPublicBytesOptions,
  KeyGetSecretBytesOptions,
  KeySignMessageOptions,
  KeyUnwrapKeyOptions,
  KeyVerifySignatureOptions,
  KeyWrapKeyOptions,
  LocalKeyHandle,
  ScanFreeOptions,
  ScanHandle,
  ScanNextOptions,
  ScanStartOptions,
  SecretBuffer,
  SessionCloseOptions,
  SessionCountOptions,
  SessionFetchAllKeysOptions,
  SessionFetchAllOptions,
  SessionFetchKeyOptions,
  SessionFetchOptions,
  SessionHandle,
  SessionInsertKeyOptions,
  SessionRemoveAllOptions,
  SessionRemoveKeyOptions,
  SessionStartOptions,
  SessionUpdateKeyOptions,
  SessionUpdateOptions,
  SetCustomLoggerOptions,
  SetMaxLogLevelOptions,
  StoreCloseOptions,
  StoreCreateProfileOptions,
  StoreGenerateRawKeyOptions,
  StoreGetProfileNameOptions,
  StoreHandle,
  StoreOpenOptions,
  StoreProvisionOptions,
  StoreRekeyOptions,
  StoreRemoveOptions,
  StoreRemoveProfileOptions,
} from 'aries-askar-shared'

export class ReactNativeAriesAskar implements AriesAskar {
  public version(): string {
    throw new Error('Method not implemented.')
  }
  public getCurrentError(): string {
    throw new Error('Method not implemented.')
  }
  public bufferFree(options: BufferFreeOptions): void {
    throw new Error('Method not implemented.')
  }
  public clearCustomLogger(): void {
    throw new Error('Method not implemented.')
  }
  public setCustomLogger(options: SetCustomLoggerOptions): void {
    throw new Error('Method not implemented.')
  }
  public setDefaultLogger(): void {
    throw new Error('Method not implemented.')
  }
  public setMaxLogLevel(options: SetMaxLogLevelOptions): void {
    throw new Error('Method not implemented.')
  }
  public entryListCount(options: EntryListCountOptions): number {
    throw new Error('Method not implemented.')
  }
  public entryListFree(options: EntryListFreeOptions): void {
    throw new Error('Method not implemented.')
  }
  public entryListGetCategory(options: EntryListGetCategoryOptions): string {
    throw new Error('Method not implemented.')
  }
  public entryListGetName(options: EntryListGetNameOptions): string {
    throw new Error('Method not implemented.')
  }
  public entryListGetTags(options: EntryListGetTagsOptions): string {
    throw new Error('Method not implemented.')
  }
  public entryListGetValue(options: EntryListGetValueOptions): string {
    throw new Error('Method not implemented.')
  }
  public keyAeadDecrypt(options: KeyAeadDecryptOptions): SecretBuffer {
    throw new Error('Method not implemented.')
  }
  public keyAeadEncrypt(options: KeyAeadEncryptOptions): EncryptedBuffer {
    throw new Error('Method not implemented.')
  }
  public keyAeadGetPadding(options: KeyAeadGetPaddingOptions): number {
    throw new Error('Method not implemented.')
  }
  public keyAeadGetParams(options: KeyAeadGetParamsOptions): AeadParams {
    throw new Error('Method not implemented.')
  }
  public keyAeadRandomNonce(options: KeyAeadRandomNonceOptions): Uint8Array {
    throw new Error('Method not implemented.')
  }
  public keyConvert(options: KeyConvertOptions): LocalKeyHandle {
    throw new Error('Method not implemented.')
  }
  public keyCryptoBox(options: KeyCryptoBoxOptions): Uint8Array {
    throw new Error('Method not implemented.')
  }
  public keyCryptoBoxOpen(options: KeyCryptoBoxOpenOptions): Uint8Array {
    throw new Error('Method not implemented.')
  }
  public keyCryptoBoxRandomNonce(): Uint8Array {
    throw new Error('Method not implemented.')
  }
  public keyCryptoBoxSeal(options: KeyCryptoBoxSealOptions): Uint8Array {
    throw new Error('Method not implemented.')
  }
  public keyCryptoBoxSealOpen(options: KeyCryptoBoxSealOpenOptions): Uint8Array {
    throw new Error('Method not implemented.')
  }
  public keyDeriveEcdh1pu(options: KeyDeriveEcdh1puOptions): LocalKeyHandle {
    throw new Error('Method not implemented.')
  }
  public keyDeriveEcdhEs(options: KeyDeriveEcdhEsOptions): LocalKeyHandle {
    throw new Error('Method not implemented.')
  }
  public keyEntryListCount(options: KeyEntryListCountOptions): number {
    throw new Error('Method not implemented.')
  }
  public keyEntryListFree(options: KeyEntryListFreeOptions): void {
    throw new Error('Method not implemented.')
  }
  public keyEntryListGetAlgorithm(options: KeyEntryListGetAlgorithmOptions): string {
    throw new Error('Method not implemented.')
  }
  public keyEntryListGetMetadata(options: KeyEntryListGetMetadataOptions): string {
    throw new Error('Method not implemented.')
  }
  public keyEntryListGetName(options: KeyEntryListGetNameOptions): string {
    throw new Error('Method not implemented.')
  }
  public keyEntryListGetTags(options: KeyEntryListGetTagsOptions): string {
    throw new Error('Method not implemented.')
  }
  public keyEntryListLoadLocal(options: KeyEntryListLoadLocalOptions): LocalKeyHandle {
    throw new Error('Method not implemented.')
  }
  public keyFree(options: KeyFreeOptions): void {
    throw new Error('Method not implemented.')
  }
  public keyFromJwk(options: KeyFromJwkOptions): LocalKeyHandle {
    throw new Error('Method not implemented.')
  }
  public keyFromKeyExchange(options: KeyFromKeyExchangeOptions): LocalKeyHandle {
    throw new Error('Method not implemented.')
  }
  public keyFromPublicBytes(options: KeyFromPublicBytesOptions): LocalKeyHandle {
    throw new Error('Method not implemented.')
  }
  public keyFromSecretBytes(options: KeyFromSecretBytesOptions): LocalKeyHandle {
    throw new Error('Method not implemented.')
  }
  public keyFromSeed(options: KeyFromSeedOptions): LocalKeyHandle {
    throw new Error('Method not implemented.')
  }
  public keyGenerate(options: KeyGenerateOptions): LocalKeyHandle {
    throw new Error('Method not implemented.')
  }
  public keyGetAlgorithm(options: KeyGetAlgorithmOptions): string {
    throw new Error('Method not implemented.')
  }
  public keyGetEphemeral(options: KeyGetEphemeralOptions): number {
    throw new Error('Method not implemented.')
  }
  public keyGetJwkPublic(options: KeyGetJwkPublicOptions): string {
    throw new Error('Method not implemented.')
  }
  public keyGetJwkSecret(options: KeyGetJwkSecretOptions): string {
    throw new Error('Method not implemented.')
  }
  public keyGetJwkThumbprint(options: KeyGetJwkThumbprintOptions): string {
    throw new Error('Method not implemented.')
  }
  public keyGetPublicBytes(options: KeyGetPublicBytesOptions): Uint8Array {
    throw new Error('Method not implemented.')
  }
  public keyGetSecretBytes(options: KeyGetSecretBytesOptions): Uint8Array {
    throw new Error('Method not implemented.')
  }
  public keySignMessage(options: KeySignMessageOptions): Uint8Array {
    throw new Error('Method not implemented.')
  }
  public keyUnwrapKey(options: KeyUnwrapKeyOptions): LocalKeyHandle {
    throw new Error('Method not implemented.')
  }
  public keyVerifySignature(options: KeyVerifySignatureOptions): boolean {
    throw new Error('Method not implemented.')
  }
  public keyWrapKey(options: KeyWrapKeyOptions): EncryptedBuffer {
    throw new Error('Method not implemented.')
  }
  public scanFree(options: ScanFreeOptions): void {
    throw new Error('Method not implemented.')
  }
  public scanNext(options: ScanNextOptions): Promise<EntryListHandle> {
    throw new Error('Method not implemented.')
  }
  public scanStart(options: ScanStartOptions): Promise<ScanHandle> {
    throw new Error('Method not implemented.')
  }
  public sessionClose(options: SessionCloseOptions): Promise<void> {
    throw new Error('Method not implemented.')
  }
  public sessionCount(options: SessionCountOptions): Promise<number> {
    throw new Error('Method not implemented.')
  }
  public sessionFetch(options: SessionFetchOptions): Promise<EntryListHandle> {
    throw new Error('Method not implemented.')
  }
  public sessionFetchAll(options: SessionFetchAllOptions): Promise<EntryListHandle> {
    throw new Error('Method not implemented.')
  }
  public sessionFetchAllKeys(options: SessionFetchAllKeysOptions): Promise<KeyEntryListHandle> {
    throw new Error('Method not implemented.')
  }
  public sessionFetchKey(options: SessionFetchKeyOptions): Promise<KeyEntryListHandle> {
    throw new Error('Method not implemented.')
  }
  public sessionInsertKey(options: SessionInsertKeyOptions): Promise<void> {
    throw new Error('Method not implemented.')
  }
  public sessionRemoveAll(options: SessionRemoveAllOptions): Promise<number> {
    throw new Error('Method not implemented.')
  }
  public sessionRemoveKey(options: SessionRemoveKeyOptions): Promise<void> {
    throw new Error('Method not implemented.')
  }
  public sessionStart(options: SessionStartOptions): Promise<SessionHandle> {
    throw new Error('Method not implemented.')
  }
  public sessionUpdate(options: SessionUpdateOptions): Promise<void> {
    throw new Error('Method not implemented.')
  }
  public sessionUpdateKey(options: SessionUpdateKeyOptions): Promise<void> {
    throw new Error('Method not implemented.')
  }
  public storeClose(options: StoreCloseOptions): Promise<void> {
    throw new Error('Method not implemented.')
  }
  public storeCreateProfile(options: StoreCreateProfileOptions): Promise<string> {
    throw new Error('Method not implemented.')
  }
  public storeGenerateRawKey(options: StoreGenerateRawKeyOptions): string {
    throw new Error('Method not implemented.')
  }
  public storeGetProfileName(options: StoreGetProfileNameOptions): Promise<string> {
    throw new Error('Method not implemented.')
  }
  public storeOpen(options: StoreOpenOptions): Promise<StoreHandle> {
    throw new Error('Method not implemented.')
  }
  public storeProvision(options: StoreProvisionOptions): Promise<StoreHandle> {
    throw new Error('Method not implemented.')
  }
  public storeRekey(options: StoreRekeyOptions): Promise<void> {
    throw new Error('Method not implemented.')
  }
  public storeRemove(options: StoreRemoveOptions): Promise<number> {
    throw new Error('Method not implemented.')
  }
  public storeRemoveProfile(options: StoreRemoveProfileOptions): Promise<number> {
    throw new Error('Method not implemented.')
  }
}
