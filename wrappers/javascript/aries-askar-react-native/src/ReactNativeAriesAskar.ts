import type { NativeBindings } from './NativeBindings'
import type { Callback, CallbackWithResponse, ReturnObject } from './serialize'
import type {
  AriesAskar,
  AriesAskarErrorObject,
  EntryListCountOptions,
  EntryListFreeOptions,
  EntryListGetCategoryOptions,
  EntryListGetNameOptions,
  EntryListGetTagsOptions,
  EntryListGetValueOptions,
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
  MigrateIndySdkOptions,
  ScanFreeOptions,
  ScanNextOptions,
  ScanStartOptions,
  SessionCloseOptions,
  SessionCountOptions,
  SessionFetchAllKeysOptions,
  SessionFetchAllOptions,
  SessionFetchKeyOptions,
  SessionFetchOptions,
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
  StoreOpenOptions,
  StoreProvisionOptions,
  StoreRekeyOptions,
  StoreRemoveOptions,
  StoreRemoveProfileOptions,
} from '@hyperledger/aries-askar-shared'

import {
  AriesAskarError,
  handleInvalidNullResponse,
  AeadParams,
  EncryptedBuffer,
  LocalKeyHandle,
  EntryListHandle,
  StoreHandle,
  SessionHandle,
  ScanHandle,
  KeyEntryListHandle,
} from '@hyperledger/aries-askar-shared'

import { serializeArguments } from './serialize'

export class ReactNativeAriesAskar implements AriesAskar {
  private ariesAskar: NativeBindings

  public constructor(bindings: NativeBindings) {
    this.ariesAskar = bindings
  }

  private handleError<T>({ errorCode, value }: ReturnObject<T>): T {
    if (errorCode !== 0) {
      throw new AriesAskarError(JSON.parse(this.getCurrentError()) as AriesAskarErrorObject)
    }

    return value as T
  }

  private promisify = (method: (cb: Callback) => void): Promise<void> => {
    return new Promise((resolve, reject) => {
      const _cb: Callback = ({ errorCode }) => {
        if (errorCode !== 0) {
          reject(new AriesAskarError(JSON.parse(this.getCurrentError()) as AriesAskarErrorObject))
        } else {
          resolve()
        }
      }

      method(_cb)
    })
  }

  private promisifyWithResponse = <Return>(
    method: (cb: CallbackWithResponse<Return>) => void
  ): Promise<Return | null> => {
    return new Promise((resolve, reject) => {
      const _cb: CallbackWithResponse<Return> = ({ errorCode, value }) => {
        if (errorCode !== 0) {
          reject(new AriesAskarError(JSON.parse(this.getCurrentError()) as AriesAskarErrorObject))
        } else {
          if (value === undefined) {
            reject(
              AriesAskarError.customError({ message: 'error code was 0 but no value found. This should not occur.' })
            )
          } else {
            resolve(value)
          }
        }
      }
      method(_cb)
    })
  }

  public version(): string {
    return handleInvalidNullResponse(this.ariesAskar.version({}))
  }

  public getCurrentError(): string {
    return handleInvalidNullResponse(this.ariesAskar.getCurrentError({}))
  }

  public clearCustomLogger(): void {
    throw new Error('Method not implemented. clearCustomLogger')
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public setCustomLogger(_: SetCustomLoggerOptions): void {
    throw new Error('Method not implemented. setCustomLogger')
  }

  public setDefaultLogger(): void {
    this.ariesAskar.setDefaultLogger({})
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public setMaxLogLevel(_: SetMaxLogLevelOptions): void {
    throw new Error('Method not implemented. setMaxLogLevel')
  }

  public entryListCount(options: EntryListCountOptions): number {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.entryListCount(serializedOptions)))
  }

  public entryListFree(options: EntryListFreeOptions): void {
    const serializedOptions = serializeArguments(options)

    // null resopnse is expected as we're freeing the object
    this.handleError(this.ariesAskar.entryListFree(serializedOptions))
  }

  public entryListGetCategory(options: EntryListGetCategoryOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.entryListGetCategory(serializedOptions)))
  }

  public entryListGetName(options: EntryListGetNameOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.entryListGetName(serializedOptions)))
  }

  public entryListGetTags(options: EntryListGetTagsOptions): string | null {
    const serializedOptions = serializeArguments(options)
    return this.handleError(this.ariesAskar.entryListGetTags(serializedOptions))
  }

  public entryListGetValue(options: EntryListGetValueOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.entryListGetValue(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyAeadDecrypt(options: KeyAeadDecryptOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyAeadDecrypt(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyAeadEncrypt(options: KeyAeadEncryptOptions): EncryptedBuffer {
    const serializedOptions = serializeArguments(options)
    const ret = this.handleError(this.ariesAskar.keyAeadEncrypt(serializedOptions))

    const { buffer, noncePos, tagPos } = handleInvalidNullResponse(ret)

    return new EncryptedBuffer({ tagPos, noncePos, buffer: new Uint8Array(buffer) })
  }

  public keyAeadGetPadding(options: KeyAeadGetPaddingOptions): number {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.keyAeadGetPadding(serializedOptions)))
  }

  public keyAeadGetParams(options: KeyAeadGetParamsOptions): AeadParams {
    const serializedOptions = serializeArguments(options)
    const ret = this.handleError(this.ariesAskar.keyAeadGetParams(serializedOptions))

    const { tagLength, nonceLength } = handleInvalidNullResponse(ret)

    return new AeadParams({ nonceLength, tagLength })
  }

  public keyAeadRandomNonce(options: KeyAeadRandomNonceOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyAeadRandomNonce(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyConvert(options: KeyConvertOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyConvert(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyCryptoBox(options: KeyCryptoBoxOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyCryptoBox(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyCryptoBoxOpen(options: KeyCryptoBoxOpenOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyCryptoBoxOpen(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyCryptoBoxRandomNonce(): Uint8Array {
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyCryptoBoxRandomNonce({})))
    return new Uint8Array(buf)
  }

  public keyCryptoBoxSeal(options: KeyCryptoBoxSealOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyCryptoBoxSeal(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyCryptoBoxSealOpen(options: KeyCryptoBoxSealOpenOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyCryptoBoxSealOpen(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyDeriveEcdh1pu(options: KeyDeriveEcdh1puOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyDeriveEcdh1pu(serializedOptions)))
    return new LocalKeyHandle(handle)
  }

  public keyDeriveEcdhEs(options: KeyDeriveEcdhEsOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyDeriveEcdhEs(serializedOptions)))
    return new LocalKeyHandle(handle)
  }

  public keyEntryListCount(options: KeyEntryListCountOptions): number {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.keyEntryListCount(serializedOptions)))
  }

  public keyEntryListFree(options: KeyEntryListFreeOptions): void {
    const serializedOptions = serializeArguments(options)

    // null resopnse is expected as we're freeing the object
    this.handleError(this.ariesAskar.keyEntryListFree(serializedOptions))
  }

  public keyEntryListGetAlgorithm(options: KeyEntryListGetAlgorithmOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.keyEntryListGetAlgorithm(serializedOptions)))
  }

  public keyEntryListGetMetadata(options: KeyEntryListGetMetadataOptions): string | null {
    const serializedOptions = serializeArguments(options)
    return this.handleError(this.ariesAskar.keyEntryListGetMetadata(serializedOptions))
  }

  public keyEntryListGetName(options: KeyEntryListGetNameOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.keyEntryListGetName(serializedOptions)))
  }

  public keyEntryListGetTags(options: KeyEntryListGetTagsOptions): string | null {
    const serializedOptions = serializeArguments(options)
    return this.handleError(this.ariesAskar.keyEntryListGetTags(serializedOptions))
  }

  public keyEntryListLoadLocal(options: KeyEntryListLoadLocalOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyEntryListLoadLocal(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyFree(options: KeyFreeOptions): void {
    const serializedOptions = serializeArguments(options)

    // null resopnse is expected as we're freeing the object
    this.handleError(this.ariesAskar.keyFree(serializedOptions))
  }

  public keyFromJwk(options: KeyFromJwkOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyFromJwk(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyFromKeyExchange(options: KeyFromKeyExchangeOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyFromKeyExchange(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyFromPublicBytes(options: KeyFromPublicBytesOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyFromPublicBytes(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyFromSecretBytes(options: KeyFromSecretBytesOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyFromSecretBytes(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyFromSeed(options: KeyFromSeedOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyFromSeed(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyGenerate(options: KeyGenerateOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyGenerate(serializedOptions)))

    return new LocalKeyHandle(handleInvalidNullResponse(handle))
  }

  public keyGetAlgorithm(options: KeyGetAlgorithmOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.keyGetAlgorithm(serializedOptions)))
  }

  public keyGetEphemeral(options: KeyGetEphemeralOptions): number {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.keyGetEphemeral(serializedOptions)))
  }

  public keyGetJwkPublic(options: KeyGetJwkPublicOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.keyGetJwkPublic(serializedOptions)))
  }

  public keyGetJwkSecret(options: KeyGetJwkSecretOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyGetJwkSecret(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyGetJwkThumbprint(options: KeyGetJwkThumbprintOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.keyGetJwkThumbprint(serializedOptions)))
  }

  public keyGetPublicBytes(options: KeyGetPublicBytesOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyGetPublicBytes(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyGetSecretBytes(options: KeyGetSecretBytesOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyGetSecretBytes(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keySignMessage(options: KeySignMessageOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(this.handleError(this.ariesAskar.keySignMessage(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyUnwrapKey(options: KeyUnwrapKeyOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(this.handleError(this.ariesAskar.keyUnwrapKey(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyVerifySignature(options: KeyVerifySignatureOptions): boolean {
    const serializedOptions = serializeArguments(options)
    const result = this.handleError(this.ariesAskar.keyVerifySignature(serializedOptions))

    return !!result
  }

  public keyWrapKey(options: KeyWrapKeyOptions): EncryptedBuffer {
    const serializedOptions = serializeArguments(options)
    const ret = this.handleError(this.ariesAskar.keyWrapKey(serializedOptions))

    const { buffer, noncePos, tagPos } = handleInvalidNullResponse(ret)

    return new EncryptedBuffer({ tagPos, noncePos, buffer: new Uint8Array(buffer) })
  }

  public scanFree(options: ScanFreeOptions): void {
    const serializedOptions = serializeArguments(options)

    // null resopnse is expected as we're freeing the object
    this.handleError(this.ariesAskar.scanFree(serializedOptions))
  }

  public async scanNext(options: ScanNextOptions) {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      this.handleError(this.ariesAskar.scanNext({ cb, ...serializedOptions }))
    )

    return EntryListHandle.fromHandle(handle)
  }

  public async scanStart(options: ScanStartOptions): Promise<ScanHandle> {
    const { category, storeHandle, limit, offset, profile, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number>((cb) =>
      this.handleError(
        this.ariesAskar.scanStart({
          cb,
          category,
          storeHandle,
          offset: offset || 0,
          limit: limit || -1,
          profile,
          tagFilter,
        })
      )
    )

    return ScanHandle.fromHandle(handle)
  }

  public sessionClose(options: SessionCloseOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => this.handleError(this.ariesAskar.sessionClose({ cb, ...serializedOptions })))
  }

  public async sessionCount(options: SessionCountOptions): Promise<number> {
    const serializedOptions = serializeArguments(options)
    const response = await this.promisifyWithResponse<number>((cb) =>
      this.handleError(this.ariesAskar.sessionCount({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }

  public async sessionFetch(options: SessionFetchOptions) {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      this.handleError(this.ariesAskar.sessionFetch({ cb, ...serializedOptions }))
    )

    return EntryListHandle.fromHandle(handle)
  }

  public async sessionFetchAll(options: SessionFetchAllOptions) {
    const { category, sessionHandle, forUpdate, limit, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      this.handleError(
        this.ariesAskar.sessionFetchAll({ cb, category, sessionHandle, forUpdate, limit: limit || -1, tagFilter })
      )
    )

    return EntryListHandle.fromHandle(handle)
  }

  public async sessionFetchAllKeys(options: SessionFetchAllKeysOptions) {
    const { sessionHandle, algorithm, forUpdate, limit, thumbprint, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      this.handleError(
        this.ariesAskar.sessionFetchAllKeys({
          cb,
          sessionHandle,
          algorithm,
          forUpdate: forUpdate || -1,
          limit: limit || -1,
          thumbprint,
          tagFilter,
        })
      )
    )

    return KeyEntryListHandle.fromHandle(handle)
  }
  public async sessionFetchKey(options: SessionFetchKeyOptions) {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      this.handleError(this.ariesAskar.sessionFetchKey({ cb, ...serializedOptions }))
    )

    return KeyEntryListHandle.fromHandle(handle)
  }

  public sessionInsertKey(options: SessionInsertKeyOptions): Promise<void> {
    const { sessionHandle, name, localKeyHandle, expiryMs, metadata, tags } = serializeArguments(options)
    return this.promisify((cb) =>
      this.handleError(
        this.ariesAskar.sessionInsertKey({
          cb,
          sessionHandle,
          name,
          localKeyHandle,
          expiryMs: expiryMs || -1,
          metadata,
          tags,
        })
      )
    )
  }

  public async sessionRemoveAll(options: SessionRemoveAllOptions): Promise<number> {
    const serializedOptions = serializeArguments(options)
    const response = await this.promisifyWithResponse<number>((cb) =>
      this.handleError(this.ariesAskar.sessionRemoveAll({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }

  public sessionRemoveKey(options: SessionRemoveKeyOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => this.handleError(this.ariesAskar.sessionRemoveKey({ cb, ...serializedOptions })))
  }

  public async sessionStart(options: SessionStartOptions): Promise<SessionHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number>((cb) =>
      this.handleError(this.ariesAskar.sessionStart({ cb, ...serializedOptions }))
    )

    return SessionHandle.fromHandle(handle)
  }

  public sessionUpdate(options: SessionUpdateOptions): Promise<void> {
    const { category, name, operation, sessionHandle, expiryMs, tags, value } = serializeArguments(options)
    return this.promisify((cb) =>
      this.handleError(
        this.ariesAskar.sessionUpdate({
          cb,
          category,
          name,
          operation,
          sessionHandle,
          expiryMs: expiryMs || -1,
          tags,
          value,
        })
      )
    )
  }

  public sessionUpdateKey(options: SessionUpdateKeyOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => this.handleError(this.ariesAskar.sessionUpdateKey({ cb, ...serializedOptions })))
  }

  public storeClose(options: StoreCloseOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => this.handleError(this.ariesAskar.storeClose({ cb, ...serializedOptions })))
  }

  public async storeCreateProfile(options: StoreCreateProfileOptions): Promise<string> {
    const serializedOptions = serializeArguments(options)
    const response = await this.promisifyWithResponse<string>((cb) =>
      this.handleError(this.ariesAskar.storeCreateProfile({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }

  public storeGenerateRawKey(options: StoreGenerateRawKeyOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(this.handleError(this.ariesAskar.storeGenerateRawKey(serializedOptions)))
  }

  public async storeGetProfileName(options: StoreGetProfileNameOptions): Promise<string> {
    const serializedOptions = serializeArguments(options)
    const response = await this.promisifyWithResponse<string>((cb) =>
      this.handleError(this.ariesAskar.storeGetProfileName({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }

  public async storeOpen(options: StoreOpenOptions): Promise<StoreHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number>((cb) =>
      this.handleError(this.ariesAskar.storeOpen({ cb, ...serializedOptions }))
    )

    return StoreHandle.fromHandle(handle)
  }

  public async storeProvision(options: StoreProvisionOptions): Promise<StoreHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number>((cb) =>
      this.handleError(this.ariesAskar.storeProvision({ cb, ...serializedOptions }))
    )

    return StoreHandle.fromHandle(handle)
  }

  public storeRekey(options: StoreRekeyOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => this.handleError(this.ariesAskar.storeRekey({ cb, ...serializedOptions })))
  }

  public async storeRemove(options: StoreRemoveOptions): Promise<number> {
    const serializedOptions = serializeArguments(options)
    const response = await this.promisifyWithResponse<number>((cb) =>
      this.handleError(this.ariesAskar.storeRemove({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }

  public async storeRemoveProfile(options: StoreRemoveProfileOptions): Promise<number> {
    const serializedOptions = serializeArguments(options)
    const response = await this.promisifyWithResponse<number>((cb) =>
      this.handleError(this.ariesAskar.storeRemoveProfile({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }

  public async migrateIndySdk(options: MigrateIndySdkOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => this.handleError(this.ariesAskar.migrateIndySdk({ cb, ...serializedOptions })))
  }
}
