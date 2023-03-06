import type { Callback, CallbackWithResponse } from './utils'
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

import { ariesAskarReactNative } from './library'
import { handleError, serializeArguments } from './utils'

export class ReactNativeAriesAskar implements AriesAskar {
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
    return handleInvalidNullResponse(ariesAskarReactNative.version({}))
  }

  public getCurrentError(): string {
    return handleInvalidNullResponse(ariesAskarReactNative.getCurrentError({}))
  }

  public clearCustomLogger(): void {
    throw new Error('Method not implemented. clearCustomLogger')
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public setCustomLogger(_: SetCustomLoggerOptions): void {
    throw new Error('Method not implemented. setCustomLogger')
  }

  public setDefaultLogger(): void {
    ariesAskarReactNative.setDefaultLogger({})
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public setMaxLogLevel(_: SetMaxLogLevelOptions): void {
    throw new Error('Method not implemented. setMaxLogLevel')
  }

  public entryListCount(options: EntryListCountOptions): number {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.entryListCount(serializedOptions)))
  }

  public entryListFree(options: EntryListFreeOptions): void {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.entryListFree(serializedOptions)))
  }

  public entryListGetCategory(options: EntryListGetCategoryOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.entryListGetCategory(serializedOptions)))
  }

  public entryListGetName(options: EntryListGetNameOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.entryListGetName(serializedOptions)))
  }

  public entryListGetTags(options: EntryListGetTagsOptions): string | null {
    const serializedOptions = serializeArguments(options)
    return handleError(ariesAskarReactNative.entryListGetTags(serializedOptions))
  }

  public entryListGetValue(options: EntryListGetValueOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.entryListGetValue(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyAeadDecrypt(options: KeyAeadDecryptOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyAeadDecrypt(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyAeadEncrypt(options: KeyAeadEncryptOptions): EncryptedBuffer {
    const serializedOptions = serializeArguments(options)
    const ret = handleError(ariesAskarReactNative.keyAeadEncrypt(serializedOptions))

    const { buffer, noncePos, tagPos } = handleInvalidNullResponse(ret)

    return new EncryptedBuffer({ tagPos, noncePos, buffer: new Uint8Array(buffer) })
  }

  public keyAeadGetPadding(options: KeyAeadGetPaddingOptions): number {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.keyAeadGetPadding(serializedOptions)))
  }

  public keyAeadGetParams(options: KeyAeadGetParamsOptions): AeadParams {
    const serializedOptions = serializeArguments(options)
    const ret = handleError(ariesAskarReactNative.keyAeadGetParams(serializedOptions))

    const { tagLength, nonceLength } = handleInvalidNullResponse(ret)

    return new AeadParams({ nonceLength, tagLength })
  }

  public keyAeadRandomNonce(options: KeyAeadRandomNonceOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyAeadRandomNonce(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyConvert(options: KeyConvertOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyConvert(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyCryptoBox(options: KeyCryptoBoxOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyCryptoBox(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyCryptoBoxOpen(options: KeyCryptoBoxOpenOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyCryptoBoxOpen(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyCryptoBoxRandomNonce(): Uint8Array {
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyCryptoBoxRandomNonce({})))
    return new Uint8Array(buf)
  }

  public keyCryptoBoxSeal(options: KeyCryptoBoxSealOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyCryptoBoxSeal(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyCryptoBoxSealOpen(options: KeyCryptoBoxSealOpenOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyCryptoBoxSealOpen(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyDeriveEcdh1pu(options: KeyDeriveEcdh1puOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyDeriveEcdh1pu(serializedOptions)))
    return new LocalKeyHandle(handle)
  }

  public keyDeriveEcdhEs(options: KeyDeriveEcdhEsOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyDeriveEcdhEs(serializedOptions)))
    return new LocalKeyHandle(handle)
  }

  public keyEntryListCount(options: KeyEntryListCountOptions): number {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.keyEntryListCount(serializedOptions)))
  }

  public keyEntryListFree(options: KeyEntryListFreeOptions): void {
    const serializedOptions = serializeArguments(options)
    handleError(ariesAskarReactNative.keyEntryListFree(serializedOptions))
  }

  public keyEntryListGetAlgorithm(options: KeyEntryListGetAlgorithmOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.keyEntryListGetAlgorithm(serializedOptions)))
  }

  public keyEntryListGetMetadata(options: KeyEntryListGetMetadataOptions): string | null {
    const serializedOptions = serializeArguments(options)
    return handleError(ariesAskarReactNative.keyEntryListGetMetadata(serializedOptions))
  }

  public keyEntryListGetName(options: KeyEntryListGetNameOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.keyEntryListGetName(serializedOptions)))
  }

  public keyEntryListGetTags(options: KeyEntryListGetTagsOptions): string | null {
    const serializedOptions = serializeArguments(options)
    return handleError(ariesAskarReactNative.keyEntryListGetTags(serializedOptions))
  }

  public keyEntryListLoadLocal(options: KeyEntryListLoadLocalOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(
      handleError(ariesAskarReactNative.keyEntryListLoadLocal(serializedOptions))
    )

    return new LocalKeyHandle(handle)
  }

  public keyFree(options: KeyFreeOptions): void {
    const serializedOptions = serializeArguments(options)
    handleError(ariesAskarReactNative.keyFree(serializedOptions))
  }

  public keyFromJwk(options: KeyFromJwkOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyFromJwk(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyFromKeyExchange(options: KeyFromKeyExchangeOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyFromKeyExchange(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyFromPublicBytes(options: KeyFromPublicBytesOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyFromPublicBytes(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyFromSecretBytes(options: KeyFromSecretBytesOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyFromSecretBytes(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyFromSeed(options: KeyFromSeedOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyFromSeed(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyGenerate(options: KeyGenerateOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyGenerate(serializedOptions)))

    return new LocalKeyHandle(handleInvalidNullResponse(handle))
  }

  public keyGetAlgorithm(options: KeyGetAlgorithmOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.keyGetAlgorithm(serializedOptions)))
  }

  public keyGetEphemeral(options: KeyGetEphemeralOptions): number {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.keyGetEphemeral(serializedOptions)))
  }

  public keyGetJwkPublic(options: KeyGetJwkPublicOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.keyGetJwkPublic(serializedOptions)))
  }

  public keyGetJwkSecret(options: KeyGetJwkSecretOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyGetJwkSecret(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyGetJwkThumbprint(options: KeyGetJwkThumbprintOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.keyGetJwkThumbprint(serializedOptions)))
  }

  public keyGetPublicBytes(options: KeyGetPublicBytesOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyGetPublicBytes(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyGetSecretBytes(options: KeyGetSecretBytesOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyGetSecretBytes(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keySignMessage(options: KeySignMessageOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = handleInvalidNullResponse(handleError(ariesAskarReactNative.keySignMessage(serializedOptions)))
    return new Uint8Array(buf)
  }

  public keyUnwrapKey(options: KeyUnwrapKeyOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = handleInvalidNullResponse(handleError(ariesAskarReactNative.keyUnwrapKey(serializedOptions)))

    return new LocalKeyHandle(handle)
  }

  public keyVerifySignature(options: KeyVerifySignatureOptions): boolean {
    const serializedOptions = serializeArguments(options)
    const result = handleError(ariesAskarReactNative.keyVerifySignature(serializedOptions))

    return !!result
  }

  public keyWrapKey(options: KeyWrapKeyOptions): EncryptedBuffer {
    const serializedOptions = serializeArguments(options)
    const ret = handleError(ariesAskarReactNative.keyWrapKey(serializedOptions))

    const { buffer, noncePos, tagPos } = handleInvalidNullResponse(ret)

    return new EncryptedBuffer({ tagPos, noncePos, buffer: new Uint8Array(buffer) })
  }

  public scanFree(options: ScanFreeOptions): void {
    const serializedOptions = serializeArguments(options)
    handleError(ariesAskarReactNative.scanFree(serializedOptions))
  }

  public async scanNext(options: ScanNextOptions) {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      handleError(ariesAskarReactNative.scanNext({ cb, ...serializedOptions }))
    )

    return EntryListHandle.fromHandle(handle)
  }

  public async scanStart(options: ScanStartOptions): Promise<ScanHandle> {
    const { category, storeHandle, limit, offset, profile, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number>((cb) =>
      handleError(
        ariesAskarReactNative.scanStart({
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
    return this.promisify((cb) => handleError(ariesAskarReactNative.sessionClose({ cb, ...serializedOptions })))
  }

  public async sessionCount(options: SessionCountOptions): Promise<number> {
    const serializedOptions = serializeArguments(options)
    const response = await this.promisifyWithResponse<number>((cb) =>
      handleError(ariesAskarReactNative.sessionCount({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }

  public async sessionFetch(options: SessionFetchOptions) {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      handleError(ariesAskarReactNative.sessionFetch({ cb, ...serializedOptions }))
    )

    return EntryListHandle.fromHandle(handle)
  }

  public async sessionFetchAll(options: SessionFetchAllOptions) {
    const { category, sessionHandle, forUpdate, limit, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      handleError(
        ariesAskarReactNative.sessionFetchAll({ cb, category, sessionHandle, forUpdate, limit: limit || -1, tagFilter })
      )
    )

    return EntryListHandle.fromHandle(handle)
  }

  public async sessionFetchAllKeys(options: SessionFetchAllKeysOptions) {
    const { sessionHandle, algorithm, forUpdate, limit, thumbprint, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      handleError(
        ariesAskarReactNative.sessionFetchAllKeys({
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
      handleError(ariesAskarReactNative.sessionFetchKey({ cb, ...serializedOptions }))
    )

    return KeyEntryListHandle.fromHandle(handle)
  }

  public sessionInsertKey(options: SessionInsertKeyOptions): Promise<void> {
    const { sessionHandle, name, localKeyHandle, expiryMs, metadata, tags } = serializeArguments(options)
    return this.promisify((cb) =>
      handleError(
        ariesAskarReactNative.sessionInsertKey({
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
      handleError(ariesAskarReactNative.sessionRemoveAll({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }

  public sessionRemoveKey(options: SessionRemoveKeyOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => handleError(ariesAskarReactNative.sessionRemoveKey({ cb, ...serializedOptions })))
  }

  public async sessionStart(options: SessionStartOptions): Promise<SessionHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number>((cb) =>
      handleError(ariesAskarReactNative.sessionStart({ cb, ...serializedOptions }))
    )

    return SessionHandle.fromHandle(handle)
  }

  public sessionUpdate(options: SessionUpdateOptions): Promise<void> {
    const { category, name, operation, sessionHandle, expiryMs, tags, value } = serializeArguments(options)
    return this.promisify((cb) =>
      handleError(
        ariesAskarReactNative.sessionUpdate({
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
    return this.promisify((cb) => handleError(ariesAskarReactNative.sessionUpdateKey({ cb, ...serializedOptions })))
  }

  public storeClose(options: StoreCloseOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => handleError(ariesAskarReactNative.storeClose({ cb, ...serializedOptions })))
  }

  public async storeCreateProfile(options: StoreCreateProfileOptions): Promise<string> {
    const serializedOptions = serializeArguments(options)
    const response = await this.promisifyWithResponse<string>((cb) =>
      handleError(ariesAskarReactNative.storeCreateProfile({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }

  public storeGenerateRawKey(options: StoreGenerateRawKeyOptions): string {
    const serializedOptions = serializeArguments(options)
    return handleInvalidNullResponse(handleError(ariesAskarReactNative.storeGenerateRawKey(serializedOptions)))
  }

  public async storeGetProfileName(options: StoreGetProfileNameOptions): Promise<string> {
    const serializedOptions = serializeArguments(options)
    const response = await this.promisifyWithResponse<string>((cb) =>
      handleError(ariesAskarReactNative.storeGetProfileName({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }

  public async storeOpen(options: StoreOpenOptions): Promise<StoreHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number>((cb) =>
      handleError(ariesAskarReactNative.storeOpen({ cb, ...serializedOptions }))
    )

    return StoreHandle.fromHandle(handle)
  }

  public async storeProvision(options: StoreProvisionOptions): Promise<StoreHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number>((cb) =>
      handleError(ariesAskarReactNative.storeProvision({ cb, ...serializedOptions }))
    )

    return StoreHandle.fromHandle(handle)
  }

  public storeRekey(options: StoreRekeyOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => handleError(ariesAskarReactNative.storeRekey({ cb, ...serializedOptions })))
  }

  public async storeRemove(options: StoreRemoveOptions): Promise<number> {
    const serializedOptions = serializeArguments(options)
    const response = await this.promisifyWithResponse<number>((cb) =>
      handleError(ariesAskarReactNative.storeRemove({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }

  public async storeRemoveProfile(options: StoreRemoveProfileOptions): Promise<number> {
    const serializedOptions = serializeArguments(options)
    const response = await this.promisifyWithResponse<number>((cb) =>
      handleError(ariesAskarReactNative.storeRemoveProfile({ cb, ...serializedOptions }))
    )

    return handleInvalidNullResponse(response)
  }
}
