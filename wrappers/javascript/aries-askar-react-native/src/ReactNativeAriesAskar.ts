import type {
  AriesAskar,
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
} from 'aries-askar-shared'

import {
  AeadParams,
  EncryptedBuffer,
  LocalKeyHandle,
  EntryListHandle,
  StoreHandle,
  SessionHandle,
  ScanHandle,
  KeyEntryListHandle,
} from 'aries-askar-shared'

import { ariesAskarReactNative } from './library'
import { serializeArguments } from './utils'

export class ReactNativeAriesAskar implements AriesAskar {
  private promisify = (method: (cb: (err: number) => void) => void): Promise<void> => {
    return new Promise((resolve, reject) => {
      const _cb = (err: number) => {
        if (err !== 0) reject(this.getCurrentError())
        resolve()
      }

      method(_cb)
    })
  }

  private promisifyWithResponse = <Return, Response = string>(
    method: (cb: (err: number, response: Response) => void) => void
  ): Promise<Return> => {
    return new Promise((resolve, reject) => {
      const _cb = (err: number, response: Response) => {
        if (err !== 0) reject(this.getCurrentError())

        switch (typeof response) {
          case 'string':
            resolve(response as unknown as Return)
            break
          default:
            resolve(response as unknown as Return)
        }
      }
      method(_cb)
    })
  }

  public version(): string {
    return ariesAskarReactNative.version({})
  }

  public getCurrentError(): string {
    return ariesAskarReactNative.getCurrentError({})
  }

  public clearCustomLogger(): void {
    throw new Error('Method not implemented. clearCustomLogger')
  }

  public setCustomLogger(options: SetCustomLoggerOptions): void {
    throw new Error('Method not implemented. setCustomLogger')
  }

  public setDefaultLogger(): void {
    throw new Error('Method not implemented. setDefaultLogger')
  }

  public setMaxLogLevel(options: SetMaxLogLevelOptions): void {
    throw new Error('Method not implemented. setMaxLogLevel')
  }

  public entryListCount(options: EntryListCountOptions): number {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.entryListCount(serializedOptions)
  }

  public entryListFree(options: EntryListFreeOptions): void {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.entryListFree(serializedOptions)
  }

  public entryListGetCategory(options: EntryListGetCategoryOptions): string {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.entryListGetCategory(serializedOptions)
  }

  public entryListGetName(options: EntryListGetNameOptions): string {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.entryListGetName(serializedOptions)
  }

  public entryListGetTags(options: EntryListGetTagsOptions): string {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.entryListGetTags(serializedOptions)
  }

  public entryListGetValue(options: EntryListGetValueOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = ariesAskarReactNative.entryListGetValue(serializedOptions)
    return new Uint8Array(buf)
  }

  public keyAeadDecrypt(options: KeyAeadDecryptOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = ariesAskarReactNative.keyAeadDecrypt(serializedOptions)
    return new Uint8Array(buf)
  }

  public keyAeadEncrypt(options: KeyAeadEncryptOptions): EncryptedBuffer {
    const serializedOptions = serializeArguments(options)
    const { buffer, noncePos, tagPos } = ariesAskarReactNative.keyAeadEncrypt(serializedOptions)

    return new EncryptedBuffer({ tagPos, noncePos, buffer: new Uint8Array(buffer) })
  }

  public keyAeadGetPadding(options: KeyAeadGetPaddingOptions): number {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.keyAeadGetPadding(serializedOptions)
  }

  public keyAeadGetParams(options: KeyAeadGetParamsOptions): AeadParams {
    const serializedOptions = serializeArguments(options)
    const { tagLength, nonceLength } = ariesAskarReactNative.keyAeadGetParams(serializedOptions)

    return new AeadParams({ nonceLength, tagLength })
  }

  public keyAeadRandomNonce(options: KeyAeadRandomNonceOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = ariesAskarReactNative.keyAeadRandomNonce(serializedOptions)
    return new Uint8Array(buf)
  }

  public keyConvert(options: KeyConvertOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = ariesAskarReactNative.keyConvert(serializedOptions)

    return new LocalKeyHandle(handle)
  }

  public keyCryptoBox(options: KeyCryptoBoxOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = ariesAskarReactNative.keyCryptoBox(serializedOptions)
    return new Uint8Array(buf)
  }

  public keyCryptoBoxOpen(options: KeyCryptoBoxOpenOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = ariesAskarReactNative.keyCryptoBoxOpen(serializedOptions)
    return new Uint8Array(buf)
  }

  public keyCryptoBoxRandomNonce(): Uint8Array {
    const buf = ariesAskarReactNative.keyCryptoBoxRandomNonce({})
    return new Uint8Array(buf)
  }

  public keyCryptoBoxSeal(options: KeyCryptoBoxSealOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = ariesAskarReactNative.keyCryptoBoxSeal(serializedOptions)
    return new Uint8Array(buf)
  }

  public keyCryptoBoxSealOpen(options: KeyCryptoBoxSealOpenOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = ariesAskarReactNative.keyCryptoBoxSealOpen(serializedOptions)
    return new Uint8Array(buf)
  }

  public keyDeriveEcdh1pu(options: KeyDeriveEcdh1puOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = ariesAskarReactNative.keyDeriveEcdh1pu(serializedOptions)
    return new LocalKeyHandle(handle)
  }

  public keyDeriveEcdhEs(options: KeyDeriveEcdhEsOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = ariesAskarReactNative.keyDeriveEcdhEs(serializedOptions)
    return new LocalKeyHandle(handle)
  }

  public keyEntryListCount(options: KeyEntryListCountOptions): number {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.keyEntryListCount(serializedOptions)
  }

  public keyEntryListFree(options: KeyEntryListFreeOptions): void {
    const serializedOptions = serializeArguments(options)
    ariesAskarReactNative.keyEntryListFree(serializedOptions)
  }

  public keyEntryListGetAlgorithm(options: KeyEntryListGetAlgorithmOptions): string {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.keyEntryListGetAlgorithm(serializedOptions)
  }

  public keyEntryListGetMetadata(options: KeyEntryListGetMetadataOptions): string {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.keyEntryListGetMetadata(serializedOptions)
  }

  public keyEntryListGetName(options: KeyEntryListGetNameOptions): string {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.keyEntryListGetName(serializedOptions)
  }

  public keyEntryListGetTags(options: KeyEntryListGetTagsOptions): string {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.keyEntryListGetTags(serializedOptions)
  }

  public keyEntryListLoadLocal(options: KeyEntryListLoadLocalOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = ariesAskarReactNative.keyEntryListLoadLocal(serializedOptions)

    return new LocalKeyHandle(handle)
  }

  public keyFree(options: KeyFreeOptions): void {
    const serializedOptions = serializeArguments(options)
    ariesAskarReactNative.keyFree(serializedOptions)
  }

  public keyFromJwk(options: KeyFromJwkOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = ariesAskarReactNative.keyFromJwk(serializedOptions)

    return new LocalKeyHandle(handle)
  }

  public keyFromKeyExchange(options: KeyFromKeyExchangeOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = ariesAskarReactNative.keyFromKeyExchange(serializedOptions)

    return new LocalKeyHandle(handle)
  }

  public keyFromPublicBytes(options: KeyFromPublicBytesOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = ariesAskarReactNative.keyFromPublicBytes(serializedOptions)

    return new LocalKeyHandle(handle)
  }

  public keyFromSecretBytes(options: KeyFromSecretBytesOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = ariesAskarReactNative.keyFromSecretBytes(serializedOptions)

    return new LocalKeyHandle(handle)
  }

  public keyFromSeed(options: KeyFromSeedOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = ariesAskarReactNative.keyFromSeed(serializedOptions)

    return new LocalKeyHandle(handle)
  }

  public keyGenerate(options: KeyGenerateOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = ariesAskarReactNative.keyGenerate(serializedOptions)

    return new LocalKeyHandle(handle)
  }

  public keyGetAlgorithm(options: KeyGetAlgorithmOptions): string {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.keyGetAlgorithm(serializedOptions)
  }

  public keyGetEphemeral(options: KeyGetEphemeralOptions): number {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.keyGetEphemeral(serializedOptions)
  }

  public keyGetJwkPublic(options: KeyGetJwkPublicOptions): string {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.keyGetJwkPublic(serializedOptions)
  }

  public keyGetJwkSecret(options: KeyGetJwkSecretOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = ariesAskarReactNative.keyGetJwkSecret(serializedOptions)
    return new Uint8Array(buf)
  }

  public keyGetJwkThumbprint(options: KeyGetJwkThumbprintOptions): string {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.keyGetJwkThumbprint(serializedOptions)
  }

  public keyGetPublicBytes(options: KeyGetPublicBytesOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = ariesAskarReactNative.keyGetPublicBytes(serializedOptions)
    return new Uint8Array(buf)
  }

  public keyGetSecretBytes(options: KeyGetSecretBytesOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = ariesAskarReactNative.keyGetSecretBytes(serializedOptions)
    return new Uint8Array(buf)
  }

  public keySignMessage(options: KeySignMessageOptions): Uint8Array {
    const serializedOptions = serializeArguments(options)
    const buf = ariesAskarReactNative.keySignMessage(serializedOptions)
    return new Uint8Array(buf)
  }

  public keyUnwrapKey(options: KeyUnwrapKeyOptions): LocalKeyHandle {
    const serializedOptions = serializeArguments(options)
    const handle = ariesAskarReactNative.keyUnwrapKey(serializedOptions)

    return new LocalKeyHandle(handle)
  }

  public keyVerifySignature(options: KeyVerifySignatureOptions): boolean {
    const serializedOptions = serializeArguments(options)
    const result = ariesAskarReactNative.keyVerifySignature(serializedOptions)

    return !!result
  }

  public keyWrapKey(options: KeyWrapKeyOptions): EncryptedBuffer {
    const serializedOptions = serializeArguments(options)
    const { buffer, noncePos, tagPos } = ariesAskarReactNative.keyWrapKey(serializedOptions)

    return new EncryptedBuffer({ tagPos, noncePos, buffer: new Uint8Array(buffer) })
  }

  public scanFree(options: ScanFreeOptions): void {
    const serializedOptions = serializeArguments(options)
    ariesAskarReactNative.scanFree(serializedOptions)
  }

  public async scanNext(options: ScanNextOptions): Promise<EntryListHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      ariesAskarReactNative.scanNext({ cb, ...serializedOptions })
    )

    return new EntryListHandle(handle)
  }

  public async scanStart(options: ScanStartOptions): Promise<ScanHandle> {
    const { category, storeHandle, limit, offset, profile, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number, number>((cb) =>
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

    return new ScanHandle(handle)
  }

  public sessionClose(options: SessionCloseOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => ariesAskarReactNative.sessionClose({ cb, ...serializedOptions }))
  }

  public sessionCount(options: SessionCountOptions): Promise<number> {
    const serializedOptions = serializeArguments(options)
    return this.promisifyWithResponse<number, number>((cb) =>
      ariesAskarReactNative.sessionCount({ cb, ...serializedOptions })
    )
  }

  public async sessionFetch(options: SessionFetchOptions): Promise<EntryListHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      ariesAskarReactNative.sessionFetch({ cb, ...serializedOptions })
    )

    return new EntryListHandle(handle)
  }

  public async sessionFetchAll(options: SessionFetchAllOptions): Promise<EntryListHandle> {
    const { category, sessionHandle, forUpdate, limit, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      ariesAskarReactNative.sessionFetchAll({ cb, category, sessionHandle, forUpdate, limit: limit || -1, tagFilter })
    )

    return new EntryListHandle(handle)
  }

  public async sessionFetchAllKeys(options: SessionFetchAllKeysOptions): Promise<KeyEntryListHandle> {
    const { sessionHandle, algorithm, forUpdate, limit, thumbprint, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
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

    return new KeyEntryListHandle(handle)
  }
  public async sessionFetchKey(options: SessionFetchKeyOptions): Promise<KeyEntryListHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<string>((cb) =>
      ariesAskarReactNative.sessionFetchKey({ cb, ...serializedOptions })
    )

    return new KeyEntryListHandle(handle)
  }

  public sessionInsertKey(options: SessionInsertKeyOptions): Promise<void> {
    const { sessionHandle, name, localKeyHandle, expiryMs, metadata, tags } = serializeArguments(options)
    return this.promisify((cb) =>
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
  }

  public sessionRemoveAll(options: SessionRemoveAllOptions): Promise<number> {
    const serializedOptions = serializeArguments(options)
    return this.promisifyWithResponse<number, number>((cb) =>
      ariesAskarReactNative.sessionRemoveAll({ cb, ...serializedOptions })
    )
  }

  public sessionRemoveKey(options: SessionRemoveKeyOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => ariesAskarReactNative.sessionRemoveKey({ cb, ...serializedOptions }))
  }

  public async sessionStart(options: SessionStartOptions): Promise<SessionHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number, number>((cb) =>
      ariesAskarReactNative.sessionStart({ cb, ...serializedOptions })
    )

    return new SessionHandle(handle)
  }

  public sessionUpdate(options: SessionUpdateOptions): Promise<void> {
    const { category, name, operation, sessionHandle, expiryMs, tags, value } = serializeArguments(options)
    return this.promisify((cb) =>
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
  }

  public sessionUpdateKey(options: SessionUpdateKeyOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisifyWithResponse((cb) => ariesAskarReactNative.sessionUpdateKey({ cb, ...serializedOptions }))
  }

  public storeClose(options: StoreCloseOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => ariesAskarReactNative.storeClose({ cb, ...serializedOptions }))
  }

  public storeCreateProfile(options: StoreCreateProfileOptions): Promise<string> {
    const serializedOptions = serializeArguments(options)
    return this.promisifyWithResponse<string>((cb) =>
      ariesAskarReactNative.storeCreateProfile({ cb, ...serializedOptions })
    )
  }

  public storeGenerateRawKey(options: StoreGenerateRawKeyOptions): string {
    const serializedOptions = serializeArguments(options)
    return ariesAskarReactNative.storeGenerateRawKey(serializedOptions)
  }

  public storeGetProfileName(options: StoreGetProfileNameOptions): Promise<string> {
    const serializedOptions = serializeArguments(options)
    return this.promisifyWithResponse<string>((cb) =>
      ariesAskarReactNative.storeGetProfileName({ cb, ...serializedOptions })
    )
  }

  public storeOpen(options: StoreOpenOptions): Promise<StoreHandle> {
    const serializedOptions = serializeArguments(options)
    return this.promisifyWithResponse<StoreHandle, number>((cb) =>
      ariesAskarReactNative.storeOpen({ cb, ...serializedOptions })
    )
  }

  public async storeProvision(options: StoreProvisionOptions): Promise<StoreHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number, number>((cb) =>
      ariesAskarReactNative.storeProvision({ cb, ...serializedOptions })
    )

    return new StoreHandle(handle)
  }

  public storeRekey(options: StoreRekeyOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => ariesAskarReactNative.storeRekey({ cb, ...serializedOptions }))
  }

  public storeRemove(options: StoreRemoveOptions): Promise<number> {
    const serializedOptions = serializeArguments(options)
    return this.promisifyWithResponse<number>((cb) => ariesAskarReactNative.storeRemove({ cb, ...serializedOptions }))
  }

  public storeRemoveProfile(options: StoreRemoveProfileOptions): Promise<number> {
    const serializedOptions = serializeArguments(options)
    return this.promisifyWithResponse<number>((cb) =>
      ariesAskarReactNative.storeRemoveProfile({ cb, ...serializedOptions })
    )
  }
}
