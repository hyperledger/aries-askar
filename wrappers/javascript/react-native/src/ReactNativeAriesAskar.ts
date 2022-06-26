/* eslint-disable @typescript-eslint/ban-ts-comment */
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
  ScanNextOptions,
  ScanStartOptions,
  SecretBuffer,
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

import { EntryListHandle, StoreHandle, SessionHandle, ScanHandle } from 'aries-askar-shared'

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

  public bufferFree(options: BufferFreeOptions): void {
    throw new Error('Method not implemented. bufferFree')
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
    return ariesAskarReactNative.entryListGetValue(serializedOptions)
  }

  public keyAeadDecrypt(options: KeyAeadDecryptOptions): Uint8Array {
    throw new Error('Method not implemented. keyAeadDecrypt')
  }
  public keyAeadEncrypt(options: KeyAeadEncryptOptions): EncryptedBuffer {
    throw new Error('Method not implemented. keyAeadEncrypt')
  }
  public keyAeadGetPadding(options: KeyAeadGetPaddingOptions): number {
    throw new Error('Method not implemented. keyAeadGetPadding')
  }
  public keyAeadGetParams(options: KeyAeadGetParamsOptions): AeadParams {
    throw new Error('Method not implemented. keyAeadGetParams')
  }
  public keyAeadRandomNonce(options: KeyAeadRandomNonceOptions): Uint8Array {
    throw new Error('Method not implemented. keyAeadRandomNonce')
  }
  public keyConvert(options: KeyConvertOptions): LocalKeyHandle {
    throw new Error('Method not implemented. keyConvert')
  }
  public keyCryptoBox(options: KeyCryptoBoxOptions): Uint8Array {
    throw new Error('Method not implemented. keyCryptoBox')
  }
  public keyCryptoBoxOpen(options: KeyCryptoBoxOpenOptions): Uint8Array {
    throw new Error('Method not implemented. keyCryptoBoxOpen')
  }
  public keyCryptoBoxRandomNonce(): Uint8Array {
    throw new Error('Method not implemented. keyCryptoBoxRandomNonce')
  }
  public keyCryptoBoxSeal(options: KeyCryptoBoxSealOptions): Uint8Array {
    throw new Error('Method not implemented. keyCryptoBoxSeal')
  }
  public keyCryptoBoxSealOpen(options: KeyCryptoBoxSealOpenOptions): Uint8Array {
    throw new Error('Method not implemented. keyCryptoBoxSealOpen')
  }
  public keyDeriveEcdh1pu(options: KeyDeriveEcdh1puOptions): LocalKeyHandle {
    throw new Error('Method not implemented. keyDeriveEcdh1pu')
  }
  public keyDeriveEcdhEs(options: KeyDeriveEcdhEsOptions): LocalKeyHandle {
    throw new Error('Method not implemented. keyDeriveEcdhEs')
  }
  public keyEntryListCount(options: KeyEntryListCountOptions): number {
    throw new Error('Method not implemented. keyEntryListCount')
  }
  public keyEntryListFree(options: KeyEntryListFreeOptions): void {
    throw new Error('Method not implemented. keyEntryListFree')
  }
  public keyEntryListGetAlgorithm(options: KeyEntryListGetAlgorithmOptions): string {
    throw new Error('Method not implemented. keyEntryListGetAlgorithm')
  }
  public keyEntryListGetMetadata(options: KeyEntryListGetMetadataOptions): string {
    throw new Error('Method not implemented. keyEntryListGetMetadata')
  }
  public keyEntryListGetName(options: KeyEntryListGetNameOptions): string {
    throw new Error('Method not implemented. keyEntryListGetName')
  }
  public keyEntryListGetTags(options: KeyEntryListGetTagsOptions): string {
    throw new Error('Method not implemented. keyEntryListGetTags')
  }
  public keyEntryListLoadLocal(options: KeyEntryListLoadLocalOptions): LocalKeyHandle {
    throw new Error('Method not implemented. keyEntryListLoadLocal')
  }
  public keyFree(options: KeyFreeOptions): void {
    throw new Error('Method not implemented. keyFree')
  }
  public keyFromJwk(options: KeyFromJwkOptions): LocalKeyHandle {
    throw new Error('Method not implemented. keyFromJwk')
  }
  public keyFromKeyExchange(options: KeyFromKeyExchangeOptions): LocalKeyHandle {
    throw new Error('Method not implemented. keyFromKeyExchange')
  }
  public keyFromPublicBytes(options: KeyFromPublicBytesOptions): LocalKeyHandle {
    throw new Error('Method not implemented. keyFromPublicBytes')
  }
  public keyFromSecretBytes(options: KeyFromSecretBytesOptions): LocalKeyHandle {
    throw new Error('Method not implemented. keyFromSecretBytes')
  }
  public keyFromSeed(options: KeyFromSeedOptions): LocalKeyHandle {
    throw new Error('Method not implemented. keyFromSeed')
  }
  public keyGenerate(options: KeyGenerateOptions): LocalKeyHandle {
    throw new Error('Method not implemented. keyGenerate')
  }
  public keyGetAlgorithm(options: KeyGetAlgorithmOptions): string {
    throw new Error('Method not implemented. keyGetAlgorithm')
  }
  public keyGetEphemeral(options: KeyGetEphemeralOptions): number {
    throw new Error('Method not implemented. keyGetEphemeral')
  }
  public keyGetJwkPublic(options: KeyGetJwkPublicOptions): string {
    throw new Error('Method not implemented. keyGetJwkPublic')
  }
  public keyGetJwkSecret(options: KeyGetJwkSecretOptions): string {
    throw new Error('Method not implemented. keyGetJwkSecret')
  }
  public keyGetJwkThumbprint(options: KeyGetJwkThumbprintOptions): string {
    throw new Error('Method not implemented. keyGetJwkThumbprint')
  }
  public keyGetPublicBytes(options: KeyGetPublicBytesOptions): Uint8Array {
    throw new Error('Method not implemented. keyGetPublicBytes')
  }
  public keyGetSecretBytes(options: KeyGetSecretBytesOptions): Uint8Array {
    throw new Error('Method not implemented. keyGetSecretBytes')
  }
  public keySignMessage(options: KeySignMessageOptions): Uint8Array {
    throw new Error('Method not implemented. keySignMessage')
  }
  public keyUnwrapKey(options: KeyUnwrapKeyOptions): LocalKeyHandle {
    throw new Error('Method not implemented. keyUnwrapKey')
  }
  public keyVerifySignature(options: KeyVerifySignatureOptions): boolean {
    throw new Error('Method not implemented. keyVerifySignature')
  }
  public keyWrapKey(options: KeyWrapKeyOptions): EncryptedBuffer {
    throw new Error('Method not implemented. keyWrapKey')
  }

  public scanFree(options: ScanFreeOptions): void {
    const serializedOptions = serializeArguments(options)
    ariesAskarReactNative.scanFree(serializedOptions)
  }

  public async scanNext(options: ScanNextOptions): Promise<EntryListHandle> {
    const serializedOptions = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number, number>((cb) =>
      ariesAskarReactNative.scanNext({ cb, ...serializedOptions })
    )

    //  @ts-ignore
    return new EntryListHandle(handle)
  }

  public async scanStart(options: ScanStartOptions): Promise<ScanHandle> {
    const { category, storeHandle, limit, offset, profile, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number, number>((cb) =>
      ariesAskarReactNative.scanStart({
        cb,
        category,
        storeHandle,
        limit: limit || -1,
        offset: offset || -1,
        profile,
        tagFilter,
      })
    )

    //  @ts-ignore
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
    const handle = await this.promisifyWithResponse<number, number>((cb) =>
      ariesAskarReactNative.sessionFetch({ cb, ...serializedOptions })
    )

    //  @ts-ignore
    return new EntryListHandle(handle)
  }

  public async sessionFetchAll(options: SessionFetchAllOptions): Promise<EntryListHandle> {
    const { category, sessionHandle, forUpdate, limit, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number, number>((cb) =>
      ariesAskarReactNative.sessionFetchAll({ cb, category, sessionHandle, forUpdate, limit: limit || -1, tagFilter })
    )

    //  @ts-ignore
    return new EntryListHandle(handle)
  }

  public sessionFetchAllKeys(options: SessionFetchAllKeysOptions): Promise<KeyEntryListHandle> {
    throw new Error('Method not implemented. sessionFetchAllKeys')
  }
  public sessionFetchKey(options: SessionFetchKeyOptions): Promise<KeyEntryListHandle> {
    throw new Error('Method not implemented. sessionFetchKey')
  }

  public sessionInsertKey(options: SessionInsertKeyOptions): Promise<void> {
    const serializedOptions = serializeArguments(options)
    return this.promisify((cb) => ariesAskarReactNative.sessionInsertKey({ cb, ...serializedOptions }))
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
