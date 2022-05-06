/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/ban-ts-comment */
/* eslint-disable no-console */
import type {
  AeadParamsType,
  EncryptedBufferType,
  NativeCallback,
  NativeCallbackWithResponse,
  NativeLogCallback,
  SecretBufferType,
} from './utils'
import type {
  AriesAskar,
  BufferFreeOptions,
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
  ScanFreeOptions,
  ScanNextOptions,
  ScanStartOptions,
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

import { EncryptedBuffer, SecretBuffer, AeadParams, LocalKeyHandle } from 'aries-askar-shared'

import { handleError } from './error'
import { nativeAriesAskar } from './lib'
import {
  serializeArguments,
  allocateAeadParams,
  allocateLocalKeyHandle,
  allocateEncryptedBuffer,
  allocateSecretBuffer,
  allocateIntBuffer,
  toNativeLogCallback,
  allocateStringBuffer,
  deallocateCallbackBuffer,
  toNativeCallback,
  toNativeCallbackWithResponse,
  ByteBufferStruct,
} from './utils'

export class NodeJSAriesAskar implements AriesAskar {
  private promisify = async (method: (nativeCallbackPtr: Buffer, id: number) => void): Promise<void> => {
    return new Promise((resolve, reject) => {
      const cb: NativeCallback = (id, _) => {
        deallocateCallbackBuffer(id)

        try {
          handleError()
        } catch (e) {
          reject(e)
        }

        resolve()
      }
      const { nativeCallback, id } = toNativeCallback(cb)
      method(nativeCallback, +id)
    })
  }

  private promisifyWithResponse = async <T, R = string>(
    method: (nativeCallbackWithResponsePtr: Buffer, id: number) => void,
    isStream = false
  ): Promise<T> => {
    return new Promise((resolve, reject) => {
      const cb: NativeCallbackWithResponse<R> = (id, _, response) => {
        deallocateCallbackBuffer(id)

        try {
          handleError()
        } catch (e) {
          reject(e)
        }

        if (typeof response === 'string') {
          console.log('resolved with string')
          try {
            //this is required to add array brackets, and commas, to an invalid json object that
            // should be a list
            const mappedResponse = isStream ? '[' + response.replace(/\n/g, ',') + ']' : response
            resolve(JSON.parse(mappedResponse) as T)
          } catch (error) {
            reject(error)
          }
        } else if (typeof response === 'number') {
          console.log('resolved with int')
          resolve('TODO' as unknown as T)
        }
      }
      const { nativeCallback, id } = toNativeCallbackWithResponse(cb)
      method(nativeCallback, +id)
    })
  }

  public version(): string {
    return nativeAriesAskar.askar_version()
  }

  public getCurrentError(): string {
    const error = allocateStringBuffer()
    nativeAriesAskar.askar_get_current_error(error)
    handleError()
    return error.deref() as string
  }

  public bufferFree(options: BufferFreeOptions): void {
    const { secretBuffer } = serializeArguments(options)
    nativeAriesAskar.askar_buffer_free(secretBuffer)
    handleError()
  }

  public clearCustomLogger(): void {
    nativeAriesAskar.askar_clear_custom_logger()
    handleError()
  }

  // TODO: the id has to be deallocated when its done, but how?
  public setCustomLogger({ logLevel, flush = false, enabled = false }: SetCustomLoggerOptions): void {
    const loggie: NativeLogCallback = (context, level, target, message, modulePath, file, line) => {
      // console.table({ context, level, target, message, modulePath, file, line })
      console.log('----------------------------')
      console.log(`${file}:${line}`)
      console.log(message)
      console.log('----------------------------')
    }
    const { id, nativeCallback } = toNativeLogCallback(loggie)

    // TODO: flush and enabled are just guessed
    nativeAriesAskar.askar_set_custom_logger(0, nativeCallback, +enabled, +flush, logLevel)
    handleError()
    deallocateCallbackBuffer(+id)
  }

  public setDefaultLogger(): void {
    nativeAriesAskar.askar_set_default_logger()
    handleError()
  }

  public setMaxLogLevel(options: SetMaxLogLevelOptions): void {
    const { logLevel } = serializeArguments(options)

    nativeAriesAskar.askar_set_max_log_level(logLevel)
    handleError()
  }

  public entryListCount(options: EntryListCountOptions): number {
    const { entryListHandle } = serializeArguments(options)
    const ret = allocateIntBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_entry_list_count(entryListHandle, ret)
    handleError()

    return ret.deref() as number
  }

  public entryListFree(options: EntryListFreeOptions): void {
    const { entryListHandle } = serializeArguments(options)

    // @ts-ignore
    nativeAriesAskar.askar_entry_list_free(entryListHandle)
    handleError()
  }

  public entryListGetCategory(options: EntryListGetCategoryOptions): string {
    const { entryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_entry_list_get_category(entryListHandle, index, ret)
    handleError()

    return ret.deref() as string
  }

  public entryListGetName(options: EntryListGetNameOptions): string {
    const { entryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_entry_list_get_name(entryListHandle, index, ret)
    handleError()

    return ret.deref() as string
  }

  public entryListGetTags(options: EntryListGetTagsOptions): string {
    const { entryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_entry_list_get_tags(entryListHandle, index, ret)
    handleError()

    return ret.deref() as string
  }

  public entryListGetValue(options: EntryListGetValueOptions): string {
    const { entryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_entry_list_get_value(entryListHandle, index, ret)
    handleError()

    return ret.deref() as string
  }

  public keyAeadDecrypt(options: KeyAeadDecryptOptions): SecretBuffer {
    const { aad, cipherText, localKeyHandle, nonce, tag } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_aead_decrypt(localKeyHandle, cipherText, nonce, tag, aad, ret)
    handleError()

    const secretBuffer = ret.deref() as SecretBufferType
    return new SecretBuffer(secretBuffer)
  }

  public keyAeadEncrypt(options: KeyAeadEncryptOptions): EncryptedBuffer {
    const { localKeyHandle, aad, nonce, message } = serializeArguments(options)
    const ret = allocateEncryptedBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_aead_encrypt(localKeyHandle, message, nonce, aad, ret)
    handleError()

    const encryptedBuffer = ret.deref() as EncryptedBufferType
    return new EncryptedBuffer(encryptedBuffer)
  }

  public keyAeadGetPadding(options: KeyAeadGetPaddingOptions): number {
    const { localKeyHandle, msgLen } = serializeArguments(options)
    const ret = allocateIntBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_aead_get_padding(localKeyHandle, msgLen, ret)
    handleError()

    return ret.deref() as number
  }

  public keyAeadGetParams(options: KeyAeadGetParamsOptions): AeadParams {
    const { localKeyHandle } = serializeArguments(options)
    const ret = allocateAeadParams()

    // @ts-ignore
    nativeAriesAskar.askar_key_aead_get_params(localKeyHandle, ret)
    handleError()

    const aeadParams = ret.deref() as AeadParamsType
    return new AeadParams(aeadParams)
  }

  public keyAeadRandomNonce(options: KeyAeadRandomNonceOptions): SecretBuffer {
    const { localKeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_aead_random_nonce(localKeyHandle, ret)
    handleError()

    const secretBuffer = ret.deref() as SecretBufferType
    return new SecretBuffer(secretBuffer)
  }

  public keyConvert(options: KeyConvertOptions): LocalKeyHandle {
    const { localKeyHandle, alg } = serializeArguments(options)
    const ret = allocateLocalKeyHandle()

    // @ts-ignore
    nativeAriesAskar.askar_key_convert(localKeyHandle, alg, ret)
    handleError()

    // TODO: use the output
    // const outLocalKeyHandle = ret.deref() as LocalKeyHandleType
    return new LocalKeyHandle()
  }

  public keyCryptoBox(options: KeyCryptoBoxOptions): SecretBuffer {
    const { nonce, message, recipKey, senderKey } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_crypto_box(recipKey, senderKey, message, nonce, ret)
    handleError()

    const secretBuffer = ret.deref() as SecretBufferType
    return new SecretBuffer(secretBuffer)
  }

  public keyCryptoBoxOpen(options: KeyCryptoBoxOpenOptions): SecretBuffer {
    const { nonce, message, senderKey, recipKey } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_crypto_box_open(recipKey, senderKey, message, nonce, ret)
    handleError()

    const secretBuffer = ret.deref() as SecretBufferType
    return new SecretBuffer(secretBuffer)
  }

  public keyCryptoBoxRandomNonce(): SecretBuffer {
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_crypto_box_random_nonce(ret)
    handleError()

    const secretBuffer = ret.deref() as SecretBufferType
    return new SecretBuffer(secretBuffer)
  }

  public keyCryptoBoxSeal(options: KeyCryptoBoxSealOptions): SecretBuffer {
    const { message, localKeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_crypto_box_seal(localKeyHandle, message, ret)

    const secretBuffer = ret.deref() as SecretBufferType
    return new SecretBuffer(secretBuffer)
  }

  public keyCryptoBoxSealOpen(options: KeyCryptoBoxSealOpenOptions): SecretBuffer {
    const { ciphertext, localKeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_crypto_box_seal_open(localKeyHandle, ciphertext, ret)

    const secretBuffer = ret.deref() as SecretBufferType
    return new SecretBuffer(secretBuffer)
  }

  public keyDeriveEcdh1pu(options: KeyDeriveEcdh1puOptions): LocalKeyHandle {
    const { senderKey, recipKey, alg, algId, apu, apv, ccTag, ephemKey, receive } = serializeArguments(options)
    const ret = allocateLocalKeyHandle()

    // @ts-ignore
    nativeAriesAskar.askar_key_derive_ecdh_1pu(alg, ephemKey, senderKey, recipKey, algId, apu, apv, ccTag, receive, ret)

    // TODO: use
    // const localKeyHandle = ret.deref() as  LocalKeyHandleType
    return new LocalKeyHandle()
  }

  public keyDeriveEcdhEs(options: KeyDeriveEcdhEsOptions): LocalKeyHandle {
    const { receive, apv, apu, algId, recipKey, ephemKey, alg } = serializeArguments(options)
    const ret = allocateLocalKeyHandle()

    // @ts-ignore
    nativeAriesAskar.askar_key_derive_ecdh_es(alg, ephemKey, recipKey, algId, apu, apv, receive, ret)

    // TODO: use
    // const localKeyHandle = ret.deref() as  LocalKeyHandleType
    return new LocalKeyHandle()
  }

  public keyEntryListCount(options: KeyEntryListCountOptions): number {
    const { keyEntryListHandle } = serializeArguments(options)
    const ret = allocateIntBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_count(keyEntryListHandle, ret)
    handleError()

    return ret.deref() as number
  }

  public keyEntryListFree(options: KeyEntryListFreeOptions): void {
    const { keyEntryListHandle } = serializeArguments(options)

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_free(keyEntryListHandle)
  }

  public keyEntryListGetAlgorithm(options: KeyEntryListGetAlgorithmOptions): string {
    const { keyEntryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_get_algorithm(keyEntryListHandle, index, ret)
    return ret.deref() as string
  }

  public keyEntryListGetMetadata(options: KeyEntryListGetMetadataOptions): string {
    const { keyEntryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_get_metadata(keyEntryListHandle, index, ret)
    return ret.deref() as string
  }

  public keyEntryListGetName(options: KeyEntryListGetNameOptions): string {
    const { keyEntryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_get_name(keyEntryListHandle, index, ret)
    return ret.deref() as string
  }

  public keyEntryListGetTags(options: KeyEntryListGetTagsOptions): string {
    const { keyEntryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_get_tags(keyEntryListHandle, index, ret)
    return ret.deref() as string
  }

  public keyEntryListLoadLocal(options: KeyEntryListLoadLocalOptions): string {
    const { index, keyEntryListHandle } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_load_local(keyEntryListHandle, index, ret)
    return ret.deref() as string
  }

  public keyFree(options: KeyFreeOptions): void {
    const { keyEntryListHandle } = serializeArguments(options)

    // @ts-ignore
    nativeAriesAskar.askar_key_free(keyEntryListHandle)
  }

  public keyFromJwk(options: KeyFromJwkOptions): LocalKeyHandle {
    const { jwk } = serializeArguments(options)
    const ret = allocateLocalKeyHandle()

    // @ts-ignore
    nativeAriesAskar.askar_key_from_jwk(jwk, ret)

    // TODO: use
    // const localKeyHandle = ret.deref() as LocalKeyHandleType
    return new LocalKeyHandle()
  }

  public keyFromKeyExchange(options: KeyFromKeyExchangeOptions): LocalKeyHandle {
    const { alg, pkHandle, skHandle } = serializeArguments(options)
    const ret = allocateLocalKeyHandle()

    // @ts-ignore
    nativeAriesAskar.askar_key_from_key_exchange(alg, skHandle, pkHandle, ret)

    // TODO: use
    // const localKeyHandle = ret.deref() as LocalKeyHandleType
    return new LocalKeyHandle()
  }

  public keyFromPublicBytes(options: KeyFromPublicBytesOptions): LocalKeyHandle {
    const { publicKey, alg } = serializeArguments(options)
    const ret = allocateLocalKeyHandle()

    // @ts-ignore
    nativeAriesAskar.askar_key_from_public_bytes(alg, publicKey, ret)

    // TODO: use
    // const localKeyHandle = ret.deref() as LocalKeyHandleType
    return new LocalKeyHandle()
  }

  public keyFromSecretBytes(options: KeyFromSecretBytesOptions): LocalKeyHandle {
    const { secretKey, alg } = serializeArguments(options)
    const ret = allocateLocalKeyHandle()

    // @ts-ignore
    nativeAriesAskar.askar_key_from_secret_bytes(alg, secretKey, ret)

    // TODO: use
    // const localKeyHandle = ret.deref() as LocalKeyHandleType
    return new LocalKeyHandle()
  }

  public keyFromSeed(options: KeyFromSeedOptions): LocalKeyHandle {
    const { alg, method, seed } = serializeArguments(options)
    // @ts-ignore
    const ret = allocateLocalKeyHandle()

    // @ts-ignore
    nativeAriesAskar.askar_key_from_seed(alg, seed, method, ret)
    const base = ret.deref().deref().inner.deref()
    console.log('SEC: ', base.secret.toJSON())
    console.log('CMP: ', base.public.CompressedEdwardsY.toJSON())
    console.log('E X: ', base.public.EdwardsPoint.X.toJSON())
    console.log('E Y: ', base.public.EdwardsPoint.Y.toJSON())
    console.log('E Z: ', base.public.EdwardsPoint.Z.toJSON())
    console.log('E T: ', base.public.EdwardsPoint.T.toJSON())

    // TODO: use
    // const localKeyHandle = ret.deref() as LocalKeyHandleType
    return new LocalKeyHandle({ ephemeral: true, inner: 'foo' })
  }

  public keyGenerate(options: KeyGenerateOptions): LocalKeyHandle {
    const { alg, ephemeral } = serializeArguments(options)
    const ret = allocateLocalKeyHandle()

    // @ts-ignore
    nativeAriesAskar.askar_key_generate(alg, ephemeral, ret)

    // TODO: use
    // const localKeyHandle = ret.deref()
    return new LocalKeyHandle({ ephemeral: true, inner: 0 })
  }

  public keyGetAlgorithm(options: KeyGetAlgorithmOptions): string {
    const { localkeyHandle } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_algorithm(localkeyHandle, ret)
    return ret.deref() as string
  }

  public keyGetEphemeral(options: KeyGetEphemeralOptions): number {
    const { localkeyHandle } = serializeArguments(options)
    const ret = allocateIntBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_ephemeral(localkeyHandle, ret)
    return ret.deref() as number
  }

  public keyGetJwkPublic(options: KeyGetJwkPublicOptions): string {
    const { localkeyHandle } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_jwk_public(localkeyHandle, ret)
    return ret.deref() as string
  }

  public keyGetJwkSecret(options: KeyGetJwkSecretOptions): SecretBuffer {
    const { localkeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_jwk_secret(localkeyHandle, ret)
    const secretBuffer = ret.deref() as SecretBufferType
    return new SecretBuffer(secretBuffer)
  }

  public keyGetJwkThumbprint(options: KeyGetJwkThumbprintOptions): string {
    const { localkeyHandle } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_jwk_thumbprint(localkeyHandle, ret)
    return ret.deref() as string
  }

  public keyGetPublicBytes(options: KeyGetPublicBytesOptions): SecretBuffer {
    const { localkeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_public_bytes(localkeyHandle, ret)

    const secretBuffer = ret.deref() as SecretBufferType
    return new SecretBuffer(secretBuffer)
  }

  public keyGetSecretBytes(options: KeyGetSecretBytesOptions): SecretBuffer {
    const { localkeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_secret_bytes(localkeyHandle, ret)

    const secretBuffer = ret.deref() as SecretBufferType
    return new SecretBuffer(secretBuffer)
  }

  public keySignMessage(options: KeySignMessageOptions): SecretBuffer {
    const { localkeyHandle, message, sigType } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_sign_message(localkeyHandle, message, sigType, ret)

    const secretBuffer = ret.deref() as SecretBufferType
    return new SecretBuffer(secretBuffer)
  }

  public keyUnwrapKey(options: KeyUnwrapKeyOptions): LocalKeyHandle {
    const { localkeyHandle, alg, ciphertext, nonce, tag } = serializeArguments(options)
    const ret = allocateLocalKeyHandle()

    // @ts-ignore
    nativeAriesAskar.askar_key_unwrap_key(localkeyHandle, alg, ciphertext, nonce, tag, ret)

    // const outLocalKeyHandle = ret.deref() as LocalKeyHandleType
    return new LocalKeyHandle()
  }

  public keyVerifySignature(options: KeyVerifySignatureOptions): number {
    const { localkeyHandle, sigType, message, signature } = serializeArguments(options)
    const ret = allocateIntBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_verify_signature(localkeyHandle, message, signature, sigType, ret)

    return ret.deref() as number
  }

  public keyWrapKey(options: KeyWrapKeyOptions): EncryptedBuffer {
    const { localkeyHandle, nonce, other } = serializeArguments(options)
    const ret = allocateEncryptedBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_wrap_key(localkeyHandle, other, nonce, ret)
    handleError()

    const encryptedBuffer = ret.deref() as EncryptedBufferType
    return new EncryptedBuffer(encryptedBuffer)
  }

  public scanFree(options: ScanFreeOptions): void {
    const { scanHandle } = serializeArguments(options)

    nativeAriesAskar.askar_scan_free(scanHandle)
    handleError()
  }

  public scanNext(options: ScanNextOptions): Promise<EntryListHandle> {
    const { scanHandle } = serializeArguments(options)

    return this.promisifyWithResponse<EntryListHandle>((cb, cbId) =>
      nativeAriesAskar.askar_scan_next(scanHandle, cb, cbId)
    )
  }

  public async scanStart(options: ScanStartOptions): Promise<void> {
    const { category, limit, offset, profile, storeHandle, tagFilter } = serializeArguments(options)
    await this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_scan_start(storeHandle, profile, category, tagFilter, offset, limit, cb, cbId)
    )
  }

  public sessionClose(options: SessionCloseOptions): Promise<void> {
    const { commit, sessionHandle } = serializeArguments(options)

    return this.promisify((cb, cbId) => nativeAriesAskar.askar_session_close(sessionHandle, commit, cb, cbId))
  }

  public sessionCount(options: SessionCountOptions): Promise<number> {
    const { sessionHandle, tagFilter, category } = serializeArguments(options)
    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_session_count(sessionHandle, category, tagFilter, cb, cbId)
    )
  }

  public sessionFetch(options: SessionFetchOptions): Promise<EntryListHandle> {
    const { name, category, sessionHandle, forUpdate } = serializeArguments(options)
    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_session_fetch(sessionHandle, category, name, forUpdate, cb, cbId)
    )
  }

  public sessionFetchAll(options: SessionFetchAllOptions): Promise<EntryListHandle> {
    const { forUpdate, sessionHandle, tagFilter, limit, catgory } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_session_fetch_all(sessionHandle, catgory, tagFilter, limit, forUpdate, cb, cbId)
    )
  }

  public sessionFetchAllKeys(options: SessionFetchAllKeysOptions): Promise<KeyEntryListHandle> {
    const { forUpdate, limit, tagFilter, sessionHandle, alg, thumbprint } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_session_fetch_all_keys(
        sessionHandle,
        alg,
        thumbprint,
        tagFilter,
        limit,
        forUpdate,
        cb,
        cbId
      )
    )
  }

  public sessionFetchKey(options: SessionFetchKeyOptions): Promise<KeyEntryListHandle> {
    const { forUpdate, sessionHandle, name } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_session_fetch_key(sessionHandle, name, forUpdate, cb, cbId)
    )
  }

  public sessionInsertKey(options: SessionInsertKeyOptions): Promise<void> {
    const { name, sessionHandle, expiryMs, localKeyHandle, metadata, tags } = serializeArguments(options)

    return this.promisify((cb, cbId) =>
      // @ts-ignore
      nativeAriesAskar.askar_session_insert_key(sessionHandle, localKeyHandle, name, metadata, tags, expiryMs, cb, cbId)
    )
  }

  public sessionRemoveAll(options: SessionRemoveAllOptions): Promise<number> {
    const { sessionHandle, tagFilter, category } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_session_remove_all(sessionHandle, category, tagFilter, cb, cbId)
    )
  }

  public sessionRemoveKey(options: SessionRemoveKeyOptions): Promise<void> {
    const { sessionHandle, name } = serializeArguments(options)

    return this.promisify((cb, cbId) => nativeAriesAskar.askar_session_remove_key(sessionHandle, name, cb, cbId))
  }

  public sessionStart(options: SessionStartOptions): Promise<SessionHandle> {
    const { storeHandle, profile, asTransaction } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_session_start(storeHandle, profile, asTransaction, cb, cbId)
    )
  }

  public sessionUpdate(options: SessionUpdateOptions): Promise<void> {
    const { name, sessionHandle, category, expiryMs, tags, operation, value } = serializeArguments(options)

    return this.promisify((cb, cbId) =>
      nativeAriesAskar.askar_session_update(sessionHandle, operation, category, name, value, tags, expiryMs, cb, cbId)
    )
  }

  public sessionUpdateKey(options: SessionUpdateKeyOptions): Promise<void> {
    const { expiryMs, tags, name, sessionHandle, metadata } = serializeArguments(options)

    return this.promisify((cb, cbId) =>
      nativeAriesAskar.askar_session_update_key(sessionHandle, name, metadata, tags, expiryMs, cb, cbId)
    )
  }

  public storeClose(options: StoreCloseOptions): Promise<void> {
    const { storeHandle } = serializeArguments(options)

    return this.promisify((cb, cbId) => nativeAriesAskar.askar_store_close(storeHandle, cb, cbId))
  }

  public storeCreateProfile(options: StoreCreateProfileOptions): Promise<string> {
    const { storeHandle, profile } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_store_create_profile(storeHandle, profile, cb, cbId)
    )
  }

  public storeGenerateRawKey(options: StoreGenerateRawKeyOptions): string {
    const { seed } = serializeArguments(options)
    const out = allocateStringBuffer()

    nativeAriesAskar.askar_store_generate_raw_key(seed, out)
    handleError()

    return out.deref() as string
  }

  public storeGetProfileName(options: StoreGetProfileNameOptions): Promise<string> {
    const { storeHandle } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_store_get_profile_name(storeHandle, cb, cbId)
    )
  }

  public async storeOpen(options: StoreOpenOptions): Promise<StoreHandle> {
    const { profile, keyMethod, passKey, specUri } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_store_open(specUri, keyMethod, passKey, profile, cb, cbId)
    )
  }

  public async storeProvision(options: StoreProvisionOptions): Promise<StoreHandle> {
    const { profile, passKey, keyMethod, specUri, recreate } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_store_provision(specUri, keyMethod, passKey, profile, recreate, cb, cbId)
    )
  }

  public storeRekey(options: StoreRekeyOptions): Promise<void> {
    const { passKey, keyMethod, storeHandle } = serializeArguments(options)

    return this.promisify((cb, cbId) => nativeAriesAskar.askar_store_rekey(storeHandle, keyMethod, passKey, cb, cbId))
  }

  public storeRemove(options: StoreRemoveOptions): Promise<number> {
    const { specUri } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) => nativeAriesAskar.askar_store_remove(specUri, cb, cbId))
  }

  public storeRemoveProfile(options: StoreRemoveProfileOptions): Promise<number> {
    const { storeHandle, profile } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_store_remove_profile(storeHandle, profile, cb, cbId)
    )
  }
}
