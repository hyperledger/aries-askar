/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-use-before-define */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/ban-ts-comment */
/* eslint-disable no-console */

import type {
  NativeCallback,
  NativeCallbackWithResponse,
  NativeLogCallback,
  SecretBufferType,
  AeadParamsType,
} from './ffi'
import type {
  AriesAskar,
  BufferFreeOptions,
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
  EncryptedBuffer,
} from 'aries-askar-shared'

import {
  AriesAskarError,
  ScanHandle,
  EntryListHandle,
  StoreHandle,
  LocalKeyHandle,
  AeadParams,
  SecretBuffer,
  SessionHandle,
  KeyEntryListHandle,
} from 'aries-askar-shared'

import { handleError } from './error'
import {
  serializeArguments,
  encryptedBufferStructToClass,
  deallocateCallbackBuffer,
  toNativeCallback,
  FFI_STRING,
  allocateStringBuffer,
  toNativeCallbackWithResponse,
  toNativeLogCallback,
  allocateInt32Buffer,
  allocateSecretBuffer,
  secretBufferToBuffer,
  allocateEncryptedBuffer,
  allocateAeadParams,
  allocatePointer,
  allocateInt8Buffer,
  FFI_ENTRY_LIST_HANDLE,
  FFI_SCAN_HANDLE,
  FFI_INT64,
  FFI_KEY_ENTRY_LIST_HANDLE,
  FFI_SESSION_HANDLE,
  FFI_STORE_HANDLE,
  FFI_INT8,
} from './ffi'
import { nativeAriesAskar } from './library'

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

  private promisifyWithResponse = async <Return, Response = string>(
    method: (nativeCallbackWithResponsePtr: Buffer, id: number) => void,
    responseFfiType: any = FFI_STRING
  ): Promise<Return> => {
    return new Promise((resolve, reject) => {
      const cb: NativeCallbackWithResponse<Response> = (id, errorCode, response) => {
        deallocateCallbackBuffer(id)

        if (errorCode) {
          const nativeError = allocateStringBuffer()
          nativeAriesAskar.askar_get_current_error(nativeError)
          return reject(new AriesAskarError(JSON.parse(nativeError.deref())))
        }

        if (typeof response === 'string') {
          if (responseFfiType === FFI_STRING) resolve(response as unknown as Return)
          try {
            resolve(JSON.parse(response) as Return)
          } catch (error) {
            reject(error)
          }
        } else if (typeof response === 'number') {
          resolve(response as unknown as Return)
        } else if (response instanceof Buffer) {
          if (response.address() === 0)
            return reject(
              AriesAskarError.customError({
                message: 'Received null pointer. The native library could not find the value.',
              })
            )

          resolve(response as unknown as Return)
        }

        reject(`could not parse return type properly (type: ${typeof response})`)
      }
      const { nativeCallback, id } = toNativeCallbackWithResponse(cb, responseFfiType)
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
    // @ts-ignore
    nativeAriesAskar.askar_buffer_free(secretBuffer)
    handleError()
  }

  public clearCustomLogger(): void {
    nativeAriesAskar.askar_clear_custom_logger()
    handleError()
  }

  // TODO: the id has to be deallocated when its done, but how?
  public setCustomLogger({ logLevel, flush = false, enabled = false }: SetCustomLoggerOptions): void {
    const logger: NativeLogCallback = (context, level, target, message, modulePath, file, line) => {
      // console.table({ context, level, target, message, modulePath, file, line })
      console.log(`| ${file}:${line} | ${message}`)
    }
    const { id, nativeCallback } = toNativeLogCallback(logger)

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
    const ret = allocateInt32Buffer()

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

    return ret.deref()
  }

  public entryListGetName(options: EntryListGetNameOptions): string {
    const { entryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_entry_list_get_name(entryListHandle, index, ret)
    handleError()

    return ret.deref()
  }

  public entryListGetTags(options: EntryListGetTagsOptions): string {
    const { entryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_entry_list_get_tags(entryListHandle, index, ret)
    handleError()

    return ret.deref()
  }

  public entryListGetValue(options: EntryListGetValueOptions): string {
    const { entryListHandle, index } = serializeArguments(options)

    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_entry_list_get_value(entryListHandle, index, ret)
    handleError()

    return secretBufferToBuffer(ret.deref()).toString()
  }

  public keyAeadDecrypt(options: KeyAeadDecryptOptions): SecretBuffer {
    const { aad, ciphertext, localKeyHandle, nonce, tag } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_aead_decrypt(localKeyHandle, ciphertext, nonce, tag, aad, ret)
    handleError()

    const secretBuffer: SecretBufferType = ret.deref()
    // @ts-ignore
    return new SecretBuffer(secretBuffer)
  }

  public keyAeadEncrypt(options: KeyAeadEncryptOptions): EncryptedBuffer {
    const { localKeyHandle, aad, nonce, message } = serializeArguments(options)
    const ret = allocateEncryptedBuffer()
    console.log('Pointer @ node.js', ret.hexAddress())

    // @ts-ignore
    nativeAriesAskar.askar_key_aead_encrypt(localKeyHandle, message, nonce, aad, ret)
    handleError()

    return encryptedBufferStructToClass(ret.deref())
  }

  public keyAeadGetPadding(options: KeyAeadGetPaddingOptions): number {
    const { localKeyHandle, msgLen } = serializeArguments(options)
    const ret = allocateInt32Buffer()

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

    const aeadParams: AeadParamsType = ret.deref()
    // @ts-ignore
    return new AeadParams(aeadParams)
  }

  public keyAeadRandomNonce(options: KeyAeadRandomNonceOptions): Uint8Array {
    const { localKeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_aead_random_nonce(localKeyHandle, ret)
    handleError()

    return new Uint8Array(secretBufferToBuffer(ret.deref()))
  }

  public keyConvert(options: KeyConvertOptions): LocalKeyHandle {
    const { localKeyHandle, alg } = serializeArguments(options)

    const ret = allocatePointer()

    // @ts-ignore
    nativeAriesAskar.askar_key_convert(localKeyHandle, alg, ret)
    handleError()

    return new LocalKeyHandle(ret.deref())
  }

  public keyCryptoBox(options: KeyCryptoBoxOptions): Uint8Array {
    const { nonce, message, recipKey, senderKey } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_crypto_box(recipKey, senderKey, message, nonce, ret)
    handleError()

    return new Uint8Array(secretBufferToBuffer(ret.deref()))
  }

  public keyCryptoBoxOpen(options: KeyCryptoBoxOpenOptions): Uint8Array {
    const { nonce, message, senderKey, recipKey } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_crypto_box_open(recipKey, senderKey, message, nonce, ret)
    handleError()

    return new Uint8Array(secretBufferToBuffer(ret.deref()))
  }

  public keyCryptoBoxRandomNonce(): Uint8Array {
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_crypto_box_random_nonce(ret)
    handleError()

    return new Uint8Array(secretBufferToBuffer(ret.deref()))
  }

  public keyCryptoBoxSeal(options: KeyCryptoBoxSealOptions): Uint8Array {
    const { message, localKeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_crypto_box_seal(localKeyHandle, message, ret)
    handleError()

    return new Uint8Array(secretBufferToBuffer(ret.deref()))
  }

  public keyCryptoBoxSealOpen(options: KeyCryptoBoxSealOpenOptions): Uint8Array {
    const { ciphertext, localKeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_crypto_box_seal_open(localKeyHandle, ciphertext, ret)
    handleError()

    return new Uint8Array(secretBufferToBuffer(ret.deref()))
  }

  public keyDeriveEcdh1pu(options: KeyDeriveEcdh1puOptions): LocalKeyHandle {
    const { senderKey, recipKey, alg, algId, apu, apv, ccTag, ephemKey, receive } = serializeArguments(options)

    const ret = allocatePointer()

    // @ts-ignore
    nativeAriesAskar.askar_key_derive_ecdh_1pu(alg, ephemKey, senderKey, recipKey, algId, apu, apv, ccTag, receive, ret)
    handleError()

    return new LocalKeyHandle(ret.deref())
  }

  public keyDeriveEcdhEs(options: KeyDeriveEcdhEsOptions): LocalKeyHandle {
    const { receive, apv, apu, algId, recipKey, ephemKey, alg } = serializeArguments(options)

    const ret = allocatePointer()

    // @ts-ignore
    nativeAriesAskar.askar_key_derive_ecdh_es(alg, ephemKey, recipKey, algId, apu, apv, receive, ret)
    handleError()

    return new LocalKeyHandle(ret.deref())
  }

  public keyEntryListCount(options: KeyEntryListCountOptions): number {
    const { keyEntryListHandle } = serializeArguments(options)
    const ret = allocateInt32Buffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_count(keyEntryListHandle, ret)
    handleError()

    return ret.deref() as number
  }

  public keyEntryListFree(options: KeyEntryListFreeOptions): void {
    const { keyEntryListHandle } = serializeArguments(options)

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_free(keyEntryListHandle)
    handleError()
  }

  public keyEntryListGetAlgorithm(options: KeyEntryListGetAlgorithmOptions): string {
    const { keyEntryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_get_algorithm(keyEntryListHandle, index, ret)
    handleError()

    return ret.deref()
  }

  public keyEntryListGetMetadata(options: KeyEntryListGetMetadataOptions): string {
    const { keyEntryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_get_metadata(keyEntryListHandle, index, ret)
    handleError()

    return ret.deref()
  }

  public keyEntryListGetName(options: KeyEntryListGetNameOptions): string {
    const { keyEntryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_get_name(keyEntryListHandle, index, ret)
    handleError()

    return ret.deref()
  }

  public keyEntryListGetTags(options: KeyEntryListGetTagsOptions): string {
    const { keyEntryListHandle, index } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_entry_list_get_tags(keyEntryListHandle, index, ret)
    return ret.deref()
  }

  public keyEntryListLoadLocal(options: KeyEntryListLoadLocalOptions): LocalKeyHandle {
    const { index, keyEntryListHandle } = serializeArguments(options)
    const ret = allocatePointer()

    nativeAriesAskar.askar_key_entry_list_load_local(keyEntryListHandle, index, ret)
    handleError()

    return new LocalKeyHandle(ret.deref())
  }

  public keyFree(options: KeyFreeOptions): void {
    const { keyEntryListHandle } = serializeArguments(options)

    // @ts-ignore
    nativeAriesAskar.askar_key_free(keyEntryListHandle)
    handleError()
  }

  public keyFromJwk(options: KeyFromJwkOptions): LocalKeyHandle {
    const { jwk } = serializeArguments(options)

    const ret = allocatePointer()

    // @ts-ignore
    nativeAriesAskar.askar_key_from_jwk(jwk, ret)
    handleError()

    return new LocalKeyHandle(ret.deref())
  }

  public keyFromKeyExchange(options: KeyFromKeyExchangeOptions): LocalKeyHandle {
    const { alg, pkHandle, skHandle } = serializeArguments(options)

    const ret = allocatePointer()

    // @ts-ignore
    nativeAriesAskar.askar_key_from_key_exchange(alg, skHandle, pkHandle, ret)
    handleError()

    return new LocalKeyHandle(ret.deref())
  }

  public keyFromPublicBytes(options: KeyFromPublicBytesOptions): LocalKeyHandle {
    const { publicKey, alg } = serializeArguments(options)

    const ret = allocatePointer()

    // @ts-ignore
    nativeAriesAskar.askar_key_from_public_bytes(alg, publicKey, ret)
    handleError()

    return new LocalKeyHandle(ret.deref())
  }

  public keyFromSecretBytes(options: KeyFromSecretBytesOptions): LocalKeyHandle {
    const { secretKey, alg } = serializeArguments(options)

    const ret = allocatePointer()

    // @ts-ignore
    nativeAriesAskar.askar_key_from_secret_bytes(alg, secretKey, ret)
    handleError()

    return new LocalKeyHandle(ret.deref())
  }

  public keyFromSeed(options: KeyFromSeedOptions): LocalKeyHandle {
    const { alg, method, seed } = serializeArguments(options)

    const ret = allocatePointer()

    // @ts-ignore
    nativeAriesAskar.askar_key_from_seed(alg, seed, method, ret)
    handleError()

    return new LocalKeyHandle(ret.deref())
  }

  public keyGenerate(options: KeyGenerateOptions): LocalKeyHandle {
    const { alg, ephemeral } = serializeArguments(options)

    const ret = allocatePointer()

    // @ts-ignore
    nativeAriesAskar.askar_key_generate(alg, ephemeral, ret)
    handleError()

    return new LocalKeyHandle(ret.deref())
  }

  public keyGetAlgorithm(options: KeyGetAlgorithmOptions): string {
    // @ts-ignore
    const { localKeyHandle } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_algorithm(localKeyHandle, ret)
    handleError()

    return ret.deref()
  }

  public keyGetEphemeral(options: KeyGetEphemeralOptions): number {
    const { localKeyHandle } = serializeArguments(options)
    const ret = allocateInt32Buffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_ephemeral(localKeyHandle, ret)
    handleError()

    return ret.deref()
  }

  public keyGetJwkPublic(options: KeyGetJwkPublicOptions): string {
    const { localKeyHandle, algorithm } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_jwk_public(localKeyHandle, algorithm, ret)
    handleError()

    return ret.deref()
  }

  public keyGetJwkSecret(options: KeyGetJwkSecretOptions): string {
    const { localKeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_jwk_secret(localKeyHandle, ret)
    handleError()

    return secretBufferToBuffer(ret.deref()).toString()
  }

  public keyGetJwkThumbprint(options: KeyGetJwkThumbprintOptions): string {
    const { localKeyHandle, algorithm } = serializeArguments(options)
    const ret = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_jwk_thumbprint(localKeyHandle, algorithm, ret)
    handleError()

    return ret.deref()
  }

  public keyGetPublicBytes(options: KeyGetPublicBytesOptions): Uint8Array {
    const { localKeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_public_bytes(localKeyHandle, ret)
    handleError()

    return new Uint8Array(secretBufferToBuffer(ret.deref()))
  }

  public keyGetSecretBytes(options: KeyGetSecretBytesOptions): Uint8Array {
    const { localKeyHandle } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_get_secret_bytes(localKeyHandle, ret)
    handleError()

    return new Uint8Array(secretBufferToBuffer(ret.deref()))
  }

  public keySignMessage(options: KeySignMessageOptions): Uint8Array {
    const { localKeyHandle, message, sigType } = serializeArguments(options)
    const ret = allocateSecretBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_sign_message(localKeyHandle, message, sigType, ret)
    handleError()

    return new Uint8Array(secretBufferToBuffer(ret.deref()))
  }

  public keyUnwrapKey(options: KeyUnwrapKeyOptions): LocalKeyHandle {
    const { localKeyHandle, alg, ciphertext, nonce, tag } = serializeArguments(options)

    const ret = allocatePointer()

    // @ts-ignore
    nativeAriesAskar.askar_key_unwrap_key(localKeyHandle, alg, ciphertext, nonce, tag, ret)
    handleError()

    return new LocalKeyHandle(ret.deref())
  }

  public keyVerifySignature(options: KeyVerifySignatureOptions): boolean {
    const { localKeyHandle, sigType, message, signature } = serializeArguments(options)
    const ret = allocateInt8Buffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_verify_signature(localKeyHandle, message, signature, sigType, ret)
    handleError()

    return Boolean(ret.deref())
  }

  public keyWrapKey(options: KeyWrapKeyOptions): EncryptedBuffer {
    const { localKeyHandle, nonce, other } = serializeArguments(options)
    const ret = allocateEncryptedBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_key_wrap_key(localKeyHandle, other, nonce, ret)
    handleError()

    return encryptedBufferStructToClass(ret.deref())
  }

  public scanFree(options: ScanFreeOptions): void {
    const { scanHandle } = serializeArguments(options)

    nativeAriesAskar.askar_scan_free(scanHandle)
    handleError()
  }

  public async scanNext(options: ScanNextOptions): Promise<EntryListHandle> {
    const { scanHandle } = serializeArguments(options)

    const handle = await this.promisifyWithResponse<Uint8Array>(
      (cb, cbId) => nativeAriesAskar.askar_scan_next(scanHandle, cb, cbId),
      FFI_ENTRY_LIST_HANDLE
    )

    return new EntryListHandle(handle)
  }

  public async scanStart(options: ScanStartOptions): Promise<ScanHandle> {
    const { category, limit, offset, profile, storeHandle, tagFilter } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<number>(
      (cb, cbId) =>
        nativeAriesAskar.askar_scan_start(
          storeHandle,
          profile,
          category,
          tagFilter,
          +offset || -1,
          +limit || -1,
          cb,
          cbId
        ),
      FFI_SCAN_HANDLE
    )

    return new ScanHandle(handle)
  }

  public async sessionClose(options: SessionCloseOptions): Promise<void> {
    const { commit, sessionHandle } = serializeArguments(options)

    return await this.promisify((cb, cbId) => nativeAriesAskar.askar_session_close(sessionHandle, commit, cb, cbId))
  }

  public async sessionCount(options: SessionCountOptions): Promise<number> {
    const { sessionHandle, tagFilter, category } = serializeArguments(options)
    return this.promisifyWithResponse<number, number>(
      (cb, cbId) => nativeAriesAskar.askar_session_count(sessionHandle, category, tagFilter, cb, cbId),
      FFI_INT64
    )
  }

  public async sessionFetch(options: SessionFetchOptions): Promise<EntryListHandle> {
    const { name, category, sessionHandle, forUpdate } = serializeArguments(options)
    const handle = await this.promisifyWithResponse<Uint8Array>(
      (cb, cbId) => nativeAriesAskar.askar_session_fetch(sessionHandle, category, name, forUpdate, cb, cbId),
      FFI_ENTRY_LIST_HANDLE
    )

    return new EntryListHandle(handle)
  }

  public async sessionFetchAll(options: SessionFetchAllOptions): Promise<EntryListHandle> {
    const { forUpdate, sessionHandle, tagFilter, limit, category } = serializeArguments(options)

    const handle = await this.promisifyWithResponse<Uint8Array>(
      (cb, cbId) =>
        nativeAriesAskar.askar_session_fetch_all(sessionHandle, category, tagFilter, +limit || -1, forUpdate, cb, cbId),
      FFI_ENTRY_LIST_HANDLE
    )

    return new EntryListHandle(handle)
  }

  public async sessionFetchAllKeys(options: SessionFetchAllKeysOptions): Promise<KeyEntryListHandle> {
    const { forUpdate, limit, tagFilter, sessionHandle, algorithm, thumbprint } = serializeArguments(options)

    const handle = await this.promisifyWithResponse<Uint8Array>(
      (cb, cbId) =>
        nativeAriesAskar.askar_session_fetch_all_keys(
          sessionHandle,
          algorithm,
          thumbprint,
          tagFilter,
          +limit || -1,
          forUpdate,
          cb,
          cbId
        ),
      FFI_KEY_ENTRY_LIST_HANDLE
    )

    return new KeyEntryListHandle(handle)
  }

  public async sessionFetchKey(options: SessionFetchKeyOptions): Promise<KeyEntryListHandle> {
    const { forUpdate, sessionHandle, name } = serializeArguments(options)

    const handle = await this.promisifyWithResponse<Uint8Array>(
      (cb, cbId) => nativeAriesAskar.askar_session_fetch_key(sessionHandle, name, forUpdate, cb, cbId),
      FFI_KEY_ENTRY_LIST_HANDLE
    )

    return new KeyEntryListHandle(handle)
  }

  public async sessionInsertKey(options: SessionInsertKeyOptions): Promise<void> {
    const { name, sessionHandle, expiryMs, localKeyHandle, metadata, tags } = serializeArguments(options)

    return this.promisify((cb, cbId) =>
      nativeAriesAskar.askar_session_insert_key(
        sessionHandle,
        // @ts-ignore
        localKeyHandle,
        name,
        metadata,
        tags,
        +expiryMs || -1,
        cb,
        cbId
      )
    )
  }

  public async sessionRemoveAll(options: SessionRemoveAllOptions): Promise<number> {
    const { sessionHandle, tagFilter, category } = serializeArguments(options)

    return this.promisifyWithResponse(
      (cb, cbId) => nativeAriesAskar.askar_session_remove_all(sessionHandle, category, tagFilter, cb, cbId),
      FFI_INT64
    )
  }

  public async sessionRemoveKey(options: SessionRemoveKeyOptions): Promise<void> {
    const { sessionHandle, name } = serializeArguments(options)

    return this.promisify((cb, cbId) => nativeAriesAskar.askar_session_remove_key(sessionHandle, name, cb, cbId))
  }

  public async sessionStart(options: SessionStartOptions): Promise<SessionHandle> {
    const { storeHandle, profile, asTransaction } = serializeArguments(options)

    const handle = await this.promisifyWithResponse<number, number>((cb, cbId) => {
      nativeAriesAskar.askar_session_start(storeHandle, profile, asTransaction, cb, cbId)
    }, FFI_SESSION_HANDLE)

    return new SessionHandle(handle)
  }

  public async sessionUpdate(options: SessionUpdateOptions): Promise<void> {
    const { name, sessionHandle, category, expiryMs, tags, operation, value } = serializeArguments(options)

    return this.promisify((cb, cbId) =>
      nativeAriesAskar.askar_session_update(
        sessionHandle,
        operation,
        category,
        name,
        // @ts-ignore
        value,
        tags,
        +expiryMs || -1,
        cb,
        cbId
      )
    )
  }

  public async sessionUpdateKey(options: SessionUpdateKeyOptions): Promise<void> {
    const { expiryMs, tags, name, sessionHandle, metadata } = serializeArguments(options)

    return this.promisify((cb, cbId) =>
      nativeAriesAskar.askar_session_update_key(sessionHandle, name, metadata, tags, +expiryMs || -1, cb, cbId)
    )
  }

  public storeClose(options: StoreCloseOptions): Promise<void> {
    const { storeHandle } = serializeArguments(options)

    return this.promisify((cb, cbId) => nativeAriesAskar.askar_store_close(storeHandle, cb, cbId))
  }

  public storeCreateProfile(options: StoreCreateProfileOptions): Promise<string> {
    const { storeHandle, profile } = serializeArguments(options)

    return this.promisifyWithResponse(
      (cb, cbId) => nativeAriesAskar.askar_store_create_profile(storeHandle, profile, cb, cbId),
      FFI_STRING
    )
  }

  public storeGenerateRawKey(options: StoreGenerateRawKeyOptions): string {
    const { seed } = serializeArguments(options)
    const out = allocateStringBuffer()

    // @ts-ignore
    nativeAriesAskar.askar_store_generate_raw_key(seed, out)
    handleError()

    return out.deref() as string
  }

  public async storeGetProfileName(options: StoreGetProfileNameOptions): Promise<string> {
    const { storeHandle } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) =>
      nativeAriesAskar.askar_store_get_profile_name(storeHandle, cb, cbId)
    )
  }

  public async storeOpen(options: StoreOpenOptions): Promise<StoreHandle> {
    const { profile, keyMethod, passKey, specUri } = serializeArguments(options)

    const handle = await this.promisifyWithResponse<number>(
      (cb, cbId) => nativeAriesAskar.askar_store_open(specUri, keyMethod, passKey, profile, cb, cbId),
      FFI_STORE_HANDLE
    )

    return new StoreHandle(handle)
  }

  public async storeProvision(options: StoreProvisionOptions): Promise<StoreHandle> {
    const { profile, passKey, keyMethod, specUri, recreate } = serializeArguments(options)

    const handle = await this.promisifyWithResponse<number, number>(
      (cb, cbId) => nativeAriesAskar.askar_store_provision(specUri, keyMethod, passKey, profile, recreate, cb, cbId),
      FFI_STORE_HANDLE
    )

    return new StoreHandle(handle)
  }

  public async storeRekey(options: StoreRekeyOptions): Promise<void> {
    const { passKey, keyMethod, storeHandle } = serializeArguments(options)

    return this.promisify((cb, cbId) => nativeAriesAskar.askar_store_rekey(storeHandle, keyMethod, passKey, cb, cbId))
  }

  public async storeRemove(options: StoreRemoveOptions): Promise<number> {
    const { specUri } = serializeArguments(options)

    return this.promisifyWithResponse((cb, cbId) => nativeAriesAskar.askar_store_remove(specUri, cb, cbId), FFI_INT8)
  }

  public async storeRemoveProfile(options: StoreRemoveProfileOptions): Promise<number> {
    const { storeHandle, profile } = serializeArguments(options)

    return this.promisifyWithResponse(
      (cb, cbId) => nativeAriesAskar.askar_store_remove_profile(storeHandle, profile, cb, cbId),
      FFI_INT8
    )
  }
}
