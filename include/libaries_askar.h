#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

static const uintptr_t PAGE_SIZE = 32;

enum class ErrorCode : int64_t {
  Success = 0,
  Backend = 1,
  Busy = 2,
  Duplicate = 3,
  Encryption = 4,
  Input = 5,
  NotFound = 6,
  Unexpected = 7,
  Unsupported = 8,
  Custom = 100,
};

/// A record in the store
struct Entry;

template<typename R = void>
struct FfiResultList;

/// A stored key entry
struct KeyEntry;

/// A stored key entry
struct LocalKey;

template<typename T = void>
struct Option;

template<typename T>
using ArcHandle = uintptr_t;

using LocalKeyHandle = ArcHandle<LocalKey>;

struct SecretBuffer {
  int64_t len;
  uint8_t *data;
};

struct AeadParams {
  int32_t nonce_length;
  int32_t tag_length;
};

struct EncryptedBuffer {
  SecretBuffer buffer;
  int64_t tag_pos;
  int64_t nonce_pos;
};

using LogCallback = void(*)(const void *context, int32_t level, const char *target, const char *message, const char *module_path, const char *file, int32_t line);

using EnabledCallback = int8_t(*)(const void *context, int32_t level);

using FlushCallback = void(*)(const void *context);

using FfiEntryList = FfiResultList<Entry>;

using EntryListHandle = ArcHandle<FfiEntryList>;

using FfiKeyEntryList = FfiResultList<KeyEntry>;

using KeyEntryListHandle = ArcHandle<FfiKeyEntryList>;

using CallbackId = int64_t;

extern "C" {

char *askar_version();

ErrorCode askar_get_current_error(const char **error_json_p);

ErrorCode askar_key_generate(FfiStr alg, int8_t ephemeral, LocalKeyHandle *out);

ErrorCode askar_key_from_seed(FfiStr alg, ByteBuffer seed, FfiStr method, LocalKeyHandle *out);

ErrorCode askar_key_from_jwk(ByteBuffer jwk, LocalKeyHandle *out);

ErrorCode askar_key_from_public_bytes(FfiStr alg, ByteBuffer public_, LocalKeyHandle *out);

ErrorCode askar_key_get_public_bytes(LocalKeyHandle handle, SecretBuffer *out);

ErrorCode askar_key_from_secret_bytes(FfiStr alg, ByteBuffer secret, LocalKeyHandle *out);

ErrorCode askar_key_get_secret_bytes(LocalKeyHandle handle, SecretBuffer *out);

ErrorCode askar_key_convert(LocalKeyHandle handle, FfiStr alg, LocalKeyHandle *out);

ErrorCode askar_key_from_key_exchange(FfiStr alg,
                                      LocalKeyHandle sk_handle,
                                      LocalKeyHandle pk_handle,
                                      LocalKeyHandle *out);

void askar_key_free(LocalKeyHandle handle);

ErrorCode askar_key_get_algorithm(LocalKeyHandle handle, const char **out);

ErrorCode askar_key_get_ephemeral(LocalKeyHandle handle, int8_t *out);

ErrorCode askar_key_get_jwk_public(LocalKeyHandle handle, FfiStr alg, const char **out);

ErrorCode askar_key_get_jwk_secret(LocalKeyHandle handle, SecretBuffer *out);

ErrorCode askar_key_get_jwk_thumbprint(LocalKeyHandle handle, FfiStr alg, const char **out);

ErrorCode askar_key_aead_random_nonce(LocalKeyHandle handle, SecretBuffer *out);

ErrorCode askar_key_aead_get_params(LocalKeyHandle handle, AeadParams *out);

ErrorCode askar_key_aead_get_padding(LocalKeyHandle handle, int64_t msg_len, int32_t *out);

ErrorCode askar_key_aead_encrypt(LocalKeyHandle handle,
                                 ByteBuffer message,
                                 ByteBuffer nonce,
                                 ByteBuffer aad,
                                 EncryptedBuffer *out);

ErrorCode askar_key_aead_decrypt(LocalKeyHandle handle,
                                 ByteBuffer ciphertext,
                                 ByteBuffer nonce,
                                 ByteBuffer tag,
                                 ByteBuffer aad,
                                 SecretBuffer *out);

ErrorCode askar_key_sign_message(LocalKeyHandle handle,
                                 ByteBuffer message,
                                 FfiStr sig_type,
                                 SecretBuffer *out);

ErrorCode askar_key_verify_signature(LocalKeyHandle handle,
                                     ByteBuffer message,
                                     ByteBuffer signature,
                                     FfiStr sig_type,
                                     int8_t *out);

ErrorCode askar_key_wrap_key(LocalKeyHandle handle,
                             LocalKeyHandle other,
                             ByteBuffer nonce,
                             EncryptedBuffer *out);

ErrorCode askar_key_unwrap_key(LocalKeyHandle handle,
                               FfiStr alg,
                               ByteBuffer ciphertext,
                               ByteBuffer nonce,
                               ByteBuffer tag,
                               LocalKeyHandle *out);

ErrorCode askar_key_crypto_box_random_nonce(SecretBuffer *out);

ErrorCode askar_key_crypto_box(LocalKeyHandle recip_key,
                               LocalKeyHandle sender_key,
                               ByteBuffer message,
                               ByteBuffer nonce,
                               SecretBuffer *out);

ErrorCode askar_key_crypto_box_open(LocalKeyHandle recip_key,
                                    LocalKeyHandle sender_key,
                                    ByteBuffer message,
                                    ByteBuffer nonce,
                                    SecretBuffer *out);

ErrorCode askar_key_crypto_box_seal(LocalKeyHandle handle, ByteBuffer message, SecretBuffer *out);

ErrorCode askar_key_crypto_box_seal_open(LocalKeyHandle handle,
                                         ByteBuffer ciphertext,
                                         SecretBuffer *out);

ErrorCode askar_key_derive_ecdh_es(FfiStr alg,
                                   LocalKeyHandle ephem_key,
                                   LocalKeyHandle recip_key,
                                   ByteBuffer alg_id,
                                   ByteBuffer apu,
                                   ByteBuffer apv,
                                   int8_t receive,
                                   LocalKeyHandle *out);

ErrorCode askar_key_derive_ecdh_1pu(FfiStr alg,
                                    LocalKeyHandle ephem_key,
                                    LocalKeyHandle sender_key,
                                    LocalKeyHandle recip_key,
                                    ByteBuffer alg_id,
                                    ByteBuffer apu,
                                    ByteBuffer apv,
                                    ByteBuffer cc_tag,
                                    int8_t receive,
                                    LocalKeyHandle *out);

ErrorCode askar_set_custom_logger(const void *context,
                                  LogCallback log,
                                  Option<EnabledCallback> enabled,
                                  Option<FlushCallback> flush,
                                  int32_t max_level);

ErrorCode askar_set_default_logger();

ErrorCode askar_set_max_log_level(int32_t max_level);

ErrorCode askar_entry_list_count(EntryListHandle handle, int32_t *count);

ErrorCode askar_entry_list_get_category(EntryListHandle handle,
                                        int32_t index,
                                        const char **category);

ErrorCode askar_entry_list_get_name(EntryListHandle handle, int32_t index, const char **name);

ErrorCode askar_entry_list_get_value(EntryListHandle handle, int32_t index, SecretBuffer *value);

ErrorCode askar_entry_list_get_tags(EntryListHandle handle, int32_t index, const char **tags);

void askar_entry_list_free(EntryListHandle handle);

ErrorCode askar_key_entry_list_count(KeyEntryListHandle handle, int32_t *count);

void askar_key_entry_list_free(KeyEntryListHandle handle);

ErrorCode askar_key_entry_list_get_algorithm(KeyEntryListHandle handle,
                                             int32_t index,
                                             const char **alg);

ErrorCode askar_key_entry_list_get_name(KeyEntryListHandle handle,
                                        int32_t index,
                                        const char **name);

ErrorCode askar_key_entry_list_get_metadata(KeyEntryListHandle handle,
                                            int32_t index,
                                            const char **metadata);

ErrorCode askar_key_entry_list_get_tags(KeyEntryListHandle handle,
                                        int32_t index,
                                        const char **tags);

ErrorCode askar_key_entry_list_load_local(KeyEntryListHandle handle,
                                          int32_t index,
                                          LocalKeyHandle *out);

void askar_buffer_free(SecretBuffer buffer);

ErrorCode askar_store_generate_raw_key(ByteBuffer seed, const char **out);

ErrorCode askar_store_provision(FfiStr spec_uri,
                                FfiStr key_method,
                                FfiStr pass_key,
                                FfiStr profile,
                                int8_t recreate,
                                void (*cb)(CallbackId cb_id, ErrorCode err, StoreHandle handle),
                                CallbackId cb_id);

ErrorCode askar_store_open(FfiStr spec_uri,
                           FfiStr key_method,
                           FfiStr pass_key,
                           FfiStr profile,
                           void (*cb)(CallbackId cb_id, ErrorCode err, StoreHandle handle),
                           CallbackId cb_id);

ErrorCode askar_store_remove(FfiStr spec_uri,
                             void (*cb)(CallbackId cb_id, ErrorCode err, int8_t),
                             CallbackId cb_id);

ErrorCode askar_store_create_profile(StoreHandle handle,
                                     FfiStr profile,
                                     void (*cb)(CallbackId cb_id, ErrorCode err, const char *result_p),
                                     CallbackId cb_id);

ErrorCode askar_store_get_profile_name(StoreHandle handle,
                                       void (*cb)(CallbackId cb_id, ErrorCode err, const char *name),
                                       CallbackId cb_id);

ErrorCode askar_store_remove_profile(StoreHandle handle,
                                     FfiStr profile,
                                     void (*cb)(CallbackId cb_id, ErrorCode err, int8_t removed),
                                     CallbackId cb_id);

ErrorCode askar_store_rekey(StoreHandle handle,
                            FfiStr key_method,
                            FfiStr pass_key,
                            void (*cb)(CallbackId cb_id, ErrorCode err),
                            CallbackId cb_id);

ErrorCode askar_store_close(StoreHandle handle,
                            void (*cb)(CallbackId cb_id, ErrorCode err),
                            CallbackId cb_id);

ErrorCode askar_scan_start(StoreHandle handle,
                           FfiStr profile,
                           FfiStr category,
                           FfiStr tag_filter,
                           int64_t offset,
                           int64_t limit,
                           void (*cb)(CallbackId cb_id, ErrorCode err, ScanHandle handle),
                           CallbackId cb_id);

ErrorCode askar_scan_next(ScanHandle handle,
                          void (*cb)(CallbackId cb_id, ErrorCode err, EntryListHandle results),
                          CallbackId cb_id);

ErrorCode askar_scan_free(ScanHandle handle);

ErrorCode askar_session_start(StoreHandle handle,
                              FfiStr profile,
                              int8_t as_transaction,
                              void (*cb)(CallbackId cb_id, ErrorCode err, SessionHandle handle),
                              CallbackId cb_id);

ErrorCode askar_session_count(SessionHandle handle,
                              FfiStr category,
                              FfiStr tag_filter,
                              void (*cb)(CallbackId cb_id, ErrorCode err, int64_t count),
                              CallbackId cb_id);

ErrorCode askar_session_fetch(SessionHandle handle,
                              FfiStr category,
                              FfiStr name,
                              int8_t for_update,
                              void (*cb)(CallbackId cb_id, ErrorCode err, EntryListHandle results),
                              CallbackId cb_id);

ErrorCode askar_session_fetch_all(SessionHandle handle,
                                  FfiStr category,
                                  FfiStr tag_filter,
                                  int64_t limit,
                                  int8_t for_update,
                                  void (*cb)(CallbackId cb_id, ErrorCode err, EntryListHandle results),
                                  CallbackId cb_id);

ErrorCode askar_session_remove_all(SessionHandle handle,
                                   FfiStr category,
                                   FfiStr tag_filter,
                                   void (*cb)(CallbackId cb_id, ErrorCode err, int64_t removed),
                                   CallbackId cb_id);

ErrorCode askar_session_update(SessionHandle handle,
                               int8_t operation,
                               FfiStr category,
                               FfiStr name,
                               ByteBuffer value,
                               FfiStr tags,
                               int64_t expiry_ms,
                               void (*cb)(CallbackId cb_id, ErrorCode err),
                               CallbackId cb_id);

ErrorCode askar_session_insert_key(SessionHandle handle,
                                   LocalKeyHandle key_handle,
                                   FfiStr name,
                                   FfiStr metadata,
                                   FfiStr tags,
                                   int64_t expiry_ms,
                                   void (*cb)(CallbackId cb_id, ErrorCode err),
                                   CallbackId cb_id);

ErrorCode askar_session_fetch_key(SessionHandle handle,
                                  FfiStr name,
                                  int8_t for_update,
                                  void (*cb)(CallbackId cb_id, ErrorCode err, KeyEntryListHandle results),
                                  CallbackId cb_id);

ErrorCode askar_session_fetch_all_keys(SessionHandle handle,
                                       FfiStr alg,
                                       FfiStr thumbprint,
                                       FfiStr tag_filter,
                                       int64_t limit,
                                       int8_t for_update,
                                       void (*cb)(CallbackId cb_id, ErrorCode err, KeyEntryListHandle results),
                                       CallbackId cb_id);

ErrorCode askar_session_update_key(SessionHandle handle,
                                   FfiStr name,
                                   FfiStr metadata,
                                   FfiStr tags,
                                   int64_t expiry_ms,
                                   void (*cb)(CallbackId cb_id, ErrorCode err),
                                   CallbackId cb_id);

ErrorCode askar_session_remove_key(SessionHandle handle,
                                   FfiStr name,
                                   void (*cb)(CallbackId cb_id, ErrorCode err),
                                   CallbackId cb_id);

ErrorCode askar_session_close(SessionHandle handle,
                              int8_t commit,
                              void (*cb)(CallbackId cb_id, ErrorCode err),
                              CallbackId cb_id);

} // extern "C"
