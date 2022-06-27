#include <ariesAskar.h>

#include <include/libaries_askar.h>

using namespace turboModuleUtility;

namespace ariesAskar {

jsi::Value version(jsi::Runtime &rt, jsi::Object options) {
  return jsi::String::createFromAscii(rt, askar_version());
};

jsi::Value getCurrentError(jsi::Runtime &rt, jsi::Object options) {
  const char *error;
  askar_get_current_error(&error);
  return jsi::String::createFromAscii(rt, error);
};

jsi::Value entryListCount(jsi::Runtime &rt, jsi::Object options) {
  EntryListHandle handle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");

  int32_t out;

  ErrorCode code = askar_entry_list_count(handle, &out);
  handleError(rt, code);

  return jsi::Value(out);
};
jsi::Value entryListFree(jsi::Runtime &rt, jsi::Object options) {
  EntryListHandle handle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");

  askar_entry_list_free(handle);

  return jsi::Value::null();
}

jsi::Value entryListGetCategory(jsi::Runtime &rt, jsi::Object options) {
  EntryListHandle handle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");
  int32_t index = jsiToValue<int32_t>(rt, options, "index");

  const char *out;

  ErrorCode code = askar_entry_list_get_category(handle, index, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value entryListGetTags(jsi::Runtime &rt, jsi::Object options) {
  EntryListHandle handle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");
  int32_t index = jsiToValue<int32_t>(rt, options, "index");

  const char *out;

  ErrorCode code = askar_entry_list_get_tags(handle, index, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out ? out : "{}");
}

jsi::Value entryListGetValue(jsi::Runtime &rt, jsi::Object options) {
  EntryListHandle handle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");
  int32_t index = jsiToValue<int32_t>(rt, options, "index");

  SecretBuffer out;

  ErrorCode code = askar_entry_list_get_value(handle, index, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value entryListGetName(jsi::Runtime &rt, jsi::Object options) {
  EntryListHandle handle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");
  int32_t index = jsiToValue<int32_t>(rt, options, "index");

  const char *out;

  ErrorCode code = askar_entry_list_get_name(handle, index, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value storeOpen(jsi::Runtime &rt, jsi::Object options) {
  std::string specUri = jsiToValue<std::string>(rt, options, "specUri");
  std::string keyMethod =
      jsiToValue<std::string>(rt, options, "keyMethod", true);
  std::string passKey = jsiToValue<std::string>(rt, options, "passKey", true);
  std::string profile = jsiToValue<std::string>(rt, options, "profile", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_open(
      specUri.c_str(), keyMethod.length() ? keyMethod.c_str() : nullptr,
      passKey.length() ? passKey.c_str() : nullptr,
      profile.length() ? profile.c_str() : nullptr, callbackWithResponse,
      CallbackId(state));

  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeProvision(jsi::Runtime &rt, jsi::Object options) {
  std::string specUri = jsiToValue<std::string>(rt, options, "specUri");
  std::string keyMethod =
      jsiToValue<std::string>(rt, options, "keyMethod", true);
  std::string passKey = jsiToValue<std::string>(rt, options, "passKey", true);
  std::string profile = jsiToValue<std::string>(rt, options, "profile", true);
  int8_t recreate = jsiToValue<int8_t>(rt, options, "recreate");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_provision(
      specUri.c_str(), keyMethod.length() ? keyMethod.c_str() : nullptr,
      passKey.length() ? passKey.c_str() : nullptr,
      profile.length() ? profile.c_str() : nullptr, recreate,
      callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeGenerateRawKey(jsi::Runtime &rt, jsi::Object options) {
  ByteBuffer seed = jsiToValue<ByteBuffer>(rt, options, "seed", true);

  const char *out;
  ErrorCode code = askar_store_generate_raw_key(seed, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value storeClose(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "storeHandle");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_close(handle, callback, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeCreateProfile(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "storeHandle");
  std::string profile = jsiToValue<std::string>(rt, options, "profile", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_create_profile(
      handle, profile.length() ? profile.c_str() : nullptr,
      callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeGetProfileName(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "storeHandle");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_get_profile_name(handle, callbackWithResponse,
                                                CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeRekey(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "storeHandle");
  std::string keyMethod = jsiToValue<std::string>(rt, options, "keyMethod");
  std::string passKey = jsiToValue<std::string>(rt, options, "passKey");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_get_profile_name(
      StoreHandle(handle), callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeRemove(jsi::Runtime &rt, jsi::Object options) {
  std::string specUri = jsiToValue<std::string>(rt, options, "specUri");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_remove(specUri.c_str(), callbackWithResponse,
                                      CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeRemoveProfile(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "storeHandle");
  std::string profile = jsiToValue<std::string>(rt, options, "profile");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_store_remove_profile(StoreHandle(handle), profile.c_str(),
                                 callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionClose(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  int8_t commit = jsiToValue<int8_t>(rt, options, "commit");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_session_close(SessionHandle(handle), commit, callback,
                                       CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionCount(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  std::string category = jsiToValue<std::string>(rt, options, "category");
  std::string tagFilter =
      jsiToValue<std::string>(rt, options, "tagFilter", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_session_count(SessionHandle(handle), category.c_str(),
                          tagFilter.length() ? tagFilter.c_str() : nullptr,
                          callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionFetch(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  std::string category = jsiToValue<std::string>(rt, options, "category");
  std::string name = jsiToValue<std::string>(rt, options, "name");
  int8_t forUpdate = jsiToValue<int8_t>(rt, options, "forUpdate");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_session_fetch(SessionHandle(handle), category.c_str(), name.c_str(),
                          forUpdate, callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionFetchAll(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  std::string category = jsiToValue<std::string>(rt, options, "category");
  std::string tagFilter =
      jsiToValue<std::string>(rt, options, "tagFilter", true);
  int64_t limit = jsiToValue<int64_t>(rt, options, "limit", true);
  int8_t forUpdate = jsiToValue<int8_t>(rt, options, "forUpdate");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_session_fetch_all(
      SessionHandle(handle), category.c_str(),
      tagFilter.length() ? tagFilter.c_str() : nullptr, limit, forUpdate,
      callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionFetchAllKeys(jsi::Runtime &rt, jsi::Object options) {
  //  int64_t handle =
  //        jsiToValue<int64_t>(rt, options,
  //        "sessionHandle");
  //  std::string alg =
  //        jsiToValue<std::string>(rt, options, "algorithm");
  //  std::string thumbprint =
  //        jsiToValue<std::string>(rt, options,
  //        "thumbprint");
  //  std::string tagFilter =
  //        jsiToValue<std::string>(rt, options,
  //        "tagFilter");
  //  int64_t limit =
  //        jsiToValue<int64_t>(rt, options, "limit");
  //  int8_t forUpdate =
  //        jsiToValue<int8_t>(rt, options, "forUpdate");
  //
  //  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  //  State *state = new State(&cb);
  //  state->rt = &rt;
  //
  //  ErrorCode code = askar_session_fetch_all_keys(SessionHandle(handle),
  //  alg.c_str(), thumbprint.c_str(), tagFilter.c_str(), limit, forUpdate,
  //  callbackWithResponse, CallbackId(state));
  //  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionFetchKey(jsi::Runtime &rt, jsi::Object options) {
  //  int64_t handle =
  //        jsiToValue<int64_t>(rt, options,
  //        "sessionHandle");
  //  std::string name =
  //        jsiToValue<std::string>(rt, options, "name");
  //  int8_t forUpdate =
  //        jsiToValue<int8_t>(rt, options, "forUpdate");
  //
  //  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  //  State *state = new State(&cb);
  //  state->rt = &rt;
  //
  //  ErrorCode code = askar_session_fetch_key(SessionHandle(handle),
  //  name.c_str(), forUpdate, callbackWithResponse,
  //  CallbackId(state)); handleError(rt, code);

  return jsi::Value::null();
}

// TODO: how to deal with localKeyHandle
jsi::Value sessionInsertKey(jsi::Runtime &rt, jsi::Object options) {
  //  int64_t handle =
  //        jsiToValue<int64_t>(rt, options,
  //        "sessionHandle");
  //  LocalKeyHandle localKeyHandle =
  //        jsiToValue<LocalKeyHandle>(rt, options,
  //        "localKeyHandle");
  //  std::string name =
  //        jsiToValue<std::string>(rt, options, "name");
  //  std::string metadata =
  //        jsiToValue<std::string>(rt, options,
  //        "metadata");
  //  std::string tags =
  //        jsiToValue<std::string>(rt, options, "tags");
  //  int64_t expiryMs =
  //        jsiToValue<int64_t>(rt, options, "expiryMs");
  //
  //  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  //  State *state = new State(&cb);
  //  state->rt = &rt;
  //
  //  ErrorCode code = askar_session_insert_key(SessionHandle(handle),
  //  localKeyHandle, name.c_str(), metadata.c_str(), tags.c_str(), expiryMs,
  //  callback, CallbackId(state));
  //  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionRemoveAll(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  std::string category = jsiToValue<std::string>(rt, options, "category");
  std::string tagFilter =
      jsiToValue<std::string>(rt, options, "tagFilter", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_session_remove_all(SessionHandle(handle), category.c_str(),
                               tagFilter.length() ? tagFilter.c_str() : nullptr,
                               callbackWithResponse, CallbackId(state));

  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionRemoveKey(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  std::string name = jsiToValue<std::string>(rt, options, "name");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_session_remove_key(SessionHandle(handle), name.c_str(),
                                            callback, CallbackId(state));

  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionStart(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "storeHandle");
  std::string profile = jsiToValue<std::string>(rt, options, "profile", true);
  int8_t asTransaction = jsiToValue<int8_t>(rt, options, "asTransaction");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_session_start(
      StoreHandle(handle), profile.length() ? profile.c_str() : nullptr,
      asTransaction, callbackWithResponse, CallbackId(state));

  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionUpdate(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  int8_t operation = jsiToValue<int8_t>(rt, options, "operation");
  std::string category = jsiToValue<std::string>(rt, options, "category");
  std::string name = jsiToValue<std::string>(rt, options, "name");
  std::string tags = jsiToValue<std::string>(rt, options, "tags", true);
  ByteBuffer value = jsiToValue<ByteBuffer>(rt, options, "value", true);
  int64_t expiryMs = jsiToValue<int64_t>(rt, options, "expiryMs", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_session_update(SessionHandle(handle), operation,
                                        category.c_str(), name.c_str(), value,
                                        tags.length() ? tags.c_str() : nullptr,
                                        expiryMs, callback, CallbackId(state));

  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionUpdateKey(jsi::Runtime &rt, jsi::Object options) {
  //  int64_t handle =
  //        jsiToValue<int64_t>(rt, options,
  //        "sessionHandle");
  //  std::string name =
  //        jsiToValue<std::string>(rt, options, "name");
  //  std::string tags =
  //        jsiToValue<std::string>(rt, options, "tags");
  //  std::string metadata =
  //        jsiToValue<std::string>(rt, options,
  //        "metadata");
  //  int64_t expiryMs =
  //        jsiToValue<int64_t>(rt, options, "expiryMs");
  //
  //  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  //  State *state = new State(&cb);
  //  state->rt = &rt;
  //
  //  ErrorCode code = askar_session_update_key(SessionHandle(handle),
  //  name.c_str(), metadata.c_str(), tags.c_str(),expiryMs,
  //  callback, CallbackId(state));
  //
  //  handleError(rt, code);
  //
  return jsi::Value::null();
}

jsi::Value scanStart(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "storeHandle");
  std::string category = jsiToValue<std::string>(rt, options, "category");

  std::string tagFilter =
      jsiToValue<std::string>(rt, options, "tagFilter", true);
  std::string profile = jsiToValue<std::string>(rt, options, "profile", true);
  int64_t offset = jsiToValue<int64_t>(rt, options, "offset", true);
  int64_t limit = jsiToValue<int64_t>(rt, options, "limit", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_scan_start(
      handle, profile.length() ? profile.c_str() : nullptr, category.c_str(),
      tagFilter.length() ? tagFilter.c_str() : nullptr, offset, limit,
      callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
};

jsi::Value scanNext(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "scanHandle");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_scan_next(handle, callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
};

jsi::Value scanFree(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = jsiToValue<int64_t>(rt, options, "scanHandle");

  ErrorCode code = askar_scan_free(ScanHandle(handle));
  handleError(rt, code);

  return jsi::Value::null();
};

jsi::Value keyFromJwk(jsi::Runtime &rt, jsi::Object options) {
  ByteBuffer jwk = jsiToValue<ByteBuffer>(rt, options, "jwk");

  LocalKeyHandle out;

  ErrorCode code = askar_key_from_jwk(jwk, &out);
  handleError(rt, code);

  std::string serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyFromKeyExchange(jsi::Runtime &rt, jsi::Object options) {
  std::string alg = jsiToValue<std::string>(rt, options, "alg");
  LocalKeyHandle skHandle = jsiToValue<LocalKeyHandle>(rt, options, "skHandle");
  LocalKeyHandle pkHandle = jsiToValue<LocalKeyHandle>(rt, options, "pkHandle");

  LocalKeyHandle out;

  ErrorCode code =
      askar_key_from_key_exchange(alg.c_str(), skHandle, pkHandle, &out);
  handleError(rt, code);

  std::string serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyFromPublicBytes(jsi::Runtime &rt, jsi::Object options) {
  std::string alg = jsiToValue<std::string>(rt, options, "alg");
  ByteBuffer publicKey = jsiToValue<ByteBuffer>(rt, options, "publicKey");

  LocalKeyHandle out;

  ErrorCode code = askar_key_from_public_bytes(alg.c_str(), publicKey, &out);
  handleError(rt, code);

  std::string serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyFromSecretBytes(jsi::Runtime &rt, jsi::Object options) {
  std::string alg = jsiToValue<std::string>(rt, options, "alg");
  ByteBuffer secretKey = jsiToValue<ByteBuffer>(rt, options, "secretKey");

  LocalKeyHandle out;

  ErrorCode code = askar_key_from_secret_bytes(alg.c_str(), secretKey, &out);
  handleError(rt, code);

  std::string serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyFromSeed(jsi::Runtime &rt, jsi::Object options) {
  std::string alg = jsiToValue<std::string>(rt, options, "alg");
  ByteBuffer seed = jsiToValue<ByteBuffer>(rt, options, "seed");
  std::string method = jsiToValue<std::string>(rt, options, "method");

  LocalKeyHandle out;

  ErrorCode code = askar_key_from_seed(alg.c_str(), seed, method.c_str(), &out);
  handleError(rt, code);

  std::string serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyGenerate(jsi::Runtime &rt, jsi::Object options) {
  std::string alg = jsiToValue<std::string>(rt, options, "alg");
  int8_t ephemeral = jsiToValue<int8_t>(rt, options, "ephemeral");

  LocalKeyHandle out;

  ErrorCode code = askar_key_generate(alg.c_str(), ephemeral, &out);
  handleError(rt, code);

  std::string serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyGetAlgorithm(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  const char *out;

  ErrorCode code = askar_key_get_algorithm(handle, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value keyGetEphemeral(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  int8_t out;

  ErrorCode code = askar_key_get_ephemeral(handle, &out);
  handleError(rt, code);

  return jsi::Value(int(out));
}

jsi::Value keyGetJwkPublic(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  std::string alg = jsiToValue<std::string>(rt, options, "algorithm");

  const char *out;

  ErrorCode code = askar_key_get_jwk_public(handle, alg.c_str(), &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value keyGetJwkSecret(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  SecretBuffer out;

  ErrorCode code = askar_key_get_jwk_secret(handle, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyGetJwkThumbprint(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  std::string alg = jsiToValue<std::string>(rt, options, "alg");

  const char *out;

  ErrorCode code = askar_key_get_jwk_thumbprint(handle, alg.c_str(), &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value keyGetPublicBytes(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  SecretBuffer out;

  ErrorCode code = askar_key_get_public_bytes(handle, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyGetSecretBytes(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  SecretBuffer out;

  ErrorCode code = askar_key_get_secret_bytes(handle, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keySignMessage(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  ByteBuffer message = jsiToValue<ByteBuffer>(rt, options, "message");
  std::string sigType = jsiToValue<std::string>(rt, options, "sigType", true);

  SecretBuffer out;

  ErrorCode code = askar_key_sign_message(
      handle, message, sigType.length() ? sigType.c_str() : nullptr, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyUnwrapKey(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  std::string alg = jsiToValue<std::string>(rt, options, "alg");
  ByteBuffer ciphertext = jsiToValue<ByteBuffer>(rt, options, "ciphertext");
  ByteBuffer nonce = jsiToValue<ByteBuffer>(rt, options, "nonce", true);
  ByteBuffer tag = jsiToValue<ByteBuffer>(rt, options, "tag", true);

  LocalKeyHandle out;

  ErrorCode code =
      askar_key_unwrap_key(handle, alg.c_str(), ciphertext, nonce, tag, &out);
  handleError(rt, code);

  std::string serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyVerifySignature(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  ByteBuffer message = jsiToValue<ByteBuffer>(rt, options, "message");
  ByteBuffer signature = jsiToValue<ByteBuffer>(rt, options, "signature");
  std::string sigType = jsiToValue<std::string>(rt, options, "sigType", true);

  int8_t out;

  ErrorCode code = askar_key_verify_signature(
      handle, message, signature, sigType.length() ? sigType.c_str() : nullptr,
      &out);
  handleError(rt, code);

  return jsi::Value(int(out));
}

jsi::Value keyWrapKey(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  LocalKeyHandle other = jsiToValue<LocalKeyHandle>(rt, options, "other");
  ByteBuffer nonce = jsiToValue<ByteBuffer>(rt, options, "nonce", true);

  EncryptedBuffer out;

  ErrorCode code = askar_key_wrap_key(handle, other, nonce, &out);
  handleError(rt, code);

  // TODO: encryptedbuffer to object with the tag pos and all
  return jsi::Value::null();
}

jsi::Value keyConvert(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  std::string alg = jsiToValue<std::string>(rt, options, "alg");

  LocalKeyHandle out;

  ErrorCode code = askar_key_convert(handle, alg.c_str(), &out);
  handleError(rt, code);

  std::string serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
};

jsi::Value keyFree(jsi::Runtime &rt, jsi::Object options) {
  LocalKeyHandle handle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  askar_key_free(handle);

  return jsi::Value::null();
};

jsi::Value keyCryptoBox(jsi::Runtime &rt, jsi::Object options) {
  auto recipientKey = jsiToValue<LocalKeyHandle>(rt, options, "recipientKey");
  auto senderKey = jsiToValue<LocalKeyHandle>(rt, options, "senderKey");
  auto message = jsiToValue<ByteBuffer>(rt, options, "message");
  auto nonce = jsiToValue<ByteBuffer>(rt, options, "nonce");

  SecretBuffer out;

  ErrorCode code = askar_key_crypto_box(recipientKey, senderKey, message, nonce, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyCryptoBoxOpen(jsi::Runtime &rt, jsi::Object options) {
  auto recipientKey = jsiToValue<LocalKeyHandle>(rt, options, "recipientKey");
  auto senderKey = jsiToValue<LocalKeyHandle>(rt, options, "senderKey");
  auto message = jsiToValue<ByteBuffer>(rt, options, "message");
  auto nonce = jsiToValue<ByteBuffer>(rt, options, "nonce");

  SecretBuffer out;

  ErrorCode code = askar_key_crypto_box_open(recipientKey, senderKey, message, nonce, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyCryptoBoxRandomNonce(jsi::Runtime &rt, jsi::Object options) {
  SecretBuffer out;

  ErrorCode code = askar_key_crypto_box_random_nonce(&out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);

}

jsi::Value keyCryptoBoxSeal(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto message = jsiToValue<ByteBuffer>(rt, options, "message");

  SecretBuffer out;

  ErrorCode code = askar_key_crypto_box_seal(handle, message, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyCryptoBoxSealOpen(jsi::Runtime &rt, jsi::Object options) {
  auto handle = jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto ciphertext = jsiToValue<ByteBuffer>(rt, options, "ciphertext");

  SecretBuffer out;

  ErrorCode code = raskar_key_crypto_box_seal_open(handle, ciphertext, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

} // namespace ariesAskar
