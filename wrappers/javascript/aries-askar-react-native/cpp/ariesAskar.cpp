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
  auto entryListHandle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");

  int32_t out;

  ErrorCode code = askar_entry_list_count(entryListHandle, &out);
  handleError(rt, code);

  return jsi::Value(out);
};
jsi::Value entryListFree(jsi::Runtime &rt, jsi::Object options) {
  auto entryListHandle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");

  askar_entry_list_free(entryListHandle);

  return jsi::Value::null();
}

jsi::Value entryListGetCategory(jsi::Runtime &rt, jsi::Object options) {
  auto entryListHandle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");
  auto index = jsiToValue<int32_t>(rt, options, "index");

  const char *out;

  ErrorCode code = askar_entry_list_get_category(entryListHandle, index, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value entryListGetTags(jsi::Runtime &rt, jsi::Object options) {
  auto entryListHandle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");
  auto index = jsiToValue<int32_t>(rt, options, "index");

  const char *out;

  ErrorCode code = askar_entry_list_get_tags(entryListHandle, index, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out ? out : "{}");
}

jsi::Value entryListGetValue(jsi::Runtime &rt, jsi::Object options) {
  auto entryListHandle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");
  auto index = jsiToValue<int32_t>(rt, options, "index");

  SecretBuffer out;

  ErrorCode code = askar_entry_list_get_value(entryListHandle, index, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value entryListGetName(jsi::Runtime &rt, jsi::Object options) {
  auto entryListHandle =
      jsiToValue<EntryListHandle>(rt, options, "entryListHandle");
  auto index = jsiToValue<int32_t>(rt, options, "index");

  const char *out;

  ErrorCode code = askar_entry_list_get_name(entryListHandle, index, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value storeOpen(jsi::Runtime &rt, jsi::Object options) {
  auto specUri = jsiToValue<std::string>(rt, options, "specUri");
  auto keyMethod = jsiToValue<std::string>(rt, options, "keyMethod", true);
  auto passKey = jsiToValue<std::string>(rt, options, "passKey", true);
  auto profile = jsiToValue<std::string>(rt, options, "profile", true);

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
  auto specUri = jsiToValue<std::string>(rt, options, "specUri");
  auto keyMethod = jsiToValue<std::string>(rt, options, "keyMethod", true);
  auto passKey = jsiToValue<std::string>(rt, options, "passKey", true);
  auto profile = jsiToValue<std::string>(rt, options, "profile", true);
  auto recreate = jsiToValue<int8_t>(rt, options, "recreate");

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
  auto seed = jsiToValue<ByteBuffer>(rt, options, "seed", true);

  const char *out;
  ErrorCode code = askar_store_generate_raw_key(seed, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value storeClose(jsi::Runtime &rt, jsi::Object options) {
  auto storeHandle = jsiToValue<int64_t>(rt, options, "storeHandle");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_close(storeHandle, callback, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeCreateProfile(jsi::Runtime &rt, jsi::Object options) {
  auto storeHandle = jsiToValue<int64_t>(rt, options, "storeHandle");
  auto profile = jsiToValue<std::string>(rt, options, "profile", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_create_profile(
      storeHandle, profile.length() ? profile.c_str() : nullptr,
      callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeGetProfileName(jsi::Runtime &rt, jsi::Object options) {
  auto storeHandle = jsiToValue<int64_t>(rt, options, "storeHandle");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_get_profile_name(
      storeHandle, callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeRekey(jsi::Runtime &rt, jsi::Object options) {
  auto storeHandle = jsiToValue<int64_t>(rt, options, "storeHandle");
  auto keyMethod = jsiToValue<std::string>(rt, options, "keyMethod");
  auto passKey = jsiToValue<std::string>(rt, options, "passKey");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_get_profile_name(
      storeHandle, callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeRemove(jsi::Runtime &rt, jsi::Object options) {
  auto specUri = jsiToValue<std::string>(rt, options, "specUri");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_remove(specUri.c_str(), callbackWithResponse,
                                      CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeRemoveProfile(jsi::Runtime &rt, jsi::Object options) {
  auto storeHandle = jsiToValue<int64_t>(rt, options, "storeHandle");
  auto profile = jsiToValue<std::string>(rt, options, "profile");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_remove_profile(
      storeHandle, profile.c_str(), callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionClose(jsi::Runtime &rt, jsi::Object options) {
  auto sessionHandle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  int8_t commit = jsiToValue<int8_t>(rt, options, "commit");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_session_close(sessionHandle, commit, callback, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionCount(jsi::Runtime &rt, jsi::Object options) {
  auto sessionHandle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  auto category = jsiToValue<std::string>(rt, options, "category");
  auto tagFilter = jsiToValue<std::string>(rt, options, "tagFilter", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_session_count(sessionHandle, category.c_str(),
                          tagFilter.length() ? tagFilter.c_str() : nullptr,
                          callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionFetch(jsi::Runtime &rt, jsi::Object options) {
  auto sessionHandle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  auto category = jsiToValue<std::string>(rt, options, "category");
  auto name = jsiToValue<std::string>(rt, options, "name");
  int8_t forUpdate = jsiToValue<int8_t>(rt, options, "forUpdate");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_session_fetch(sessionHandle, category.c_str(), name.c_str(),
                          forUpdate, callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionFetchAll(jsi::Runtime &rt, jsi::Object options) {
  auto sessionHandle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  auto category = jsiToValue<std::string>(rt, options, "category");
  auto tagFilter = jsiToValue<std::string>(rt, options, "tagFilter", true);
  int64_t limit = jsiToValue<int64_t>(rt, options, "limit", true);
  int8_t forUpdate = jsiToValue<int8_t>(rt, options, "forUpdate");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_session_fetch_all(
      sessionHandle, category.c_str(),
      tagFilter.length() ? tagFilter.c_str() : nullptr, limit, forUpdate,
      callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionFetchAllKeys(jsi::Runtime &rt, jsi::Object options) {
  auto sessionHandle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm", true);
  auto thumbprint = jsiToValue<std::string>(rt, options, "thumbprint", true);
  auto tagFilter = jsiToValue<std::string>(rt, options, "tagFilter", true);
  auto limit = jsiToValue<int64_t>(rt, options, "limit", true);
  auto forUpdate = jsiToValue<int8_t>(rt, options, "forUpdate");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_session_fetch_all_keys(
      sessionHandle, algorithm.length() ? algorithm.c_str() : nullptr,
      thumbprint.length() ? thumbprint.c_str() : nullptr,
      tagFilter.length() ? tagFilter.c_str() : nullptr, limit, forUpdate,
      callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionFetchKey(jsi::Runtime &rt, jsi::Object options) {
  auto sessionHandle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");
  auto forUpdate = jsiToValue<int8_t>(rt, options, "forUpdate");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_session_fetch_key(sessionHandle, name.c_str(), forUpdate,
                              callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionInsertKey(jsi::Runtime &rt, jsi::Object options) {
  auto sessionHandle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");
  auto metadata = jsiToValue<std::string>(rt, options, "metadata", true);
  auto tags = jsiToValue<std::string>(rt, options, "tags", true);
  auto expiryMs = jsiToValue<int64_t>(rt, options, "expiryMs", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_session_insert_key(sessionHandle, localKeyHandle, name.c_str(),
                               metadata.length() ? metadata.c_str() : nullptr,
                               tags.length() ? tags.c_str() : nullptr, expiryMs,
                               callback, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionRemoveAll(jsi::Runtime &rt, jsi::Object options) {
  auto sessionHandle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  auto category = jsiToValue<std::string>(rt, options, "category");
  auto tagFilter = jsiToValue<std::string>(rt, options, "tagFilter", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_session_remove_all(sessionHandle, category.c_str(),
                               tagFilter.length() ? tagFilter.c_str() : nullptr,
                               callbackWithResponse, CallbackId(state));

  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionRemoveKey(jsi::Runtime &rt, jsi::Object options) {
  auto sessionHandle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_session_remove_key(sessionHandle, name.c_str(),
                                            callback, CallbackId(state));

  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionStart(jsi::Runtime &rt, jsi::Object options) {
  auto storeHandle = jsiToValue<int64_t>(rt, options, "storeHandle");
  auto profile = jsiToValue<std::string>(rt, options, "profile", true);
  int8_t asTransaction = jsiToValue<int8_t>(rt, options, "asTransaction");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_session_start(
      storeHandle, profile.length() ? profile.c_str() : nullptr, asTransaction,
      callbackWithResponse, CallbackId(state));

  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionUpdate(jsi::Runtime &rt, jsi::Object options) {
  auto sessionHandle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  int8_t operation = jsiToValue<int8_t>(rt, options, "operation");
  auto category = jsiToValue<std::string>(rt, options, "category");
  auto name = jsiToValue<std::string>(rt, options, "name");
  auto tags = jsiToValue<std::string>(rt, options, "tags", true);
  auto value = jsiToValue<ByteBuffer>(rt, options, "value", true);
  int64_t expiryMs = jsiToValue<int64_t>(rt, options, "expiryMs", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_session_update(sessionHandle, operation,
                                        category.c_str(), name.c_str(), value,
                                        tags.length() ? tags.c_str() : nullptr,
                                        expiryMs, callback, CallbackId(state));

  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value sessionUpdateKey(jsi::Runtime &rt, jsi::Object options) {
  auto sessionHandle = jsiToValue<int64_t>(rt, options, "sessionHandle");
  auto name = jsiToValue<std::string>(rt, options, "name");
  auto tags = jsiToValue<std::string>(rt, options, "tags", true);
  auto metadata = jsiToValue<std::string>(rt, options, "metadata", true);
  auto expiryMs = jsiToValue<int64_t>(rt, options, "expiryMs", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_session_update_key(sessionHandle, name.c_str(),
                               metadata.length() ? metadata.c_str() : nullptr,
                               tags.length() ? tags.c_str() : nullptr, expiryMs,
                               callback, CallbackId(state));

  handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value scanStart(jsi::Runtime &rt, jsi::Object options) {
  auto storeHandle = jsiToValue<int64_t>(rt, options, "storeHandle");
  auto category = jsiToValue<std::string>(rt, options, "category");

  auto tagFilter = jsiToValue<std::string>(rt, options, "tagFilter", true);
  auto profile = jsiToValue<std::string>(rt, options, "profile", true);
  auto offset = jsiToValue<int64_t>(rt, options, "offset", true);
  auto limit = jsiToValue<int64_t>(rt, options, "limit", true);

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_scan_start(
      storeHandle, profile.length() ? profile.c_str() : nullptr,
      category.c_str(), tagFilter.length() ? tagFilter.c_str() : nullptr,
      offset, limit, callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
};

jsi::Value scanNext(jsi::Runtime &rt, jsi::Object options) {
  auto scanHandle = jsiToValue<int64_t>(rt, options, "scanHandle");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code =
      askar_scan_next(scanHandle, callbackWithResponse, CallbackId(state));
  handleError(rt, code);

  return jsi::Value::null();
};

jsi::Value scanFree(jsi::Runtime &rt, jsi::Object options) {
  auto scanHandle = jsiToValue<int64_t>(rt, options, "scanHandle");

  ErrorCode code = askar_scan_free(scanHandle);
  handleError(rt, code);

  return jsi::Value::null();
};

jsi::Value keyFromJwk(jsi::Runtime &rt, jsi::Object options) {
  auto jwk = jsiToValue<ByteBuffer>(rt, options, "jwk");

  LocalKeyHandle out;

  ErrorCode code = askar_key_from_jwk(jwk, &out);
  handleError(rt, code);

  auto serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyFromKeyExchange(jsi::Runtime &rt, jsi::Object options) {
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm");
  auto skHandle = jsiToValue<LocalKeyHandle>(rt, options, "skHandle");
  auto pkHandle = jsiToValue<LocalKeyHandle>(rt, options, "pkHandle");

  LocalKeyHandle out;

  ErrorCode code =
      askar_key_from_key_exchange(algorithm.c_str(), skHandle, pkHandle, &out);
  handleError(rt, code);

  auto serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyFromPublicBytes(jsi::Runtime &rt, jsi::Object options) {
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm");
  auto publicKey = jsiToValue<ByteBuffer>(rt, options, "publicKey");

  LocalKeyHandle out;

  ErrorCode code =
      askar_key_from_public_bytes(algorithm.c_str(), publicKey, &out);
  handleError(rt, code);

  auto serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyFromSecretBytes(jsi::Runtime &rt, jsi::Object options) {
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm");
  auto secretKey = jsiToValue<ByteBuffer>(rt, options, "secretKey");

  LocalKeyHandle out;

  ErrorCode code =
      askar_key_from_secret_bytes(algorithm.c_str(), secretKey, &out);
  handleError(rt, code);

  auto serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyFromSeed(jsi::Runtime &rt, jsi::Object options) {
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm");
  auto seed = jsiToValue<ByteBuffer>(rt, options, "seed");
  auto method = jsiToValue<std::string>(rt, options, "method");

  LocalKeyHandle out;

  ErrorCode code =
      askar_key_from_seed(algorithm.c_str(), seed, method.c_str(), &out);
  handleError(rt, code);

  auto serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyGenerate(jsi::Runtime &rt, jsi::Object options) {
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm");
  //  auto ephemeral = jsiToValue<int8_t>(rt, options, "ephemeral");
  auto ephemeral = 0;

  LocalKeyHandle out;

  ErrorCode code = askar_key_generate(algorithm.c_str(), ephemeral, &out);
  handleError(rt, code);

  auto serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyGetAlgorithm(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  const char *out;

  ErrorCode code = askar_key_get_algorithm(localKeyHandle, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value keyGetEphemeral(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  int8_t out;

  ErrorCode code = askar_key_get_ephemeral(localKeyHandle, &out);
  handleError(rt, code);

  return jsi::Value(int(out));
}

jsi::Value keyGetJwkPublic(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm");

  const char *out;

  ErrorCode code =
      askar_key_get_jwk_public(localKeyHandle, algorithm.c_str(), &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value keyGetJwkSecret(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  SecretBuffer out;

  ErrorCode code = askar_key_get_jwk_secret(localKeyHandle, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyGetJwkThumbprint(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm");

  const char *out;

  ErrorCode code =
      askar_key_get_jwk_thumbprint(localKeyHandle, algorithm.c_str(), &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value keyGetPublicBytes(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  SecretBuffer out;

  ErrorCode code = askar_key_get_public_bytes(localKeyHandle, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyGetSecretBytes(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  SecretBuffer out;

  ErrorCode code = askar_key_get_secret_bytes(localKeyHandle, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keySignMessage(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto message = jsiToValue<ByteBuffer>(rt, options, "message");
  auto sigType = jsiToValue<std::string>(rt, options, "sigType", true);

  SecretBuffer out;

  ErrorCode code = askar_key_sign_message(
      localKeyHandle, message, sigType.length() ? sigType.c_str() : nullptr,
      &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyUnwrapKey(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm");
  auto ciphertext = jsiToValue<ByteBuffer>(rt, options, "ciphertext");
  auto nonce = jsiToValue<ByteBuffer>(rt, options, "nonce", true);
  auto tag = jsiToValue<ByteBuffer>(rt, options, "tag", true);

  LocalKeyHandle out;

  ErrorCode code = askar_key_unwrap_key(localKeyHandle, algorithm.c_str(),
                                        ciphertext, nonce, tag, &out);
  handleError(rt, code);

  auto serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyVerifySignature(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto message = jsiToValue<ByteBuffer>(rt, options, "message");
  auto signature = jsiToValue<ByteBuffer>(rt, options, "signature");
  auto sigType = jsiToValue<std::string>(rt, options, "sigType", true);

  int8_t out;

  ErrorCode code = askar_key_verify_signature(
      localKeyHandle, message, signature,
      sigType.length() ? sigType.c_str() : nullptr, &out);
  handleError(rt, code);

  return jsi::Value(int(out));
}

jsi::Value keyWrapKey(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto other = jsiToValue<LocalKeyHandle>(rt, options, "other");
  auto nonce = jsiToValue<ByteBuffer>(rt, options, "nonce", true);

  EncryptedBuffer out;

  ErrorCode code = askar_key_wrap_key(localKeyHandle, other, nonce, &out);
  handleError(rt, code);

  auto object = jsi::Object(rt);
  object.setProperty(rt, "buffer", secretBufferToArrayBuffer(rt, out.buffer));
  object.setProperty(rt, "tagPos", int(out.tag_pos));
  object.setProperty(rt, "noncePos", int(out.nonce_pos));

  return object;
}

jsi::Value keyConvert(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm");

  LocalKeyHandle out;

  ErrorCode code = askar_key_convert(localKeyHandle, algorithm.c_str(), &out);
  handleError(rt, code);

  auto serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
};

jsi::Value keyFree(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  askar_key_free(localKeyHandle);

  return jsi::Value::null();
};

jsi::Value keyCryptoBox(jsi::Runtime &rt, jsi::Object options) {
  auto recipientKey = jsiToValue<LocalKeyHandle>(rt, options, "recipientKey");
  auto senderKey = jsiToValue<LocalKeyHandle>(rt, options, "senderKey");
  auto message = jsiToValue<ByteBuffer>(rt, options, "message");
  auto nonce = jsiToValue<ByteBuffer>(rt, options, "nonce");

  SecretBuffer out;

  ErrorCode code =
      askar_key_crypto_box(recipientKey, senderKey, message, nonce, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyCryptoBoxOpen(jsi::Runtime &rt, jsi::Object options) {
  auto recipientKey = jsiToValue<LocalKeyHandle>(rt, options, "recipientKey");
  auto senderKey = jsiToValue<LocalKeyHandle>(rt, options, "senderKey");
  auto message = jsiToValue<ByteBuffer>(rt, options, "message");
  auto nonce = jsiToValue<ByteBuffer>(rt, options, "nonce");

  SecretBuffer out;

  ErrorCode code =
      askar_key_crypto_box_open(recipientKey, senderKey, message, nonce, &out);
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
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto message = jsiToValue<ByteBuffer>(rt, options, "message");

  SecretBuffer out;

  ErrorCode code = askar_key_crypto_box_seal(localKeyHandle, message, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyCryptoBoxSealOpen(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto ciphertext = jsiToValue<ByteBuffer>(rt, options, "ciphertext");

  SecretBuffer out;

  ErrorCode code =
      askar_key_crypto_box_seal_open(localKeyHandle, ciphertext, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyDeriveEcdh1pu(jsi::Runtime &rt, jsi::Object options) {
  auto ephemeralKey = jsiToValue<LocalKeyHandle>(rt, options, "ephemeralKey");
  auto senderKey = jsiToValue<LocalKeyHandle>(rt, options, "senderKey");
  auto recipientKey = jsiToValue<LocalKeyHandle>(rt, options, "recipientKey");
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm");
  auto algId = jsiToValue<ByteBuffer>(rt, options, "algId");
  auto apu = jsiToValue<ByteBuffer>(rt, options, "apu");
  auto apv = jsiToValue<ByteBuffer>(rt, options, "apv");
  auto ccTag = jsiToValue<ByteBuffer>(rt, options, "ccTag", true);
  auto receive = jsiToValue<int8_t>(rt, options, "receive");

  LocalKeyHandle out;

  ErrorCode code = askar_key_derive_ecdh_1pu(algorithm.c_str(), ephemeralKey,
                                             senderKey, recipientKey, algId,
                                             apu, apv, ccTag, receive, &out);
  handleError(rt, code);

  auto serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyDeriveEcdhEs(jsi::Runtime &rt, jsi::Object options) {
  auto ephemeralKey = jsiToValue<LocalKeyHandle>(rt, options, "ephemeralKey");
  auto recipientKey = jsiToValue<LocalKeyHandle>(rt, options, "recipientKey");
  auto algorithm = jsiToValue<std::string>(rt, options, "algorithm");
  auto algId = jsiToValue<ByteBuffer>(rt, options, "algId");
  auto apu = jsiToValue<ByteBuffer>(rt, options, "apu");
  auto apv = jsiToValue<ByteBuffer>(rt, options, "apv");
  auto receive = jsiToValue<int8_t>(rt, options, "receive");

  LocalKeyHandle out;

  ErrorCode code =
      askar_key_derive_ecdh_es(algorithm.c_str(), ephemeralKey, recipientKey,
                               algId, apu, apv, receive, &out);
  handleError(rt, code);

  auto serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

jsi::Value keyAeadDecrypt(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto ciphertext = jsiToValue<ByteBuffer>(rt, options, "ciphertext");
  auto nonce = jsiToValue<ByteBuffer>(rt, options, "nonce");
  auto tag = jsiToValue<ByteBuffer>(rt, options, "tag", true);
  auto aad = jsiToValue<ByteBuffer>(rt, options, "aad", true);

  SecretBuffer out;

  ErrorCode code =
      askar_key_aead_decrypt(localKeyHandle, ciphertext, nonce, tag, aad, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyAeadEncrypt(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto message = jsiToValue<ByteBuffer>(rt, options, "message");
  auto nonce = jsiToValue<ByteBuffer>(rt, options, "nonce", true);
  auto aad = jsiToValue<ByteBuffer>(rt, options, "aad", true);

  EncryptedBuffer out;

  ErrorCode code =
      askar_key_aead_encrypt(localKeyHandle, message, nonce, aad, &out);
  handleError(rt, code);

  auto object = jsi::Object(rt);
  object.setProperty(rt, "buffer", secretBufferToArrayBuffer(rt, out.buffer));
  object.setProperty(rt, "tagPos", int(out.tag_pos));
  object.setProperty(rt, "noncePos", int(out.nonce_pos));

  return object;
}

jsi::Value keyAeadGetPadding(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");
  auto messageLength = jsiToValue<int64_t>(rt, options, "msgLen");

  int32_t out;

  ErrorCode code =
      askar_key_aead_get_padding(localKeyHandle, messageLength, &out);
  handleError(rt, code);

  return jsi::Value(out);
}

jsi::Value keyAeadGetParams(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  AeadParams out;

  ErrorCode code = askar_key_aead_get_params(localKeyHandle, &out);
  handleError(rt, code);

  auto object = jsi::Object(rt);
  object.setProperty(rt, "nonceLength", out.nonce_length);
  object.setProperty(rt, "tagLength", out.tag_length);

  return object;
}

jsi::Value keyAeadRandomNonce(jsi::Runtime &rt, jsi::Object options) {
  auto localKeyHandle =
      jsiToValue<LocalKeyHandle>(rt, options, "localKeyHandle");

  SecretBuffer out;

  ErrorCode code = askar_key_aead_random_nonce(localKeyHandle, &out);
  handleError(rt, code);

  return secretBufferToArrayBuffer(rt, out);
}

jsi::Value keyEntryListCount(jsi::Runtime &rt, jsi::Object options) {
  auto keyEntryListHandle =
      jsiToValue<KeyEntryListHandle>(rt, options, "keyEntryListHandle");

  int32_t out;

  ErrorCode code = askar_key_entry_list_count(keyEntryListHandle, &out);
  handleError(rt, code);

  return jsi::Value(out);
}

jsi::Value keyEntryListFree(jsi::Runtime &rt, jsi::Object options) {
  auto keyEntryListHandle =
      jsiToValue<KeyEntryListHandle>(rt, options, "keyEntryListHandle");

  int32_t out;

  ErrorCode code = askar_key_entry_list_count(keyEntryListHandle, &out);
  handleError(rt, code);

  return jsi::Value(out);
}

jsi::Value keyEntryListGetAlgorithm(jsi::Runtime &rt, jsi::Object options) {
  auto keyEntryListHandle =
      jsiToValue<KeyEntryListHandle>(rt, options, "keyEntryListHandle");
  auto index = jsiToValue<int32_t>(rt, options, "index");

  const char *out;

  ErrorCode code =
      askar_key_entry_list_get_algorithm(keyEntryListHandle, index, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value keyEntryListGetMetadata(jsi::Runtime &rt, jsi::Object options) {
  auto keyEntryListHandle =
      jsiToValue<KeyEntryListHandle>(rt, options, "keyEntryListHandle");
  auto index = jsiToValue<int32_t>(rt, options, "index");

  const char *out;

  ErrorCode code =
      askar_key_entry_list_get_metadata(keyEntryListHandle, index, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value keyEntryListGetName(jsi::Runtime &rt, jsi::Object options) {
  auto keyEntryListHandle =
      jsiToValue<KeyEntryListHandle>(rt, options, "keyEntryListHandle");
  auto index = jsiToValue<int32_t>(rt, options, "index");

  const char *out;

  ErrorCode code =
      askar_key_entry_list_get_name(keyEntryListHandle, index, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out);
}

jsi::Value keyEntryListGetTags(jsi::Runtime &rt, jsi::Object options) {
  auto keyEntryListHandle =
      jsiToValue<KeyEntryListHandle>(rt, options, "keyEntryListHandle");
  auto index = jsiToValue<int32_t>(rt, options, "index");

  const char *out;

  ErrorCode code =
      askar_key_entry_list_get_tags(keyEntryListHandle, index, &out);
  handleError(rt, code);

  return jsi::String::createFromAscii(rt, out ? out : "{}");
}

jsi::Value keyEntryListLoadLocal(jsi::Runtime &rt, jsi::Object options) {
  auto keyEntryListHandle =
      jsiToValue<KeyEntryListHandle>(rt, options, "keyEntryListHandle");
  auto index = jsiToValue<int32_t>(rt, options, "index");

  LocalKeyHandle out;

  ErrorCode code =
      askar_key_entry_list_load_local(keyEntryListHandle, index, &out);
  handleError(rt, code);

  auto serializedPointer = std::to_string(intptr_t(out._0));
  jsi::String pointer = jsi::String::createFromAscii(rt, serializedPointer);
  return pointer;
}

} // namespace ariesAskar
