#include <ariesAskar.h>
#include <include/libaries_askar.h>

using namespace turboModuleUtility;

namespace ariesAskar {

jsi::Value version(jsi::Runtime &rt, jsi::Object options) {
    return jsi::String::createFromAscii(rt, askar_version());
};

jsi::Value getCurrentError(jsi::Runtime &rt, jsi::Object options) {
    const char* error;
    askar_get_current_error(&error);
    return jsi::String::createFromAscii(rt, error);
};

jsi::Value storeOpen(jsi::Runtime &rt, jsi::Object options) {
    std::string specUri =
        turboModuleUtility::jsiToValue<std::string>(rt, options, "specUri");
    std::string keyMethod =
        turboModuleUtility::jsiToValue<std::string>(rt, options, "keyMethod", true);
    std::string passKey =
        turboModuleUtility::jsiToValue<std::string>(rt, options, "passKey", true);
    std::string profile =
        turboModuleUtility::jsiToValue<std::string>(rt, options, "profile", true);

    jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
    State *state = new State(&cb);
    state->rt = &rt;
    
    ErrorCode code = askar_store_open(specUri.c_str(),
                           keyMethod.length() ? keyMethod.c_str() : nullptr,
                           passKey.length() ? passKey.c_str() : nullptr,
                           profile.length() ? profile.c_str() : nullptr,
                           turboModuleUtility::callbackWithResponse, 
                           CallbackId(state));

    turboModuleUtility::handleError(rt, code);
    

    return jsi::Value::null();
}

jsi::Value storeProvision(jsi::Runtime &rt, jsi::Object options) {
    std::string specUri =
        turboModuleUtility::jsiToValue<std::string>(rt, options, "specUri");
    std::string keyMethod =
        turboModuleUtility::jsiToValue<std::string>(rt, options, "keyMethod", true);
    std::string passKey =
        turboModuleUtility::jsiToValue<std::string>(rt, options, "passKey", true);
    std::string profile =
        turboModuleUtility::jsiToValue<std::string>(rt, options, "profile", true);
    int8_t recreate =
        turboModuleUtility::jsiToValue<int8_t>(rt, options, "recreate");

    jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
    State *state = new State(&cb);
    state->rt = &rt;
    
    ErrorCode code = askar_store_provision(specUri.c_str(),
                           keyMethod.length() ? keyMethod.c_str() : nullptr,
                           passKey.length() ? passKey.c_str() : nullptr,
                           profile.length() ? profile.c_str() : nullptr,
                           recreate,
                           turboModuleUtility::callbackWithResponse, 
                           CallbackId(state));
    turboModuleUtility::handleError(rt, code);
    

    return jsi::Value::null();
}

jsi::Value storeGenerateRawKey(jsi::Runtime &rt, jsi::Object options) {
    ByteBuffer seed =
        turboModuleUtility::jsiToValue<ByteBuffer>(rt, options, "seed", true);
    
    const char* out;
    ErrorCode code = askar_store_generate_raw_key(seed, &out);
    turboModuleUtility::handleError(rt, code);
    
    return jsi::String::createFromAscii(rt, out);
}

jsi::Value storeClose(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = 
        turboModuleUtility::jsiToValue<int64_t>(rt, options, "storeHandle");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_close(handle, turboModuleUtility::callback, CallbackId(state));
    turboModuleUtility::handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeCreateProfile(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = 
        turboModuleUtility::jsiToValue<int64_t>(rt, options, "storeHandle");
  std::string profile = 
        turboModuleUtility::jsiToValue<std::string>(rt, options, "profile");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_create_profile(handle, profile.c_str(), turboModuleUtility::callbackWithResponse, CallbackId(state));
    turboModuleUtility::handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeGetProfileName(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = 
        turboModuleUtility::jsiToValue<int64_t>(rt, options, "storeHandle");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_get_profile_name(handle, turboModuleUtility::callbackWithResponse, CallbackId(state));
    turboModuleUtility::handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeRekey(jsi::Runtime &rt, jsi::Object options) {
  int64_t handle = 
        turboModuleUtility::jsiToValue<int64_t>(rt, options, "storeHandle");
  std::string keyMethod = 
        turboModuleUtility::jsiToValue<std::string>(rt, options, "keyMethod");
  std::string passKey = 
        turboModuleUtility::jsiToValue<std::string>(rt, options, "passKey");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_get_profile_name(StoreHandle(handle), turboModuleUtility::callbackWithResponse, CallbackId(state));
    turboModuleUtility::handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeRemove(jsi::Runtime &rt, jsi::Object options) {
  std::string specUri = 
        turboModuleUtility::jsiToValue<std::string>(rt, options, "specUri");

  jsi::Function cb = options.getPropertyAsFunction(rt, "cb");
  State *state = new State(&cb);
  state->rt = &rt;

  ErrorCode code = askar_store_remove(specUri.c_str(), turboModuleUtility::callbackWithResponse, CallbackId(state));
    turboModuleUtility::handleError(rt, code);

  return jsi::Value::null();
}

jsi::Value storeRemoveProfile(jsi::Runtime &rt, jsi::Object options) {
  return jsi::Value::null();
}

}
