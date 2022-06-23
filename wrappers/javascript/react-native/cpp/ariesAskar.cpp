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
    askar_store_generate_raw_key(seed, &out);
    
    return jsi::String::createFromAscii(rt, out);
}



}
