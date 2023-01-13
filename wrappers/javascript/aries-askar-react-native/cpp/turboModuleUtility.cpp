#include <vector>

#include <turboModuleUtility.h>

namespace turboModuleUtility {

using byteVector = std::vector<uint8_t>;

std::shared_ptr<react::CallInvoker> invoker;

void registerTurboModule(jsi::Runtime &rt,
                         std::shared_ptr<react::CallInvoker> jsCallInvoker) {
  // Setting the callInvoker for async code
  invoker = jsCallInvoker;
  // Create a TurboModuleRustHostObject
  auto instance = std::make_shared<TurboModuleHostObject>(rt);
  // Create a JS equivalent object of the instance
  jsi::Object jsInstance = jsi::Object::createFromHostObject(rt, instance);
  // Register the object on global
  rt.global().setProperty(rt, "_aries_askar", std::move(jsInstance));
}

void assertValueIsObject(jsi::Runtime &rt, const jsi::Value *val) {
  val->asObject(rt);
}
void handleError(jsi::Runtime &rt, ErrorCode code) {
  if (code == ErrorCode::Success)
    return;

  jsi::Value errorMessage = ariesAskar::getCurrentError(rt, jsi::Object(rt));

  jsi::Object JSON = rt.global().getPropertyAsObject(rt, "JSON");
  jsi::Function JSONParse = JSON.getPropertyAsFunction(rt, "parse");
  jsi::Object parsedErrorObject =
      JSONParse.call(rt, errorMessage).getObject(rt);
  jsi::Value message = parsedErrorObject.getProperty(rt, "message");
  if (message.isString()) {
    throw jsi::JSError(rt, message.getString(rt).utf8(rt));
  }
  throw jsi::JSError(rt, "Could not get message with code: " +
                             std::to_string(code));
};

void callback(CallbackId result, ErrorCode code) {
  invoker->invokeAsync([result, code]() {
    State *_state = reinterpret_cast<State *>(result);
    State *state = static_cast<State *>(_state);
    jsi::Function *cb = &state->cb;
    jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);
    cb->call(*rt, int(code));
  });
  //  delete state;
}

// Session, Store and Scan Handle
template <>
void callbackWithResponse(CallbackId result, ErrorCode code, size_t response) {
  invoker->invokeAsync([result, code, response]() {
    State *_state = reinterpret_cast<State *>(result);
    State *state = static_cast<State *>(_state);
    jsi::Function *cb = &state->cb;
    jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);
    cb->call(*rt, int(code), int(response));
  });
}

template <>
void callbackWithResponse(CallbackId result, ErrorCode code,
                          const char *response) {
  invoker->invokeAsync([result, code, response]() {
    State *_state = reinterpret_cast<State *>(result);
    State *state = static_cast<State *>(_state);
    jsi::Function *cb = &state->cb;
    jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);
    jsi::String serializedResponse =
        jsi::String::createFromAscii(*rt, response ? response : "PANIC");
    cb->call(*rt, int(code), serializedResponse);
  });
}

template <>
void callbackWithResponse(CallbackId result, ErrorCode code,
                          EntryListHandle response) {
  invoker->invokeAsync([result, code, response]() {
    State *_state = reinterpret_cast<State *>(result);
    State *state = static_cast<State *>(_state);
    jsi::Function *cb = &state->cb;
    jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);

    std::string serializedPointer = std::to_string(intptr_t(response._0));
    jsi::String pointer = jsi::String::createFromAscii(*rt, serializedPointer);

    cb->call(*rt, int(code), serializedPointer);
  });
}

template <>
void callbackWithResponse(CallbackId result, ErrorCode code,
                          KeyEntryListHandle response) {
  invoker->invokeAsync([result, code, response]() {
    State *_state = reinterpret_cast<State *>(result);
    State *state = static_cast<State *>(_state);
    jsi::Function *cb = &state->cb;
    jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);

    std::string serializedPointer = std::to_string(intptr_t(response._0));
    jsi::String pointer = jsi::String::createFromAscii(*rt, serializedPointer);

    cb->call(*rt, int(code), serializedPointer);
  });
}

template <>
void callbackWithResponse(CallbackId result, ErrorCode code, int8_t response) {
  invoker->invokeAsync([result, code, response]() {
    State *_state = reinterpret_cast<State *>(result);
    State *state = static_cast<State *>(_state);
    jsi::Function *cb = &state->cb;
    jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);
    cb->call(*rt, int(code), int(response));
  });
}

template <>
void callbackWithResponse(CallbackId result, ErrorCode code, int64_t response) {
  invoker->invokeAsync([result, code, response]() {
    State *_state = reinterpret_cast<State *>(result);
    State *state = static_cast<State *>(_state);
    jsi::Function *cb = &state->cb;
    jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);
    cb->call(*rt, int(code), int(response));
  });
}

template <>
uint8_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
                   bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return 0;

  if (value.isNumber())
    return value.asNumber();

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
};

template <>
int8_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
                  bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return 0;

  if (value.isNumber())
    return value.asNumber();

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
};

template <>
std::string jsiToValue<std::string>(jsi::Runtime &rt, jsi::Object &options,
                                    const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if ((value.isNull() || value.isUndefined()) && optional)
    return std::string();

  if (value.isString()) {
    auto x = value.asString(rt).utf8(rt);
    return x;
  }

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "string");
}

template <>
int64_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
                   bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return 0;

  if (value.isNumber())
    return value.asNumber();

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
};

template <>
uint64_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
                    bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return 0;

  if (value.isNumber())
    return value.asNumber();

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
};

template <>
int32_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
                   bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return 0;

  if (value.isNumber())
    return value.asNumber();

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
};

template <>
uint32_t jsiToValue(jsi::Runtime &rt, jsi::Object &options, const char *name,
                    bool optional) {
  jsi::Value value = options.getProperty(rt, name);
  if ((value.isNull() || value.isUndefined()) && optional)
    return 0;

  if (value.isNumber())
    return value.asNumber();

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
};

template <>
KeyEntryListHandle jsiToValue(jsi::Runtime &rt, jsi::Object &options,
                              const char *name, bool optional) {
  std::string handle = jsiToValue<std::string>(rt, options, name, optional);
  FfiKeyEntryList *ffiKeyEntryListPtr =
      reinterpret_cast<FfiKeyEntryList *>(std::stol(handle));
  KeyEntryListHandle keyEntryListHandle =
      KeyEntryListHandle{._0 = ffiKeyEntryListPtr};

  return keyEntryListHandle;
};

template <>
EntryListHandle jsiToValue(jsi::Runtime &rt, jsi::Object &options,
                           const char *name, bool optional) {
  std::string handle = jsiToValue<std::string>(rt, options, name, optional);
  FfiEntryList *ffiEntryListPtr =
      reinterpret_cast<FfiEntryList *>(std::stol(handle));
  EntryListHandle entryListHandle = EntryListHandle{._0 = ffiEntryListPtr};

  return entryListHandle;
};

template <>
LocalKeyHandle jsiToValue(jsi::Runtime &rt, jsi::Object &options,
                          const char *name, bool optional) {
  std::string handle = jsiToValue<std::string>(rt, options, name, optional);
  LocalKey *localKeyPtr = reinterpret_cast<LocalKey *>(std::stol(handle));
  LocalKeyHandle localKeyHandle = LocalKeyHandle{._0 = localKeyPtr};

  return localKeyHandle;
};

template <>
std::vector<int32_t>
jsiToValue<std::vector<int32_t>>(jsi::Runtime &rt, jsi::Object &options,
                                 const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArray(rt)) {
    std::vector<int32_t> vec = {};
    jsi::Array arr = value.asObject(rt).asArray(rt);
    size_t length = arr.length(rt);
    for (int i = 0; i < length; i++) {
      jsi::Value element = arr.getValueAtIndex(rt, i);
      if (element.isNumber()) {
        vec.push_back(element.asNumber());
      } else {
        throw jsi::JSError(rt, errorPrefix + name + errorInfix + "number");
      }
    }
    return vec;
  }

  if (optional)
    return {};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Array<number>");
}

template <>
ByteBuffer jsiToValue<ByteBuffer>(jsi::Runtime &rt, jsi::Object &options,
                                  const char *name, bool optional) {
  jsi::Value value = options.getProperty(rt, name);

  if (value.isObject() && value.asObject(rt).isArrayBuffer(rt)) {
    jsi::ArrayBuffer arrayBuffer = value.getObject(rt).getArrayBuffer(rt);
    return ByteBuffer{int(arrayBuffer.size(rt)), arrayBuffer.data(rt)};
  }

  if (optional)
    return ByteBuffer{0, 0};

  throw jsi::JSError(rt, errorPrefix + name + errorInfix + "Uint8Array");
}

jsi::ArrayBuffer byteBufferToArrayBuffer(jsi::Runtime &rt, ByteBuffer bb) {
  jsi::ArrayBuffer arrayBuffer = rt.global()
                                     .getPropertyAsFunction(rt, "ArrayBuffer")
                                     .callAsConstructor(rt, int(bb.len))
                                     .getObject(rt)
                                     .getArrayBuffer(rt);

  memcpy(arrayBuffer.data(rt), bb.data, bb.len);
  return arrayBuffer;
}

jsi::ArrayBuffer secretBufferToArrayBuffer(jsi::Runtime &rt, SecretBuffer sb) {
  jsi::ArrayBuffer arrayBuffer = rt.global()
                                     .getPropertyAsFunction(rt, "ArrayBuffer")
                                     .callAsConstructor(rt, int(sb.len))
                                     .getObject(rt)
                                     .getArrayBuffer(rt);

  // TODO: signature here is weird. sb.data cannot go into ab.data()
  memcpy(arrayBuffer.data(rt), sb.data, sb.len);
  return arrayBuffer;
}

} // namespace turboModuleUtility
