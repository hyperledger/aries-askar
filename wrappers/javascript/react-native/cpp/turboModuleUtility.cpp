#include <turboModuleUtility.h>

namespace turboModuleUtility {

void registerTurboModule(jsi::Runtime &rt) {
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
  State *_state = reinterpret_cast<State *>(result);
  State *state = static_cast<State *>(_state);
  jsi::Function *cb = &state->cb;
  jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);

  cb->call(*rt, int(code));
  delete state;
}

// Session, Store and Scan Handle
template <>
void callbackWithResponse(CallbackId result, ErrorCode code, size_t response) {
  State *_state = reinterpret_cast<State *>(result);
  State *state = static_cast<State *>(_state);
  jsi::Function *cb = &state->cb;
  jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);
  cb->call(*rt, int(code), int(response));
  delete state;
}

template <>
void callbackWithResponse(CallbackId result, ErrorCode code,
                          const char *response) {
  State *_state = reinterpret_cast<State *>(result);
  State *state = static_cast<State *>(_state);
  jsi::Function *cb = &state->cb;
  jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);
  jsi::String serializedResponse = jsi::String::createFromAscii(*rt, response);
  cb->call(*rt, int(code), serializedResponse);
  delete state;
}

template <>
void callbackWithResponse(CallbackId result, ErrorCode code,
                          EntryListHandle response) {
  State *_state = reinterpret_cast<State *>(result);
  State *state = static_cast<State *>(_state);
  jsi::Function *cb = &state->cb;
  jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);

  std::string serializedPointer = std::to_string(intptr_t(response._0));
  jsi::String pointer = jsi::String::createFromAscii(*rt, serializedPointer);

  cb->call(*rt, int(code), serializedPointer);
  delete state;
}

template <>
void callbackWithResponse(CallbackId result, ErrorCode code, int8_t response) {
  State *_state = reinterpret_cast<State *>(result);
  State *state = static_cast<State *>(_state);
  jsi::Function *cb = &state->cb;
  jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);
  cb->call(*rt, int(code), int(response));
  delete state;
}

template <>
void callbackWithResponse(CallbackId result, ErrorCode code, int64_t response) {
  State *_state = reinterpret_cast<State *>(result);
  State *state = static_cast<State *>(_state);
  jsi::Function *cb = &state->cb;
  jsi::Runtime *rt = reinterpret_cast<jsi::Runtime *>(state->rt);
  cb->call(*rt, int(code), int(response));
  delete state;
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

  if (value.isString())
    return value.asString(rt).utf8(rt);

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
EntryListHandle jsiToValue(jsi::Runtime &rt, jsi::Object &options,
                           const char *name, bool optional) {
  std::string handle =
      turboModuleUtility::jsiToValue<std::string>(rt, options, name, optional);
  FfiEntryList *ffiEntryListPtr =
      reinterpret_cast<FfiEntryList *>(std::stol(handle));
  EntryListHandle entryListHandle = EntryListHandle{._0 = ffiEntryListPtr};

  return entryListHandle;
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
  const uint8_t *buffer = bb.data;
  size_t length = bb.len;
  jsi::Function arrayBufferCtor =
      rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
  jsi::ArrayBuffer arrayBuffer =
      arrayBufferCtor.callAsConstructor(rt, (int)length)
          .getObject(rt)
          .getArrayBuffer(rt);
  memcpy(arrayBuffer.data(rt), buffer, length);
  return arrayBuffer;
}

jsi::ArrayBuffer secretBufferToArrayBuffer(jsi::Runtime &rt, SecretBuffer sb) {
  const uint8_t *buffer = sb.data;
  int64_t length = sb.len;
  jsi::Function arrayBufferCtor =
      rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
  jsi::ArrayBuffer arrayBuffer =
      arrayBufferCtor.callAsConstructor(rt, int(length))
          .getObject(rt)
          .getArrayBuffer(rt);
  memcpy(arrayBuffer.data(rt), buffer, length);
  return arrayBuffer;
}

} // namespace turboModuleUtility
