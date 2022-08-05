
#include <HostObject.h>
#include <algorithm>
#include <vector>

TurboModuleHostObject::TurboModuleHostObject(jsi::Runtime &rt) { return; }
FunctionMap TurboModuleHostObject::functionMapping(jsi::Runtime &rt) {
  FunctionMap fMap;

  fMap.insert(std::make_tuple("version", &ariesAskar::version));
  fMap.insert(std::make_tuple("getCurrentError", &ariesAskar::getCurrentError));

  fMap.insert(std::make_tuple("storeOpen", &ariesAskar::storeOpen));
  fMap.insert(
      std::make_tuple("storeGenerateRawKey", &ariesAskar::storeGenerateRawKey));
  fMap.insert(std::make_tuple("storeProvision", &ariesAskar::storeProvision));
  fMap.insert(std::make_tuple("storeOpen", &ariesAskar::storeOpen));
  fMap.insert(std::make_tuple("storeClose", &ariesAskar::storeClose));
  fMap.insert(
      std::make_tuple("storeCreateProfile", &ariesAskar::storeCreateProfile));
  fMap.insert(
      std::make_tuple("storeGenerateRawKey", &ariesAskar::storeGenerateRawKey));
  fMap.insert(
      std::make_tuple("storeGetProfileName", &ariesAskar::storeGetProfileName));
  fMap.insert(std::make_tuple("storeProvision", &ariesAskar::storeProvision));
  fMap.insert(std::make_tuple("storeRekey", &ariesAskar::storeRekey));
  fMap.insert(std::make_tuple("storeRemove", &ariesAskar::storeRemove));
  fMap.insert(
      std::make_tuple("storeRemoveProfile", &ariesAskar::storeRemoveProfile));

  fMap.insert(std::make_tuple("sessionClose", &ariesAskar::sessionClose));
  fMap.insert(std::make_tuple("sessionCount", &ariesAskar::sessionCount));
  fMap.insert(std::make_tuple("sessionFetch", &ariesAskar::sessionFetch));
  fMap.insert(std::make_tuple("sessionFetchAll", &ariesAskar::sessionFetchAll));
  fMap.insert(
      std::make_tuple("sessionFetchAllKeys", &ariesAskar::sessionFetchAllKeys));
  fMap.insert(std::make_tuple("sessionFetchKey", &ariesAskar::sessionFetchKey));
  fMap.insert(
      std::make_tuple("sessionInsertKey", &ariesAskar::sessionInsertKey));
  fMap.insert(
      std::make_tuple("sessionRemoveAll", &ariesAskar::sessionRemoveAll));
  fMap.insert(
      std::make_tuple("sessionRemoveKey", &ariesAskar::sessionRemoveKey));
  fMap.insert(std::make_tuple("sessionStart", &ariesAskar::sessionStart));
  fMap.insert(std::make_tuple("sessionUpdate", &ariesAskar::sessionUpdate));
  fMap.insert(
      std::make_tuple("sessionUpdateKey", &ariesAskar::sessionUpdateKey));

  fMap.insert(
      std::make_tuple("entryListGetName", &ariesAskar::entryListGetName));
  fMap.insert(
      std::make_tuple("entryListGetValue", &ariesAskar::entryListGetValue));
  fMap.insert(std::make_tuple("entryListGetCategory",
                              &ariesAskar::entryListGetCategory));
  fMap.insert(
      std::make_tuple("entryListGetTags", &ariesAskar::entryListGetTags));
  fMap.insert(std::make_tuple("entryListCount", &ariesAskar::entryListCount));
  fMap.insert(std::make_tuple("entryListFree", &ariesAskar::entryListFree));

  fMap.insert(std::make_tuple("scanFree", &ariesAskar::scanFree));
  fMap.insert(std::make_tuple("scanNext", &ariesAskar::scanNext));
  fMap.insert(std::make_tuple("scanStart", &ariesAskar::scanStart));

  fMap.insert(std::make_tuple("keyFromJwk", &ariesAskar::keyFromJwk));
  fMap.insert(
      std::make_tuple("keyFromKeyExchange", &ariesAskar::keyFromKeyExchange));
  fMap.insert(
      std::make_tuple("keyFromPublicBytes", &ariesAskar::keyFromPublicBytes));
  fMap.insert(
      std::make_tuple("keyFromSecretBytes", &ariesAskar::keyFromSecretBytes));
  fMap.insert(std::make_tuple("keyFromSeed", &ariesAskar::keyFromSeed));
  fMap.insert(std::make_tuple("keyGenerate", &ariesAskar::keyGenerate));
  fMap.insert(std::make_tuple("keyGetAlgorithm", &ariesAskar::keyGetAlgorithm));
  fMap.insert(std::make_tuple("keyGetEphemeral", &ariesAskar::keyGetEphemeral));
  fMap.insert(std::make_tuple("keyGetJwkPublic", &ariesAskar::keyGetJwkPublic));
  fMap.insert(std::make_tuple("keyGetJwkSecret", &ariesAskar::keyGetJwkSecret));
  fMap.insert(
      std::make_tuple("keyGetJwkThumbprint", &ariesAskar::keyGetJwkThumbprint));
  fMap.insert(
      std::make_tuple("keyGetPublicBytes", &ariesAskar::keyGetPublicBytes));
  fMap.insert(
      std::make_tuple("keyGetSecretBytes", &ariesAskar::keyGetSecretBytes));
  fMap.insert(std::make_tuple("keySignMessage", &ariesAskar::keySignMessage));
  fMap.insert(std::make_tuple("keyUnwrapKey", &ariesAskar::keyUnwrapKey));
  fMap.insert(
      std::make_tuple("keyVerifySignature", &ariesAskar::keyVerifySignature));
  fMap.insert(std::make_tuple("keyWrapKey", &ariesAskar::keyWrapKey));

  fMap.insert(std::make_tuple("keyConvert", &ariesAskar::keyConvert));
  fMap.insert(std::make_tuple("keyFree", &ariesAskar::keyFree));

  fMap.insert(std::make_tuple("keyCryptoBox", &ariesAskar::keyCryptoBox));
  fMap.insert(
      std::make_tuple("keyCryptoBoxOpen", &ariesAskar::keyCryptoBoxOpen));
  fMap.insert(std::make_tuple("keyCryptoBoxRandomNonce",
                              &ariesAskar::keyCryptoBoxRandomNonce));
  fMap.insert(
      std::make_tuple("keyCryptoBoxSeal", &ariesAskar::keyCryptoBoxSeal));
  fMap.insert(std::make_tuple("keyCryptoBoxSealOpen",
                              &ariesAskar::keyCryptoBoxSealOpen));

  fMap.insert(
      std::make_tuple("keyDeriveEcdh1pu", &ariesAskar::keyDeriveEcdh1pu));
  fMap.insert(std::make_tuple("keyDeriveEcdhEs", &ariesAskar::keyDeriveEcdhEs));

  fMap.insert(std::make_tuple("keyAeadDecrypt", &ariesAskar::keyAeadDecrypt));
  fMap.insert(std::make_tuple("keyAeadEncrypt", &ariesAskar::keyAeadEncrypt));
  fMap.insert(
      std::make_tuple("keyAeadGetPadding", &ariesAskar::keyAeadGetPadding));
  fMap.insert(
      std::make_tuple("keyAeadGetParams", &ariesAskar::keyAeadGetParams));
  fMap.insert(
      std::make_tuple("keyAeadRandomNonce", &ariesAskar::keyAeadRandomNonce));

  fMap.insert(
      std::make_tuple("keyEntryListCount", &ariesAskar::keyEntryListCount));
  fMap.insert(
      std::make_tuple("keyEntryListFree", &ariesAskar::keyEntryListFree));
  fMap.insert(std::make_tuple("keyEntryListGetAlgorithm",
                              &ariesAskar::keyEntryListGetAlgorithm));
  fMap.insert(std::make_tuple("keyEntryListGetMetadata",
                              &ariesAskar::keyEntryListGetMetadata));
  fMap.insert(
      std::make_tuple("keyEntryListGetName", &ariesAskar::keyEntryListGetName));
  fMap.insert(
      std::make_tuple("keyEntryListGetTags", &ariesAskar::keyEntryListGetTags));
  fMap.insert(std::make_tuple("keyEntryListLoadLocal",
                              &ariesAskar::keyEntryListLoadLocal));

  return fMap;
}

jsi::Function TurboModuleHostObject::call(jsi::Runtime &rt, const char *name,
                                          Cb cb) {
  return jsi::Function::createFromHostFunction(
      rt, jsi::PropNameID::forAscii(rt, name), 1,
      [this, cb](jsi::Runtime &rt, const jsi::Value &thisValue,
                 const jsi::Value *arguments, size_t count) -> jsi::Value {
        const jsi::Value *val = &arguments[0];
        turboModuleUtility::assertValueIsObject(rt, val);
        return (*cb)(rt, val->getObject(rt));
      });
};

std::vector<jsi::PropNameID>
TurboModuleHostObject::getPropertyNames(jsi::Runtime &rt) {
  auto fMap = TurboModuleHostObject::functionMapping(rt);
  std::vector<jsi::PropNameID> result;
  for (FunctionMap::iterator it = fMap.begin(); it != fMap.end(); ++it) {
    result.push_back(jsi::PropNameID::forUtf8(rt, it->first));
  }

  return result;
}

jsi::Value TurboModuleHostObject::get(jsi::Runtime &rt,
                                      const jsi::PropNameID &propNameId) {
  auto propName = propNameId.utf8(rt);
  auto fMap = TurboModuleHostObject::functionMapping(rt);
  for (FunctionMap::iterator it = fMap.begin(); it != fMap.end(); ++it) {
    if (it->first == propName) {
      return TurboModuleHostObject::call(rt, it->first, it->second);
    }
  }

  /*
   * https://overreacted.io/why-do-react-elements-have-typeof-property/
   *
   * This is a special React key on the object that `React.createElement()`
   * returns.
   *
   * This function is called under-the-hood to see if this React element is
   * renderable.
   *
   * When we return undefined, instead of `Symbol.for('react.element'), we tell
   * React that this element is not renderable.
   *
   */
  if (propName == "$$typeof")
    return jsi::Value::undefined();

  throw jsi::JSError(rt, "Function: " + propName + " is not defined");
}
