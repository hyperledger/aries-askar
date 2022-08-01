#pragma once

#include <jsi/jsi.h>

#include <include/libaries_askar.h>
#include <turboModuleUtility.h>

using namespace facebook;

namespace ariesAskar {

jsi::Value version(jsi::Runtime &rt, jsi::Object options);
jsi::Value getCurrentError(jsi::Runtime &rt, jsi::Object options);


// TODO: not implemented yet
// jsi::Value setCustomLogger(jsi::Runtime &rt, jsi::Object options);
// jsi::Value setDefaultLogger(jsi::Runtime &rt, jsi::Object options);
// jsi::Value setMaxLogLevel(jsi::Runtime &rt, jsi::Object options);
// jsi::Value clearCustomLogger(jsi::Runtime &rt, jsi::Object options);

jsi::Value entryListCount(jsi::Runtime &rt, jsi::Object options);
jsi::Value entryListFree(jsi::Runtime &rt, jsi::Object options);
jsi::Value entryListGetCategory(jsi::Runtime &rt, jsi::Object options);
jsi::Value entryListGetName(jsi::Runtime &rt, jsi::Object options);
jsi::Value entryListGetTags(jsi::Runtime &rt, jsi::Object options);
jsi::Value entryListGetValue(jsi::Runtime &rt, jsi::Object options);

jsi::Value keyAeadDecrypt(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyAeadEncrypt(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyAeadGetPadding(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyAeadGetParams(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyAeadRandomNonce(jsi::Runtime &rt, jsi::Object options);

jsi::Value keyConvert(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyFree(jsi::Runtime &rt, jsi::Object options);

jsi::Value keyCryptoBox(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyCryptoBoxOpen(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyCryptoBoxRandomNonce(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyCryptoBoxSeal(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyCryptoBoxSealOpen(jsi::Runtime &rt, jsi::Object options);

jsi::Value keyDeriveEcdh1pu(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyDeriveEcdhEs(jsi::Runtime &rt, jsi::Object options);

jsi::Value keyEntryListCount(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyEntryListFree(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyEntryListGetAlgorithm(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyEntryListGetMetadata(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyEntryListGetName(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyEntryListGetTags(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyEntryListLoadLocal(jsi::Runtime &rt, jsi::Object options);

jsi::Value keyFromJwk(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyFromKeyExchange(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyFromPublicBytes(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyFromSecretBytes(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyFromSeed(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyGenerate(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyGetAlgorithm(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyGetEphemeral(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyGetJwkPublic(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyGetJwkSecret(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyGetJwkThumbprint(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyGetPublicBytes(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyGetSecretBytes(jsi::Runtime &rt, jsi::Object options);
jsi::Value keySignMessage(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyUnwrapKey(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyVerifySignature(jsi::Runtime &rt, jsi::Object options);
jsi::Value keyWrapKey(jsi::Runtime &rt, jsi::Object options);

jsi::Value scanFree(jsi::Runtime &rt, jsi::Object options);
jsi::Value scanNext(jsi::Runtime &rt, jsi::Object options);
jsi::Value scanStart(jsi::Runtime &rt, jsi::Object options);

jsi::Value sessionClose(jsi::Runtime &rt, jsi::Object options);
jsi::Value sessionCount(jsi::Runtime &rt, jsi::Object options);
jsi::Value sessionFetch(jsi::Runtime &rt, jsi::Object options);
jsi::Value sessionFetchAll(jsi::Runtime &rt, jsi::Object options);
jsi::Value sessionFetchAllKeys(jsi::Runtime &rt, jsi::Object options);
jsi::Value sessionFetchKey(jsi::Runtime &rt, jsi::Object options);
jsi::Value sessionInsertKey(jsi::Runtime &rt, jsi::Object options);
jsi::Value sessionRemoveAll(jsi::Runtime &rt, jsi::Object options);
jsi::Value sessionRemoveKey(jsi::Runtime &rt, jsi::Object options);
jsi::Value sessionStart(jsi::Runtime &rt, jsi::Object options);
jsi::Value sessionUpdate(jsi::Runtime &rt, jsi::Object options);
jsi::Value sessionUpdateKey(jsi::Runtime &rt, jsi::Object options);

jsi::Value storeOpen(jsi::Runtime &rt, jsi::Object options);
jsi::Value storeClose(jsi::Runtime &rt, jsi::Object options);
jsi::Value storeCreateProfile(jsi::Runtime &rt, jsi::Object options);
jsi::Value storeGenerateRawKey(jsi::Runtime &rt, jsi::Object options);
jsi::Value storeGetProfileName(jsi::Runtime &rt, jsi::Object options);
jsi::Value storeProvision(jsi::Runtime &rt, jsi::Object options);
jsi::Value storeRekey(jsi::Runtime &rt, jsi::Object options);
jsi::Value storeRemove(jsi::Runtime &rt, jsi::Object options);
jsi::Value storeRemoveProfile(jsi::Runtime &rt, jsi::Object options);

} // namespace ariesAskar
