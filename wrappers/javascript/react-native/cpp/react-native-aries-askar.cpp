#include "react-native-aries-askar.h"

using namespace facebook;
using namespace react;

AriesAskarCxx::AriesAskarCxx(std::shared_ptr<CallInvoker> jsInvoker) : AriesAskarCxxSpecJSI(jsInvoker){};

jsi::String AriesAskarCxx::version(jsi::Runtime &rt) {
    return jsi::String::createFromAscii(rt, askar_version());
};

