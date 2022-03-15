#pragma once

// class "interface" of the generated code. This has to be copied over from
// `../lib/cpp-generated/NativeModules.h`

#include "generated/NativeModules.h"
#include "TurboModuleUtils.h"
#include <ReactCommon/TurboModule.h>

namespace facebook {
namespace react {

class AriesAskarCxx : public AriesAskarCxxSpecJSI {
public:
  AriesAskarCxx(std::shared_ptr<CallInvoker> jsInvoker);
  jsi::String version(jsi::Runtime &rt);
};
} // namespace react
} // namespace facebook
