#pragma once

#include "include/libaries-askar.h"
#include "react-native-aries-askar.h"

using namespace facebook;
using namespace react;

class TurboModuleUtils {
public:
  // Install the Turbomodule
  static void installTurboModule(jsi::Runtime &runtime,
                                 std::shared_ptr<CallInvoker> jsCallInvoker);
};
