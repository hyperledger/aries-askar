#include "TurboModuleUtils.h"

using namespace facebook;
using namespace react;

void TurboModuleUtils::installTurboModule(
    jsi::Runtime &rt, std::shared_ptr<CallInvoker> jsCallInvoker) {
  // Register the turboModule as a pointer
  std::shared_ptr<AriesAskarCxx> turboModule =
      std::make_shared<AriesAskarCxx>(jsCallInvoker);

  // Register ariesAskar instance as global._ariesAskar
  rt.global().setProperty(rt, "_ariesAskar",
                          jsi::Object::createFromHostObject(rt, turboModule));
}
