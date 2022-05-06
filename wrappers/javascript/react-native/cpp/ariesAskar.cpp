#include <ariesAskar.h>

using namespace turboModuleUtility;

namespace ariesAskar {
jsi::Value getCurrentError(jsi::Runtime &rt) {
  const char *errorMessage = "TODO";

  return jsi::String::createFromAscii(rt, errorMessage);
};

}
