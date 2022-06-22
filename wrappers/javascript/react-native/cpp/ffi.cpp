#include <ffi.h>
#include <include/libaries_askar.h>

using namespace turboModuleUtility;

namespace ffi {

jsi::Value version(jsi::Runtime &rt, jsi::Object options) {
    return jsi::String::createFromAscii(rt, ariesAskar::version());
};

}
