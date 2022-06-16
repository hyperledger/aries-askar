#include <ariesAskar.h>
#include <include/libaries_askar.h>

using namespace turboModuleUtility;

namespace ariesAskar {

jsi::Value version(jsi::Runtime &rt, jsi::Object options) {
    return jsi::String::createFromAscii(rt, askar_version());
};

}
