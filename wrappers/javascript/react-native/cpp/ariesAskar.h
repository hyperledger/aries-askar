#pragma once

#include <jsi/jsi.h>

#include <include/libaries_askar.h>
#include <turboModuleUtility.h>

using namespace facebook;

namespace ariesAskar {

jsi::Value getCurrentError(jsi::Runtime &rt);

} // namespace ariesAskar
