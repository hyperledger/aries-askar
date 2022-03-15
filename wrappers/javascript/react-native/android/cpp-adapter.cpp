#include <CallInvokerHolder.h>
#include <fbjni/fbjni.h>
#include <jni.h>
#include <jsi/jsi.h>

#include "logging.h"
#include "TurboModuleUtils.h"

using namespace facebook;

// this reflects com.myturboutils.NativeProxy class
struct NativeProxy : jni::JavaClass<NativeProxy> {
  static constexpr auto kJavaDescriptor =
      "Lcom/reactnativeariesaskar/NativeProxy;";

  static void registerNatives() {
    // register native methods for Java
    javaClassStatic()->registerNatives(
        {makeNativeMethod("installNativeJsi", NativeProxy::installNativeJsi)});
  }

private:
  static void
  installNativeJsi(jni::alias_ref<jni::JObject> thiz, jlong jsiRuntimePtr,
                   jni::alias_ref<react::CallInvokerHolder::javaobject>
                       jsCallInvokerHolder) {

    auto jsiRuntime = reinterpret_cast<jsi::Runtime *>(jsiRuntimePtr);
    auto jsCallInvoker = jsCallInvokerHolder->cthis()->getCallInvoker();

    // initialize turbo module
    TurboModuleUtils::installTurboModule(*jsiRuntime, jsCallInvoker);
  }
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {
  return jni::initialize(vm, [] { NativeProxy::registerNatives(); });
}
