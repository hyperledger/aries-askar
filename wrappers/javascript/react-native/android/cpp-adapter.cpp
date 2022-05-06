#include <jni.h>
#include <jsi/jsi.h>
#include <turboModuleUtility.h>

using namespace facebook;

extern "C"
JNIEXPORT void JNICALL
Java_org_hyperledger_ariesaskar_AriesAskarModule_nativeInstall(JNIEnv *env, jobject clazz, jlong jsiPtr) {
    auto rt = reinterpret_cast<jsi::Runtime*>(jsiPtr);
    if (rt) {
        turboModuleUtility::registerTurboModule(*rt);
    }
}
