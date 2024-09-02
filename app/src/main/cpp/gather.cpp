#include <jni.h>
#include <string>
#include "include/hookDetection.h"

extern "C"
JNIEXPORT jstring JNICALL
Java_com_nuthecz_gather_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    openHookStatus();
    segmentHookStatus();
    prettyMethodHookStatus();
    return env->NewStringUTF(hello.c_str());
}