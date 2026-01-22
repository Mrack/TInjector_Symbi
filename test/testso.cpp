//
// Created by Mrack on 2024/5/6.
//
#include <android/log.h>

#define TAG "TESTSO"
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__))


__attribute__((constructor()))
void initialize_globals() {
    LOGD("注入成功 initialize_globals_test");
}

__attribute__((destructor()))
void destroy_globals() {
    LOGD("destroy_globals_test");
}
