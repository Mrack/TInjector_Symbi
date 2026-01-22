//
// Created by mrack on 2026/1/21.
//

#include <dlfcn.h>
#include "stub.h"


static volatile const TStub stubApi =
        {
                .mark = "/mmmmmrack87654321",
        };


__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
int
stub_replacement_set_argv0(JNIEnv *env, jobject clazz, jstring name) {
    const char *name_utf8 = (*env)->GetStringUTFChars(env, name, 0);
    const int res = stubApi.original_set_argv0(env, clazz, name);
    if (stubApi.getuid() == (uid_t) stubApi.uid) {
        LOGI((&stubApi), "%s Attempting to inject: %s", name_utf8, stubApi.so_path);
        void *handle = stubApi.dlopen(stubApi.so_path, RTLD_NOW);
        if (handle) {
            LOGI((&stubApi), "Successfully loaded SO at handle: %p", handle);
        } else {
            LOGE((&stubApi), "Failed to dlopen SO!");
        }
    }

    (*env)->ReleaseStringUTFChars(env, name, name_utf8);
    return res;
}
