//
// Created by mrack on 2026/1/22.
//

#ifndef TINJECTOR_PP_STUB_H
#define TINJECTOR_PP_STUB_H

#include <jni.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <android/log.h>

struct _TStub {
    char mark[20];

    int (*original_set_argv0)(JNIEnv *env, jobject clazz, jstring name);

    uintptr_t slot_addr;

    int uid;

    char so_path[128];

    int (*socket)(int domain, int type, int protocol);

    int (*connect)(int fd, const struct sockaddr *addr, socklen_t len);

    ssize_t (*write)(int fd, const void *buf, size_t count);

    ssize_t (*read)(int fd, void *buf, size_t count);

    int (*close)(int fd);

    uid_t (*getuid)();

    void *(*dlopen)(const char *filename, int flag);

    int (*log_print)(int prio, const char* tag, const char* fmt, ...);
};

typedef struct _TStub TStub;


#define LOG_TAG "TInjectX"
#define LOGI(stub, ...) if(stub->log_print) stub->log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(stub, ...) if(stub->log_print) stub->log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#endif //TINJECTOR_PP_STUB_H