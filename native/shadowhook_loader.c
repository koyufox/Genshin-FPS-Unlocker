#include "shadowhook.h"
#include <android/dlext.h>
#include <android/log.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <string.h>

static _Thread_local int bootstrap_fd = -1;

#ifndef SH_CONFIG_DEBUG
// Release initialization errors are reported by Rust; suppress the upstream banner.
// The linker redirects only this ShadowHook build's logging calls.
int __wrap___android_log_print(int priority, const char *tag, const char *format, ...) {
    if (bootstrap_fd >= 0 || priority < ANDROID_LOG_WARN) return 0;
    va_list args;
    va_start(args, format);
    int result = __android_log_vprint(priority, tag, format, args);
    va_end(args);
    return result;
}
#endif

void *__real_dlopen(const char *filename, int flags);

// --wrap=dlopen redirects only references inside our ShadowHook build.
void *__wrap_dlopen(const char *filename, int flags) {
    if (bootstrap_fd >= 0 && filename && !strcmp(filename, "libshadowhook_nothing.so")) {
        android_dlextinfo info = {0};
        info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
        info.library_fd = bootstrap_fd;
        return android_dlopen_ext(filename, flags, &info);
    }
    return __real_dlopen(filename, flags);
}

int genshin_shadowhook_init(shadowhook_mode_t mode, bool debuggable, int helper_fd) {
    // Load the helper after ShadowHook installs its constructor hooks. Preloading
    // it would skip the constructor calls needed to discover linker metadata.
    int previous = bootstrap_fd;
    bootstrap_fd = helper_fd;
    int result = shadowhook_init(mode, debuggable);
    bootstrap_fd = previous;
    return result;
}
