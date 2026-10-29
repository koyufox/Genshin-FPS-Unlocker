#include <sys/types.h>
#include "zygisk.hpp"
#include <android/dlext.h>
#include <dlfcn.h>
#include <cstddef>

extern "C" void *rust_pre(void *, const char *, const char *, unsigned);
extern "C" void rust_post(void *);
extern "C" void rust_companion(int);

// Keep all policy and retained state in Rust; JNI references stay on this thread.
class UnlockModule : public zygisk::ModuleBase {
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
    void *runtime_ = nullptr;
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { api_ = api; env_ = env; }
    void preServerSpecialize(zygisk::ServerSpecializeArgs *) override {
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *name = args->nice_name ? env_->GetStringUTFChars(args->nice_name, nullptr) : nullptr;
        const char *data = args->app_data_dir ? env_->GetStringUTFChars(args->app_data_dir, nullptr) : nullptr;
        runtime_ = rust_pre(api_, name, data, args->uid);
        if (data) env_->ReleaseStringUTFChars(args->app_data_dir, data);
        if (name) env_->ReleaseStringUTFChars(args->nice_name, name);
        if (!runtime_) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override { rust_post(runtime_); }
};

extern "C" int bridge_connect(void *api) {
    return static_cast<zygisk::Api *>(api)->connectCompanion();
}
extern "C" int bridge_module_dir(void *api) {
    return static_cast<zygisk::Api *>(api)->getModuleDir();
}
extern "C" void *bridge_load_fd(int fd) {
    android_dlextinfo info{};
    info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    info.library_fd = fd;
    return android_dlopen_ext("libshadowhook.so", RTLD_NOW | RTLD_LOCAL, &info);
}
extern "C" void bridge_clear_cache(void *address, size_t size) {
    auto *begin = static_cast<char *>(address);
    __builtin___clear_cache(begin, begin + size);
}
REGISTER_ZYGISK_MODULE(UnlockModule)
REGISTER_ZYGISK_COMPANION(rust_companion)
