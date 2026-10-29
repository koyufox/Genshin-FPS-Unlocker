# Genshin FPS Unlocker

适用于原神官服的 Zygisk 模块，核心逻辑使用 Rust 实现。
通过内存补丁将 `vSyncCount` 设为 1，使帧调度跟随屏幕刷新率，游戏文件保持原样。
实际帧率取决于系统刷新率和设备性能。

## 使用

1. 在 Magisk 或 KernelSU 管理器中安装模块 ZIP，启用 Zygisk 支持并重启设备。
2. 默认开启，通过模块的 Action 按钮切换；修改后须完全重启游戏。

模块描述显示保存的开关状态；`Inject failed(N)` 表示本次开机累计观察到的失败进程数，重启设备后清零。
失败日志位于 `/data/adb/genshin-fps-unlocker/log/module.log`。

## 构建

在 Linux x86_64 上准备 Rust（已验证 1.99.1）、CMake 4.0.2+、Ninja、Python 3.11+、Git 和 Android NDK 29.0.14206865。
使用完整 Git 历史构建；浅克隆先执行 `git fetch --unshallow`。

```sh
git submodule update --init --recursive
rustup target add aarch64-linux-android
python3 build.py
```

产物位于 `output/release/`。调试构建使用 `python3 build.py --debug`，产物位于 `output/debug/`；
可用 `--ndk /path/to/ndk` 指定 NDK。

## 感谢

- [zygisk-module-template](https://github.com/5ec1cff/zygisk-module-template)：Zygisk API 与安装模板。
- [ShadowHook](https://github.com/bytedance/android-inline-hook)：原生库初始化观察。

## License

本项目采用 [GNU GPLv3](LICENSE)（`GPL-3.0-only`）。第三方组件保留各自许可证，详见 [第三方声明](THIRD_PARTY_NOTICES.md)。
