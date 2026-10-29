#!/usr/bin/env python3
"""Build the Rust module, native bridge, and ARM64 installation package."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent
SHADOWHOOK = ROOT / "third_party/shadowhook"
SHADOWHOOK_CPP = SHADOWHOOK / "shadowhook/src/main/cpp"
MODULE_ID = "genshin-fps-unlocker-zygisk"


def run(args):
    subprocess.run([str(x) for x in args], check=True)


def git_version(root):
    if not (root / ".git").exists():
        return 0, "nogit"
    git = ["git", "-C", str(root)]
    head = subprocess.run(git + ["rev-parse", "--verify", "--quiet", "HEAD"],
                          check=False, capture_output=True, text=True)
    if head.returncode == 1:
        return 0, "nogit"
    head.check_returncode()
    if subprocess.check_output(git + ["rev-parse", "--is-shallow-repository"], text=True).strip() == "true":
        raise ValueError("Full Git history is required for versionCode; run git fetch --unshallow")
    commit = head.stdout.strip()
    count = int(subprocess.check_output(git + ["rev-list", "--count", commit], text=True))
    short_hash = subprocess.check_output(git + ["rev-parse", "--short", commit], text=True).strip()
    return count, short_hash


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--ndk", type=Path)
    args = parser.parse_args()
    if not (SHADOWHOOK_CPP / "include/shadowhook.h").is_file():
        parser.error("Initialize ShadowHook with: git submodule update --init --recursive")
    version = tomllib.loads((ROOT / "rust/Cargo.toml").read_text())["package"]["version"]
    try:
        commit_count, commit_hash = git_version(ROOT)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        parser.error(f"Cannot determine build version: {error}")
    build_type = "debug" if args.debug else "release"
    revision = f"{commit_count}-{commit_hash}" if commit_count else commit_hash
    version_name = f"{version} ({revision}-{build_type})"
    build_name = f"{MODULE_ID}-{version}-{revision}-{build_type}"
    config = json.loads((ROOT / "project-config.json").read_text())
    sdk = Path(os.environ.get("ANDROID_HOME", os.environ.get("ANDROID_SDK_ROOT", str(Path.home() / "Android/Sdk"))))
    ndk = args.ndk or sdk / "ndk" / config["ndkVer"]
    if not (ndk / "build/cmake/android.toolchain.cmake").is_file():
        parser.error(f"NDK not found: {ndk}")
    kind = "Debug" if args.debug else "Release"
    output = ROOT / "output" / kind.lower()
    build = ROOT / "build" / kind.lower()
    rust_target = ROOT / "build" / "rust"
    rust_profile = "debug" if args.debug else "release"
    toolchain = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    rust_env = os.environ.copy()
    rust_env["CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"] = str(toolchain / "aarch64-linux-android26-clang")
    rust_args = [os.environ.get("CARGO", "cargo"), "build", "--locked", "--manifest-path", str(ROOT / "rust/Cargo.toml"),
                 "--target", "aarch64-linux-android", "--target-dir", str(rust_target)]
    if not args.debug:
        rust_args.append("--release")
    subprocess.run(rust_args, check=True, env=rust_env)
    rust_library = rust_target / "aarch64-linux-android" / rust_profile / "libgenshin_unlock.a"
    run(["cmake", "-S", ROOT / "native", "-B", build, "-G", "Ninja",
         f"-DCMAKE_TOOLCHAIN_FILE={ndk}/build/cmake/android.toolchain.cmake",
         "-DANDROID_ABI=arm64-v8a", f"-DANDROID_PLATFORM={config['platform']}",
         "-DANDROID_STL=c++_static", "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON", f"-DCMAKE_BUILD_TYPE={kind}",
         f"-DRUST_LIBRARY={rust_library}"])
    run(["cmake", "--build", build, "--parallel", str(min(os.cpu_count() or 2, 8))])
    package = output / "module"
    # Output staging is recreated without touching source files or persisted device state.
    if package.exists():
        shutil.rmtree(package)
    shutil.copytree(ROOT / "template", package)
    prop = (package / "module.prop").read_text().replace("@VERSION@", version_name)
    prop = prop.replace("@VERSION_CODE@", str(commit_count))
    (package / "module.prop").write_text(prop)
    binary_map = {
        "libgenshin_unlock.so": "zygisk/arm64-v8a.so",
        "genshin_control": "bin/genshin-control",
        "libshadowhook.so": "lib/arm64-v8a/libshadowhook.so",
        "libshadowhook_nothing.so": "lib/arm64-v8a/libshadowhook_nothing.so",
    }
    symbols = output / "symbols"
    symbols.mkdir(parents=True, exist_ok=True)
    strip = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
    for source, dest in binary_map.items():
        path = package / dest
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(build / source, symbols / source)
        shutil.copy2(build / source, path)
        if not args.debug:
            run([strip, "--strip-unneeded", path])
    shutil.copy2(ROOT / "README.md", package / "README.md")
    files = sorted(p for p in package.rglob("*") if p.is_file())
    for path in files:
        path.with_name(path.name + ".sha256").write_text(hashlib.sha256(path.read_bytes()).hexdigest() + "\n")
    install_files = [str(p.relative_to(package)) for p in files
                     if p.name != "verify.sh" and not str(p.relative_to(package)).startswith("META-INF/")]
    manifest = "\n".join(install_files) + "\n"
    (package / "files.list").write_text(manifest)
    (package / "files.list.sha256").write_text(hashlib.sha256(manifest.encode()).hexdigest() + "\n")
    archive = output / f"{build_name}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(package.rglob("*")):
            if path.is_file():
                z.write(path, path.relative_to(package))
    archive.with_suffix(".zip.sha256").write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "\n")
    print(archive)


if __name__ == "__main__":
    main()
