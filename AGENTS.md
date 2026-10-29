# Repository Guidelines

## Project Structure

- `rust/src/`: runtime policy, patching, reporting, shared state, and host tests.
- `native/`: thin Zygisk/control bridges and loader; `template/`: Android scripts.
- `third_party/shadowhook/`: pinned submodule; preserve upstream style.
- `build.py` and `project-config.json`: build configuration.

## Core Design

- Support only the official mainland China ARM64 main process
  `com.miHoYo.Yuanshen`. Rust owns behavior and retained state.
- Force the in-memory `vSyncCount` divisor to one. Leave display refresh policy
  to the system/user; measure actual FPS independently of patch status.
- Load ShadowHook dependencies through the module-directory FD. Patch before
  ELF constructors using validated, unique signatures and original bytes; flush
  instruction caches, restore page protections, and verify after constructors.
  Preserve installed game files and callback-referenced code lifetimes.
- Action toggles saved enablement, initially enabled. Each process captures its
  startup setting; changes require a full game restart.
- Scripts invoke `genshin-control`, sharing Rust state rules with the companion:
  strict configuration validation, shared locking, atomic saves, and readback.
- Close startup sockets/FDs before specialization returns. Send final reports
  through sealed shared mappings; validate credentials and session identity.
  Keep privileged persistence outside loader callbacks.
- Persist data under `/data/adb/genshin-fps-unlocker`. Module status shows saved
  enablement and observed failures, deduplicated per process per boot. Toggles
  and successes preserve the count; reboot resets it. Automatically rotate
  failure logs; keep release logging concise and debug diagnostics detailed.

## Development Commands

Use Python 3.11+, CMake 4.0.2+, Ninja, Rust with the Android target, and NDK
29.0.14206865. From the repository root:

- `git submodule update --init --recursive`: initialize dependencies.
- `rustup target add aarch64-linux-android`: install target.
- `python3 build.py`: package release; add `--debug` or `--ndk /path/to/ndk`.
- `cargo test --locked --manifest-path rust/Cargo.toml`: run host tests.
- `cargo fmt --manifest-path rust/Cargo.toml -- --check`: check formatting.
- `shellcheck template/*.sh`: lint scripts.

Use full Git history for versioning. Outputs: `output/{release,debug}/`.

## Coding Style

Use four-space indentation; shell blocks use two. Follow Rust naming conventions
and `cargo fmt`. Keep native code warning-free (`-Wall -Wextra -Werror`).
Scripts target Android `/system/bin/sh`.

## Testing Guidelines

Prefer existing tests; add tests only when requested or necessary for critical
behavior. Rust `#[test]` cases use descriptive `snake_case` names. Validate both
build profiles, static analysis, packages, and device behavior.

## Commit & Pull Request Guidelines

Use Conventional Commits, e.g. `fix(state): validate configuration revisions`.
Use imperative titles; explain why in the body. PRs describe
behavior, relevant issues, validation, and pending device checks. Exclude
generated artifacts, caches, and unrelated changes.
