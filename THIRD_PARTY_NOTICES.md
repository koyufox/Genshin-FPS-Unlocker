# Third-party Notices

- Zygisk API header and installation verification are taken from
  5ec1cff/zygisk-module-template, revision
  ad3262b97b51369a71e1bb47f6b5a151331cd687. The API header retains its ISC notice.
- ShadowHook v2.0.1, revision 854c775c2c3676e57a0f383597ebf420b5204161, is
  included as a Git submodule under `third_party/shadowhook`. Its MIT license
  and bundled dependency notices remain with the sources. The ARM64 build
  adapter filters ARM32-only exports. A local loader adapter opens the bootstrap
  helper by file descriptor during initialization and suppresses routine
  initialization logging in release; the upstream sources remain unchanged.
- Rust dependencies are pinned in `rust/Cargo.lock`. License documents and
  third-party notices are excluded from the module ZIP.
