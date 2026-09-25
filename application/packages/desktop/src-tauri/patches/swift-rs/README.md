# swift-rs, patched

A copy of `swift-rs` 1.0.8 from crates.io (MIT OR Apache-2.0, both licenses beside this file), applied through `[patch.crates-io]` in `src-tauri/Cargo.toml`. It exists for one reason and goes away when that reason does.

Xcode 27's Swift package build keeps a package's `@_cdecl` functions internal to the archive. swift-rs 1.0.8 promotes them back to global with `llvm-objcopy`, but only for the package's own object, never for `SwiftRs.o`, the runtime shim every package carries. The iOS link then fails with `Undefined symbols` for `_retain_object`, `_release_object` and `_string_from_bytes`. This copy carries the two-line fix of upstream pull request 82 (issue 81): the shim's object is promoted like the package's own.

The only change is in `src-rs/build.rs`, in `globalize_cdecl_symbols`. Remove this directory and the patch section as soon as a swift-rs release includes the fix.
