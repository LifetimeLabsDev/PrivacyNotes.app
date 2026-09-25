# tao, patched

A copy of `tao` 0.35.3 from crates.io (Apache-2.0, license beside this file), applied through `[patch.crates-io]` in `src-tauri/Cargo.toml`. It exists for one reason and goes away when that reason does.

Every Tauri 2.11 release pins `tao ^0.35`. The iOS 27 SDK requires the scene life cycle, which `Info.ios.plist` enables with `UIApplicationSceneManifest`, and with that manifest tao 0.35.3 crashes every release build at launch: `configuration_for_connecting_scene_session` in `src/platform_impl/ios/view.rs` returned a `UISceneConfiguration` it had already released, so UIKit retained freed memory in `-[UIApplication _connectUISceneFromFBSScene:]`. Debug builds survived only because the autorelease pool happened to keep the object alive. Upstream fixed it in pull request 1245, released in tao 0.37.0, which Tauri 2.11 cannot reach (upstream issue 1340).

The only change is that one line, which now hands the configuration to the autorelease pool. Remove this directory and the patch section as soon as the Tauri release in use depends on a tao that carries the fix (`cargo tree -i tao` shows the version).
