fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // The native biometric gate (src/biometric.rs) exists only where the OS
    // exposes one: LocalAuthentication on macOS + iOS, Windows Hello on Windows,
    // androidx.biometric on Android. One cfg keeps lib.rs from repeating that
    // target list at every use site, mirroring how tauri-build hands us
    // `desktop` / `mobile`. Linux is the only target left without a gate.
    println!("cargo:rustc-check-cfg=cfg(native_biometric)");
    if matches!(target_os.as_str(), "macos" | "ios" | "windows" | "android") {
        println!("cargo:rustc-cfg=native_biometric");
    }

    // biometric.rs looks up LAContext through the ObjC runtime, and nothing else
    // in the tree links LocalAuthentication.framework - without this the class is
    // simply absent and biometrics report as unavailable. Framework links are
    // per-target, so gate on the target OS rather than the host.
    if matches!(target_os.as_str(), "macos" | "ios") {
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    }

    // file_assoc.rs calls LaunchServices (LSCopyDefaultRoleHandlerForContentType /
    // LSSetDefaultRoleHandlerForContentType) to read and set which app opens
    // Markdown. LaunchServices is a CoreServices subframework, and nothing else
    // in the tree links it. macOS only: iOS has no user-settable file
    // associations at all.
    if target_os == "macos" {
        println!("cargo:rustc-link-lib=framework=CoreServices");
    }

    tauri_build::build()
}
