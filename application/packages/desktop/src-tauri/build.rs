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

    // The iOS sign-in sheet completes on an https return address only when
    // the app claims that host as an associated web-credentials domain. The
    // deep-link plugin's build script writes the associated-domains array
    // with `applinks:` for every app-link host in tauri.conf.json and knows
    // no other service, and cargo re-runs each script on its own schedule, so
    // the array is written here in full, from the same config, on every iOS
    // build: a package's build script runs after every dependency's, and the
    // Tauri CLI sets the two variables the helper reads only during `ios dev`
    // and `ios build`, which is also when the plugin writes. The host is the
    // one in OAUTH_APP_LINK_REDIRECT (packages/web/src/authStorage.ts), and
    // tests/desktopCapabilities.test.ts holds the two together.
    // Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.2)
    if target_os == "ios" {
        claim_associated_domains();
    }

    tauri_build::build()
}

/// The helper exists on a Mac host only, which is also the only host that
/// builds iOS; the other hosts compile an empty function.
#[cfg(target_os = "macos")]
fn claim_associated_domains() {
    // Cargo re-runs this script only when an input it knows about changes.
    // The entitlements file is one, because xcodegen blanks it and the
    // deep-link plugin's script rewrites it; the two variables are another,
    // because they exist only under the Tauri CLI; the config is the third.
    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-env-changed=TAURI_IOS_PROJECT_PATH");
    println!("cargo:rerun-if-env-changed=TAURI_IOS_APP_NAME");
    if let (Ok(project), Ok(app)) = (
        std::env::var("TAURI_IOS_PROJECT_PATH"),
        std::env::var("TAURI_IOS_APP_NAME"),
    ) {
        println!("cargo:rerun-if-changed={project}/{app}_iOS/{app}_iOS.entitlements");
    }

    let conf: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string("tauri.conf.json").expect("tauri.conf.json is unreadable"),
    )
    .expect("tauri.conf.json is not JSON");
    let hosts: Vec<String> = conf["plugins"]["deep-link"]["mobile"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| entry["appLink"].as_bool() == Some(true))
        .filter_map(|entry| entry["host"].as_str().map(str::to_string))
        .collect();
    let mut domains = Vec::new();
    for host in &hosts {
        domains.push(plist::Value::String(format!("applinks:{host}")));
    }
    for host in &hosts {
        domains.push(plist::Value::String(format!("webcredentials:{host}")));
    }

    tauri_plugin::mobile::update_entitlements(|entitlements| {
        entitlements.insert(
            "com.apple.developer.associated-domains".into(),
            plist::Value::Array(domains),
        );
    })
    .expect("failed to write the associated domains into the iOS entitlements");
}

#[cfg(not(target_os = "macos"))]
fn claim_associated_domains() {}
