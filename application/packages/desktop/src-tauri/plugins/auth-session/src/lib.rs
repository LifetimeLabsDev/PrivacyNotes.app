//! The in-app OAuth sheet for iOS.
//!
//! Sign-in runs in an ASWebAuthenticationSession, because App Review guideline
//! 4 rejects sign-in that bounces through the external browser. The sheet
//! completes on an https return address that iOS hands only to the app that
//! proves it owns the host through its associated-domains entitlement
//! (`webcredentials:`), and the command resolves with that URL. A custom URL
//! scheme is never offered as the return address: any app can claim one.
//!
//! Forked from tauri-plugin-auth-session 0.2.2; README.md lists the changes.
//! Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.2)

use tauri::{
    plugin::{Builder, TauriPlugin},
    Runtime,
};

#[cfg(target_os = "ios")]
mod ios;

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("auth-session")
        .invoke_handler(tauri::generate_handler![start])
        .build()
}

/// Present the sheet at `auth_url` and resolve with the first https URL on
/// `callback_host` and `callback_path` it navigates to. Rejects with the plain
/// string `user_cancelled` when the person dismisses the sheet.
#[cfg(target_os = "ios")]
#[tauri::command]
async fn start(
    auth_url: String,
    callback_host: String,
    callback_path: String,
) -> Result<String, String> {
    ios::start_session(auth_url, callback_host, callback_path).await
}

/// The app compiles this crate for iOS alone; the stub only keeps a plain
/// `cargo check` of the crate green on any other host.
#[cfg(not(target_os = "ios"))]
#[tauri::command]
async fn start(
    _auth_url: String,
    _callback_host: String,
    _callback_path: String,
) -> Result<String, String> {
    Err("The in-app auth sheet exists on iOS only".to_string())
}
