//! The Android half of the bound biometric key.
//!
//! The Kotlin side (`android/`) makes an RSA Keystore key that needs a strong
//! biometric for every use of its private half, seals a random secret to the
//! public half, and opens it through `BiometricPrompt.CryptoObject`. This crate
//! only carries the three calls to it and maps a rejection onto its code.
//! Spec: ops/docs/plans/biometric-key-binding.md (section 8.2)

use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{Builder, PluginHandle, TauriPlugin},
    Manager, Runtime,
};

#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "app.privacynotes.biometrickey";

/// Access to the Keystore key calls.
pub struct BiometricKey<R: Runtime>(PluginHandle<R>);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Request<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<&'a str>,
    reason: &'a str,
    cancel_title: &'a str,
}

#[derive(Serialize)]
struct DeleteRequest<'a> {
    handle: &'a str,
}

/// What a create answers: the handle the web side stores and the secret (hex).
#[derive(Deserialize)]
pub struct Created {
    pub handle: String,
    pub secret: String,
}

#[derive(Deserialize)]
struct Opened {
    secret: String,
}

/// The code a rejection carries (`unsupported`, `cancelled`, `gone`,
/// `failed`); anything without one is `failed`.
fn code_of(err: tauri::plugin::mobile::PluginInvokeError) -> String {
    match err {
        tauri::plugin::mobile::PluginInvokeError::InvokeRejected(response) => {
            response.code.unwrap_or_else(|| "failed".to_owned())
        }
        _ => "failed".to_owned(),
    }
}

impl<R: Runtime> BiometricKey<R> {
    /// A fresh key, a secret sealed to it, and one prompt that opens it.
    pub fn create(&self, reason: &str, cancel_title: &str) -> Result<Created, String> {
        self.0
            .run_mobile_plugin("create", Request { handle: None, reason, cancel_title })
            .map_err(code_of)
    }

    /// The secret of a handle, behind the prompt.
    pub fn open(&self, handle: &str, reason: &str, cancel_title: &str) -> Result<String, String> {
        self.0
            .run_mobile_plugin::<Opened>("open", Request { handle: Some(handle), reason, cancel_title })
            .map(|opened| opened.secret)
            .map_err(code_of)
    }

    /// Deletes the Keystore entry of a handle; a failure leaves an orphan
    /// that opens nothing.
    pub fn delete(&self, handle: &str) {
        let _ = self.0.run_mobile_plugin::<()>("delete", DeleteRequest { handle });
    }
}

/// Access from the app handle.
pub trait BiometricKeyExt<R: Runtime> {
    fn biometric_key(&self) -> &BiometricKey<R>;
}

impl<R: Runtime, T: Manager<R>> BiometricKeyExt<R> for T {
    fn biometric_key(&self) -> &BiometricKey<R> {
        self.state::<BiometricKey<R>>().inner()
    }
}

/// Registers the Kotlin plugin. The app compiles this crate for Android only.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("biometric-key")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            {
                let handle = _api.register_android_plugin(PLUGIN_IDENTIFIER, "BiometricKeyPlugin")?;
                _app.manage(BiometricKey(handle));
            }
            Ok(())
        })
        .build()
}
