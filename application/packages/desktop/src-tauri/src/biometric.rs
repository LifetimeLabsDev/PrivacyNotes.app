//! Native biometric gate for the platforms whose OS actually exposes one:
//! Touch ID / Face ID via LocalAuthentication on macOS + iOS, Windows Hello via
//! UserConsentVerifier on Windows, BiometricPrompt via androidx.biometric on
//! Android.
//!
//! Why this exists at all: the app renders in an embedded webview (WKWebView,
//! WebView2), and those expose no WebAuthn platform authenticator, so
//! `isUserVerifyingPlatformAuthenticatorAvailable()` resolves to false and the
//! web biometric path is dead in every native build. Security > Biometric Lock
//! claimed "not available on this device" on hardware that very much has it.
//! Spec: ops/docs/biometric-unlock.md (section 3.2 native path), backlog #101.
//!
//! Security level is unchanged from the web path by design: biometrics are a
//! *presence gate*, not a key source. The phrase stays wrapped with a random
//! AES-GCM key held in the webview's localStorage (packages/web/src/biometric.ts);
//! this module only decides whether that unwrap is allowed to proceed.
//!
//! build.rs sets the `native_biometric` cfg for exactly the targets below, so
//! lib.rs never repeats the target list and Linux keeps reporting "unavailable"
//! through the same commands. Each backend implements the same two functions,
//! and owns its own threading etiquette because the platforms want opposite
//! things (LAContext needs the main thread, Hello must not block it):
//!
//!   available(&AppHandle) -> bool                                     cheap, no UI
//!   authenticate(&AppHandle, String, String) -> Result<bool, String>  blocking
//!
//! Both strings are translated by the caller, because the OS renders them: the
//! reason for the prompt, then the label for its cancel button. Only Android
//! draws that button itself and so is the only backend that reads the second
//! string; macOS, iOS and Windows get one from the system, in the system's own
//! language.
//!
//! `authenticate` is always called from a blocking task, never the main thread.
//! `Ok(false)` is every flavour of "no" a user or the OS can produce (cancelled,
//! wrong finger, fell back, system interrupt); the caller only has to keep the
//! app locked. `Err` means no prompt could be shown at all.

#[cfg(target_os = "android")]
pub use android::{authenticate, available};
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use apple::{authenticate, available};
#[cfg(target_os = "windows")]
pub use windows_hello::{authenticate, available};

/// macOS + iOS: `LAContext`, bound with raw `msg_send!` rather than the
/// `objc2-local-authentication` bindings so that no new package enters
/// Cargo.lock - objc2, block2 and objc2-foundation are already in the tree via
/// tao/wry on Apple targets.
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    use block2::RcBlock;
    use objc2::msg_send;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject, Bool};
    use objc2_foundation::{NSError, NSString};
    use std::sync::mpsc::Sender;
    use std::time::Duration;

    /// `LAPolicyDeviceOwnerAuthenticationWithBiometrics` - biometrics only, no
    /// device-passcode fallback. The app's own PIN / recovery-phrase fallback
    /// covers the "biometrics won't play" case, so offering the OS passcode here
    /// would only weaken the gate (any passerby who knows it could pass).
    /// Deliberately not `...WithBiometricsOrCompanion` (Apple Watch):
    /// availability would flap with whether a watch happens to be nearby.
    const LA_POLICY_BIOMETRICS: isize = 1;

    /// `LocalAuthentication.framework` is linked in build.rs. Safe to call off the
    /// main thread; only `evaluate` needs main-thread scheduling.
    fn new_context() -> Option<Retained<AnyObject>> {
        let class = AnyClass::get(c"LAContext")?;
        Some(unsafe { msg_send![class, new] })
    }

    /// Usable biometrics right now? False on hardware without a sensor, with
    /// nothing enrolled, when the user denied the app Face ID access, or while
    /// biometry is locked out after too many failed attempts (the OS then wants a
    /// passcode unlock first).
    pub fn available(_app: &tauri::AppHandle) -> bool {
        let Some(context) = new_context() else {
            return false;
        };
        let can: Result<(), Retained<NSError>> =
            unsafe { msg_send![&*context, canEvaluatePolicy: LA_POLICY_BIOMETRICS, error: _] };
        can.is_ok()
    }

    /// The cancel label is unused here: LocalAuthentication draws the button and
    /// localizes it itself.
    pub fn authenticate(
        app: &tauri::AppHandle,
        reason: String,
        _cancel_label: String,
    ) -> Result<bool, String> {
        let (tx, rx) = std::sync::mpsc::channel();
        app.run_on_main_thread(move || evaluate(&reason, tx))
            .map_err(|e| e.to_string())?;
        // Belt and braces: LocalAuthentication owns the prompt's lifetime, so a
        // reply that never arrives would otherwise park this thread forever.
        rx.recv_timeout(Duration::from_secs(180))
            .map_err(|_| "The biometric prompt closed unexpectedly.".to_owned())?
    }

    /// Presents the system biometric sheet and reports the outcome through `tx`.
    /// MUST run on the main thread: the sheet attaches to the app's key window.
    /// Returns as soon as the prompt is up; the reply block fires later, on an
    /// arbitrary queue.
    fn evaluate(reason: &str, tx: Sender<Result<bool, String>>) {
        let Some(context) = new_context() else {
            let _ = tx.send(Err("LocalAuthentication is unavailable.".to_owned()));
            return;
        };
        let reason = NSString::from_str(reason);

        // Take the pointer before the block swallows `context`: LAContext cancels a
        // pending evaluation when it is released, so the block has to own the only
        // strong reference and outlive the prompt. LocalAuthentication copies the
        // block and releases it after the reply, which frees the context with it.
        let context_ptr: *const AnyObject = &*context;
        let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
            let _keep_context_alive = &context;
            let _ = tx.send(Ok(success.as_bool()));
        });

        unsafe {
            let _: () = msg_send![
                context_ptr,
                evaluatePolicy: LA_POLICY_BIOMETRICS,
                localizedReason: &*reason,
                reply: &*reply,
            ];
        }
    }
}

/// Windows: `UserConsentVerifier` (Windows Hello). Both crates are already in the
/// tree via tauri/tao, so this adds features, not packages.
#[cfg(target_os = "windows")]
mod windows_hello {
    use tauri::Manager;
    use windows::core::{factory, HSTRING};
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
    use windows_future::IAsyncOperation;

    /// `Available` means Hello is set up with enrolled biometrics. Every other
    /// value (no sensor, not configured, disabled by policy, device busy) is a
    /// no, and correctly leaves the toggle hidden.
    pub fn available(_app: &tauri::AppHandle) -> bool {
        init_apartment();
        UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|op| op.get())
            .map(|availability| availability == UserConsentVerifierAvailability::Available)
            .unwrap_or(false)
    }

    /// The cancel label is unused here: Hello draws the button and localizes it
    /// itself.
    pub fn authenticate(
        app: &tauri::AppHandle,
        reason: String,
        _cancel_label: String,
    ) -> Result<bool, String> {
        let hwnd = app
            .get_webview_window("main")
            .ok_or_else(|| "No main window to attach the Windows Hello prompt to.".to_owned())?
            .hwnd()
            .map_err(|e| e.to_string())?;

        init_apartment();
        let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
            .map_err(|e| e.to_string())?;

        // A Win32 process MUST go through the interop: the plain
        // UserConsentVerifier::RequestVerificationAsync expects a CoreWindow and
        // fails outside a UWP app. The HWND is what parents the dialog, which is
        // also why this does not have to run on the UI thread - and must not,
        // since awaiting the operation blocks the calling thread.
        let operation: IAsyncOperation<UserConsentVerificationResult> =
            unsafe { interop.RequestVerificationForWindowAsync(hwnd, &HSTRING::from(reason)) }
                .map_err(|e| e.to_string())?;

        let result = operation.get().map_err(|e| e.to_string())?;
        Ok(result == UserConsentVerificationResult::Verified)
    }

    /// WinRT activation needs an initialized apartment, and this runs on a pooled
    /// blocking thread that has none. MTA keeps the wait off any message loop;
    /// `RPC_E_CHANGED_MODE` only means the thread was already initialized, which
    /// is equally fine, so the HRESULT is deliberately ignored.
    fn init_apartment() {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }
    }
}

/// Android: `BiometricPrompt` through `androidx.biometric`, reached with the
/// official Tauri biometric plugin. The other two backends call the OS from Rust;
/// this one cannot, because the API is Kotlin and the prompt has to attach to an
/// Activity, so the plugin ships the native half and this module only maps its
/// result onto the shared contract. The plugin's own commands are never granted
/// to the webview - nothing but these two functions reaches it.
#[cfg(target_os = "android")]
mod android {
    use tauri_plugin_biometric::{AuthOptions, BiometricExt};

    /// Usable biometrics right now? False on hardware without a sensor, with no
    /// finger or face enrolled, while the sensor is locked out after too many
    /// failed attempts, or when a pending security update has disabled it. The
    /// question asks for the same class of biometric the prompt below requests,
    /// so this answer cannot promise a prompt that then refuses to appear.
    pub fn available(app: &tauri::AppHandle) -> bool {
        app.biometric()
            .status()
            .map(|status| status.is_available)
            .unwrap_or(false)
    }

    pub fn authenticate(
        app: &tauri::AppHandle,
        reason: String,
        cancel_label: String,
    ) -> Result<bool, String> {
        let options = AuthOptions {
            // The prompt puts its title in the one line the user actually reads,
            // and falls back to an untranslated English "Fingerprint
            // Authentication" when there is none - so the caller's translated
            // reason goes here, and the description below it stays empty rather
            // than repeating it.
            title: Some(reason),
            cancel_title: Some(cancel_label),
            // Biometrics only, the same policy as the Apple backend: the device
            // PIN or pattern is a weaker gate than the app's own, and the app
            // already offers its PIN and the recovery phrase when biometrics
            // will not play.
            allow_device_credential: false,
            ..Default::default()
        };
        // Every "no" arrives as a rejection - cancelled, wrong finger, locked
        // out, no prompt at all - with no way to tell a refusal from a fault.
        // The caller does the same thing for all of them, so they collapse into
        // one answer here and none of them is an Err.
        Ok(app.biometric().authenticate(String::new(), options).is_ok())
    }
}
