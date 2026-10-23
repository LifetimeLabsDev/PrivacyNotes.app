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
pub use android::{authenticate, available, key_create, key_delete, key_open};
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use apple::{authenticate, available};
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use apple_key::{key_create, key_delete, key_open};
#[cfg(target_os = "windows")]
pub use windows_hello::{authenticate, available, key_create, key_delete, key_open};

// ---------------------------------------------------------------------------
// The bound key. The presence gate above only decides whether
// the web side may read a wrap key it stores itself; these three functions
// keep the key in the device's secure hardware instead, so a copy of the app's
// storage holds only ciphertext. Each backend implements:
//
//   key_create(&AppHandle, reason, cancel) -> Result<(handle, secret), KeyFailure>
//   key_open(&AppHandle, handle, reason, cancel) -> Result<secret, KeyFailure>
//   key_delete(&AppHandle, handle)
//
// `create` makes a fresh hardware key, seals a secret to it and opens it once
// behind the biometric prompt (the person's consent and the proof that the key
// opens). `handle` is opaque to the web side and is all it stores; the secret
// never touches storage: the web side derives the wrap key from it and drops
// it. `create` answers Unsupported before any prompt where the device cannot
// bind, and the web side then keeps the presence gate. `open` answers Gone only
// when the OS has destroyed the key for good, which the lock screen turns into
// "set up again" while the PIN and the phrase stay.
// Spec: ops/docs/plans/biometric-key-binding.md (section 8.2)
// ---------------------------------------------------------------------------

/// Why a key operation gave no secret. The string is what the web side reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFailure {
    /// This device cannot hold a bound key; said before any prompt.
    Unsupported,
    /// The person or the system cancelled the prompt, or biometrics are locked out.
    Cancelled,
    /// The OS destroyed the key (the device passcode removed, the key invalidated).
    Gone,
    /// No biometric is enrolled now: the key cannot open, but may again once
    /// one is. Windows Hello has no such state: its PIN always opens the key.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    Unenrolled,
    /// Anything else.
    Failed,
}

impl KeyFailure {
    pub fn code(self) -> &'static str {
        match self {
            KeyFailure::Unsupported => "unsupported",
            KeyFailure::Cancelled => "cancelled",
            KeyFailure::Gone => "gone",
            KeyFailure::Unenrolled => "unenrolled",
            KeyFailure::Failed => "failed",
        }
    }
}

/// Lower-case hex, the form every secret crosses to the web side in.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

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

/// macOS + iOS: the bound key. A Secure Enclave P-256 key whose private half
/// is usable only after a biometric check (`.biometryAny`: any enrolled finger
/// or face, so adding one keeps the key and removing all of them locks it), in
/// the `WhenPasscodeSetThisDeviceOnly` class, so removing the device passcode
/// destroys it. The key is never put in the keychain: the notarized macOS build
/// carries no keychain entitlement, and a permanent enclave key fails there
/// with -34018. The enclave hands back its own sealed copy of the key (the
/// `toid` attribute, the same bytes CryptoKit calls `dataRepresentation`),
/// which only this device's enclave can use and only under the biometric rule,
/// and the handle carries that copy with the ECIES-GCM ciphertext of a random
/// 32-byte secret. The iOS Simulator refuses a biometric enclave key (LAError
/// -1020), so it answers Unsupported there and keeps the presence gate.
/// Raw `msg_send!` and Security calls, for the reason the presence gate gives:
/// no new package.
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple_key {
    use super::{from_hex, to_hex, KeyFailure};
    use objc2::msg_send;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject, Bool};
    use objc2_foundation::{NSError, NSString};
    use std::ffi::c_void;

    type CFTypeRef = *const c_void;
    type CFErrorRef = *mut c_void;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecAttrKeyType: CFTypeRef;
        static kSecAttrKeyTypeECSECPrimeRandom: CFTypeRef;
        static kSecAttrKeySizeInBits: CFTypeRef;
        static kSecAttrTokenID: CFTypeRef;
        static kSecAttrTokenIDSecureEnclave: CFTypeRef;
        static kSecPrivateKeyAttrs: CFTypeRef;
        static kSecAttrIsPermanent: CFTypeRef;
        static kSecAttrAccessControl: CFTypeRef;
        static kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly: CFTypeRef;
        static kSecUseAuthenticationContext: CFTypeRef;
        static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM: CFTypeRef;
        fn SecAccessControlCreateWithFlags(
            allocator: CFTypeRef,
            protection: CFTypeRef,
            flags: usize,
            error: *mut CFErrorRef,
        ) -> CFTypeRef;
        fn SecKeyCreateRandomKey(parameters: CFTypeRef, error: *mut CFErrorRef) -> CFTypeRef;
        fn SecKeyCopyPublicKey(key: CFTypeRef) -> CFTypeRef;
        fn SecKeyCopyAttributes(key: CFTypeRef) -> CFTypeRef;
        fn SecKeyCreateEncryptedData(
            key: CFTypeRef,
            algorithm: CFTypeRef,
            plaintext: CFTypeRef,
            error: *mut CFErrorRef,
        ) -> CFTypeRef;
        fn SecKeyCreateDecryptedData(
            key: CFTypeRef,
            algorithm: CFTypeRef,
            ciphertext: CFTypeRef,
            error: *mut CFErrorRef,
        ) -> CFTypeRef;
        fn SecRandomCopyBytes(rnd: CFTypeRef, count: usize, bytes: *mut u8) -> i32;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(cf: CFTypeRef);
    }

    /// `kSecAccessControlBiometryAny | kSecAccessControlPrivateKeyUsage`.
    const ACCESS_FLAGS: usize = (1 << 1) | (1 << 30);
    const LA_POLICY_BIOMETRICS: isize = 1;
    const SECRET_BYTES: usize = 32;
    /// The handle's version prefix; a handle without it opens nothing.
    const HANDLE_PREFIX: &str = "se1.";

    // LAError codes (LAError.h).
    const LA_AUTHENTICATION_FAILED: isize = -1;
    const LA_USER_CANCEL: isize = -2;
    const LA_USER_FALLBACK: isize = -3;
    const LA_SYSTEM_CANCEL: isize = -4;
    const LA_PASSCODE_NOT_SET: isize = -5;
    const LA_BIOMETRY_NOT_ENROLLED: isize = -7;
    const LA_BIOMETRY_LOCKOUT: isize = -8;
    const LA_APP_CANCEL: isize = -9;
    const LA_NOT_INTERACTIVE: isize = -1004;
    /// errSecUserCanceled
    const SEC_USER_CANCELED: isize = -128;

    /// A +1 Core Foundation reference, released on drop.
    struct Owned(CFTypeRef);
    impl Owned {
        fn new(ptr: CFTypeRef) -> Option<Self> {
            // Lazily: an `Owned(null)` built and dropped would call
            // CFRelease(NULL), which aborts the process.
            (!ptr.is_null()).then(|| Self(ptr))
        }
        fn obj(&self) -> &AnyObject {
            // Every CF type used here is toll-free bridged to its NS twin.
            unsafe { &*(self.0 as *const AnyObject) }
        }
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe { CFRelease(self.0) }
        }
    }

    /// The domain and code of a CFError the call handed back (+1), released here.
    fn take_error(err: CFErrorRef) -> Option<(String, isize)> {
        let err = Owned::new(err as CFTypeRef)?;
        let ns: &NSError = unsafe { &*(err.0 as *const NSError) };
        Some((ns.domain().to_string(), ns.code()))
    }

    fn obj(ptr: CFTypeRef) -> &'static AnyObject {
        unsafe { &*(ptr as *const AnyObject) }
    }

    fn dictionary() -> Retained<AnyObject> {
        let class = AnyClass::get(c"NSMutableDictionary").expect("Foundation is linked");
        unsafe { msg_send![class, dictionary] }
    }

    fn set(dict: &AnyObject, key: CFTypeRef, value: &AnyObject) {
        let _: () = unsafe { msg_send![dict, setObject: value, forKey: obj(key)] };
    }

    fn data(bytes: &[u8]) -> Retained<AnyObject> {
        let class = AnyClass::get(c"NSData").expect("Foundation is linked");
        unsafe { msg_send![class, dataWithBytes: bytes.as_ptr() as *const c_void, length: bytes.len()] }
    }

    fn bytes_of(data: &AnyObject) -> Vec<u8> {
        let len: usize = unsafe { msg_send![data, length] };
        let ptr: *const u8 = unsafe { msg_send![data, bytes] };
        if len == 0 || ptr.is_null() {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
    }

    fn number_int(value: i32) -> Retained<AnyObject> {
        let class = AnyClass::get(c"NSNumber").expect("Foundation is linked");
        unsafe { msg_send![class, numberWithInt: value] }
    }

    fn number_bool(value: bool) -> Retained<AnyObject> {
        let class = AnyClass::get(c"NSNumber").expect("Foundation is linked");
        unsafe { msg_send![class, numberWithBool: Bool::new(value)] }
    }

    fn random_secret() -> Option<[u8; SECRET_BYTES]> {
        let mut out = [0u8; SECRET_BYTES];
        let status = unsafe { SecRandomCopyBytes(std::ptr::null(), SECRET_BYTES, out.as_mut_ptr()) };
        (status == 0).then_some(out)
    }

    fn new_context() -> Option<Retained<AnyObject>> {
        let class = AnyClass::get(c"LAContext")?;
        Some(unsafe { msg_send![class, new] })
    }

    /// The LAError code that keeps this device from a biometric check right
    /// now, or None when one can run.
    fn biometric_blocker(context: &AnyObject) -> Option<isize> {
        let can: Result<(), Retained<NSError>> =
            unsafe { msg_send![context, canEvaluatePolicy: LA_POLICY_BIOMETRICS, error: _] };
        can.err().map(|e| e.code())
    }

    /// The common part of the key attributes: an enclave P-256 key, never stored.
    fn key_attributes() -> Retained<AnyObject> {
        let attrs = dictionary();
        unsafe {
            set(&attrs, kSecAttrKeyType, obj(kSecAttrKeyTypeECSECPrimeRandom));
            set(&attrs, kSecAttrKeySizeInBits, &number_int(256));
            set(&attrs, kSecAttrTokenID, obj(kSecAttrTokenIDSecureEnclave));
        }
        attrs
    }

    pub fn key_create(
        _app: &tauri::AppHandle,
        reason: String,
        _cancel_label: String,
    ) -> Result<(String, String), KeyFailure> {
        let context = new_context().ok_or(KeyFailure::Unsupported)?;
        if biometric_blocker(&context).is_some() {
            return Err(KeyFailure::Unsupported);
        }
        let (handle, secret) = seal_new_secret()?;
        // The read-back: the prompt the person answers, and the proof that the
        // enclave opens what was sealed to it.
        match open_secret(&handle, &reason) {
            Ok(opened) if opened == secret => Ok((handle, to_hex(&secret))),
            Ok(_) => Err(KeyFailure::Failed),
            Err(KeyFailure::Cancelled) => Err(KeyFailure::Cancelled),
            Err(_) => Err(KeyFailure::Failed),
        }
    }

    /// A fresh enclave key and a random secret sealed to its public half, as
    /// a handle. No prompt: only the private half carries the biometric rule.
    fn seal_new_secret() -> Result<(String, [u8; SECRET_BYTES]), KeyFailure> {
        let access = Owned::new(unsafe {
            SecAccessControlCreateWithFlags(
                std::ptr::null(),
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                ACCESS_FLAGS,
                std::ptr::null_mut(),
            )
        })
        .ok_or(KeyFailure::Unsupported)?;

        let private = dictionary();
        unsafe {
            set(&private, kSecAttrIsPermanent, &number_bool(false));
            set(&private, kSecAttrAccessControl, access.obj());
        }
        let attrs = key_attributes();
        unsafe { set(&attrs, kSecPrivateKeyAttrs, &private) };
        let mut err: CFErrorRef = std::ptr::null_mut();
        let key = Owned::new(unsafe {
            SecKeyCreateRandomKey(&*attrs as *const AnyObject as CFTypeRef, &mut err)
        });
        let Some(key) = key else {
            take_error(err);
            return Err(KeyFailure::Unsupported);
        };

        let sealed = {
            let attributes =
                Owned::new(unsafe { SecKeyCopyAttributes(key.0) }).ok_or(KeyFailure::Unsupported)?;
            let toid: Option<Retained<AnyObject>> =
                unsafe { msg_send![attributes.obj(), objectForKey: &*NSString::from_str("toid")] };
            let toid = toid.map(|d| bytes_of(&d)).unwrap_or_default();
            if toid.is_empty() {
                return Err(KeyFailure::Unsupported);
            }
            toid
        };

        let secret = random_secret().ok_or(KeyFailure::Unsupported)?;
        let public = Owned::new(unsafe { SecKeyCopyPublicKey(key.0) }).ok_or(KeyFailure::Unsupported)?;
        let plaintext = data(&secret);
        let mut err: CFErrorRef = std::ptr::null_mut();
        let ciphertext = Owned::new(unsafe {
            SecKeyCreateEncryptedData(
                public.0,
                kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                &*plaintext as *const AnyObject as CFTypeRef,
                &mut err,
            )
        });
        let Some(ciphertext) = ciphertext else {
            take_error(err);
            return Err(KeyFailure::Unsupported);
        };
        let handle = format!("{HANDLE_PREFIX}{}.{}", to_hex(&sealed), to_hex(&bytes_of(ciphertext.obj())));
        Ok((handle, secret))
    }

    pub fn key_open(
        _app: &tauri::AppHandle,
        handle: String,
        reason: String,
        _cancel_label: String,
    ) -> Result<String, KeyFailure> {
        open_secret(&handle, &reason).map(|secret| to_hex(&secret))
    }

    /// Nothing to delete: the key lives only in the handle the web side drops.
    pub fn key_delete(_app: &tauri::AppHandle, _handle: String) {}

    fn parse_handle(handle: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let (sealed, ciphertext) = handle.strip_prefix(HANDLE_PREFIX)?.split_once('.')?;
        let sealed = from_hex(sealed)?;
        let ciphertext = from_hex(ciphertext)?;
        (!sealed.is_empty() && !ciphertext.is_empty()).then_some((sealed, ciphertext))
    }

    /// Rebuild the enclave key from its sealed copy and decrypt the secret.
    /// Blocks while the biometric prompt is up, so never on the main thread.
    fn open_secret(handle: &str, reason: &str) -> Result<Vec<u8>, KeyFailure> {
        let (sealed, ciphertext) = parse_handle(handle).ok_or(KeyFailure::Failed)?;
        let context = new_context().ok_or(KeyFailure::Failed)?;
        // No passcode: its removal destroyed the key's protection class. No
        // finger or face enrolled: the key cannot open now, but `.biometryAny`
        // opens it again once one is. Lockout is a wait, not a loss.
        match biometric_blocker(&context) {
            None => {}
            Some(LA_PASSCODE_NOT_SET) => return Err(KeyFailure::Gone),
            Some(LA_BIOMETRY_NOT_ENROLLED) => return Err(KeyFailure::Unenrolled),
            Some(LA_BIOMETRY_LOCKOUT) => return Err(KeyFailure::Cancelled),
            Some(_) => return Err(KeyFailure::Failed),
        }
        unsafe {
            let _: () = msg_send![&*context, setLocalizedReason: &*NSString::from_str(reason)];
            // An empty title hides the "Enter Password" button: the app's own
            // PIN and phrase are the fallback, and the rule refuses a password.
            let _: () = msg_send![&*context, setLocalizedFallbackTitle: &*NSString::from_str("")];
        }

        let attrs = key_attributes();
        let private = dictionary();
        unsafe {
            set(&private, kSecAttrIsPermanent, &number_bool(false));
            set(&attrs, kSecPrivateKeyAttrs, &private);
            set(&attrs, kSecUseAuthenticationContext, &context);
            let _: () = msg_send![&*attrs, setObject: &*data(&sealed), forKey: &*NSString::from_str("toid")];
        }
        let mut err: CFErrorRef = std::ptr::null_mut();
        let key = Owned::new(unsafe {
            SecKeyCreateRandomKey(&*attrs as *const AnyObject as CFTypeRef, &mut err)
        });
        let Some(key) = key else {
            // The enclave would not take its sealed copy back. That alone does
            // not prove the key is destroyed, and `gone` removes a door, so
            // only the checks above (no biometric enrolled, no passcode) say
            // `gone`; this says `failed`, and the record stays.
            take_error(err);
            return Err(KeyFailure::Failed);
        };

        let input = data(&ciphertext);
        let mut err: CFErrorRef = std::ptr::null_mut();
        let plaintext = Owned::new(unsafe {
            SecKeyCreateDecryptedData(
                key.0,
                kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                &*input as *const AnyObject as CFTypeRef,
                &mut err,
            )
        });
        match plaintext {
            Some(plaintext) => {
                let secret = bytes_of(plaintext.obj());
                if secret.len() == SECRET_BYTES {
                    Ok(secret)
                } else {
                    Err(KeyFailure::Failed)
                }
            }
            None => Err(classify(take_error(err))),
        }
    }

    fn classify(error: Option<(String, isize)>) -> KeyFailure {
        match error {
            Some((domain, code)) if domain == "com.apple.LocalAuthentication" => match code {
                LA_PASSCODE_NOT_SET => KeyFailure::Gone,
                LA_BIOMETRY_NOT_ENROLLED => KeyFailure::Unenrolled,
                LA_USER_CANCEL | LA_SYSTEM_CANCEL | LA_APP_CANCEL | LA_USER_FALLBACK
                | LA_AUTHENTICATION_FAILED | LA_BIOMETRY_LOCKOUT | LA_NOT_INTERACTIVE => {
                    KeyFailure::Cancelled
                }
                _ => KeyFailure::Failed,
            },
            Some((_, SEC_USER_CANCELED)) => KeyFailure::Cancelled,
            _ => KeyFailure::Failed,
        }
    }

    // Runs on a Mac with a Secure Enclave; nothing here shows a prompt.
    #[cfg(all(test, target_os = "macos"))]
    mod tests {
        use super::*;

        #[test]
        #[ignore = "needs a Secure Enclave; CI's macOS runners are VMs without one"]
        fn a_sealed_secret_round_trips_through_its_handle() {
            let (handle, secret) = seal_new_secret().expect("this Mac has a Secure Enclave");
            let (sealed, ciphertext) = parse_handle(&handle).expect("the handle parses");
            assert!(sealed.len() > 100, "the enclave's sealed key is in the handle");
            assert!(ciphertext.len() > SECRET_BYTES);
            assert!(!handle.contains(&to_hex(&secret)), "the secret is not in the handle");
            let (_, other) = seal_new_secret().unwrap();
            assert_ne!(secret, other, "every key seals a fresh secret");
        }

        #[test]
        fn a_null_reference_is_never_released() {
            // Every failed Security call hands back NULL; releasing it aborts.
            assert!(Owned::new(std::ptr::null()).is_none());
            assert!(take_error(std::ptr::null_mut()).is_none());
        }

        #[test]
        fn a_malformed_handle_opens_nothing() {
            for bad in ["", "se1.", "se1.zz.00", "se2.00.00", "se1.00", "se1..00", "se1.0.00"] {
                assert!(parse_handle(bad).is_none(), "{bad:?} parsed");
            }
            assert_eq!(open_secret("se1.zz.00", "reason"), Err(KeyFailure::Failed));
        }

        #[test]
        fn only_a_destroyed_key_reads_as_gone() {
            let la = |code| Some(("com.apple.LocalAuthentication".to_owned(), code));
            assert_eq!(classify(la(LA_BIOMETRY_NOT_ENROLLED)), KeyFailure::Unenrolled);
            assert_eq!(classify(la(LA_PASSCODE_NOT_SET)), KeyFailure::Gone);
            assert_eq!(classify(la(LA_USER_CANCEL)), KeyFailure::Cancelled);
            assert_eq!(classify(la(LA_BIOMETRY_LOCKOUT)), KeyFailure::Cancelled);
            assert_eq!(classify(la(-6)), KeyFailure::Failed);
            assert_eq!(classify(Some(("NSOSStatusErrorDomain".to_owned(), -50))), KeyFailure::Failed);
            assert_eq!(classify(Some(("NSOSStatusErrorDomain".to_owned(), SEC_USER_CANCELED))), KeyFailure::Cancelled);
            assert_eq!(classify(None), KeyFailure::Failed);
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
            .and_then(|op| op.join())
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

        let result = operation.join().map_err(|e| e.to_string())?;
        Ok(result == UserConsentVerificationResult::Verified)
    }

    // The bound key: a Windows Hello key credential (KeyCredentialManager)
    // under a fresh name per enrollment. Hello gives a signing key, not a wrap
    // key, so the secret is the RSA PKCS#1 v1.5 signature (deterministic) over a
    // random 32-byte challenge the handle carries; the web side runs HKDF over
    // it. Hello accepts its own PIN as well as a biometric, as the presence gate
    // above does. Removing Windows Hello deletes every key credential, which
    // `OpenAsync` reports as NotFound: Gone. Enrollment shows two prompts
    // (create, then sign). There is no window-parented entry point for these
    // calls in a Win32 process, so the dialog is the system's own.
    // Spec: ops/docs/plans/biometric-key-binding.md (section 8.2)
    use super::{from_hex, to_hex, KeyFailure};
    use windows::Security::Credentials::{
        KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Storage::Streams::IBuffer;

    const NAME_PREFIX: &str = "PrivacyNotes-bio-";
    /// The random part of a name: 16 bytes as lower-case hex.
    const NAME_SUFFIX_CHARS: usize = 32;
    const HANDLE_PREFIX: &str = "wh1.";
    const CHALLENGE_BYTES: u32 = 32;
    const MIN_SIGNATURE_BYTES: usize = 32;

    fn random(count: u32) -> Result<Vec<u8>, KeyFailure> {
        let buffer = CryptographicBuffer::GenerateRandom(count).map_err(|_| KeyFailure::Unsupported)?;
        bytes_of(&buffer).ok_or(KeyFailure::Unsupported)
    }

    fn bytes_of(buffer: &IBuffer) -> Option<Vec<u8>> {
        let mut out = windows::core::Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(buffer, &mut out).ok()?;
        Some(out.to_vec())
    }

    fn status_failure(status: KeyCredentialStatus) -> KeyFailure {
        match status {
            KeyCredentialStatus::NotFound => KeyFailure::Gone,
            KeyCredentialStatus::UserCanceled | KeyCredentialStatus::SecurityDeviceLocked => {
                KeyFailure::Cancelled
            }
            _ => KeyFailure::Failed,
        }
    }

    fn sign(credential: &KeyCredential, challenge: &[u8]) -> Result<Vec<u8>, KeyFailure> {
        let data = CryptographicBuffer::CreateFromByteArray(challenge).map_err(|_| KeyFailure::Failed)?;
        let result = credential
            .RequestSignAsync(&data)
            .and_then(|op| op.join())
            .map_err(|_| KeyFailure::Failed)?;
        let status = result.Status().map_err(|_| KeyFailure::Failed)?;
        if status != KeyCredentialStatus::Success {
            return Err(status_failure(status));
        }
        let signature = result.Result().ok().and_then(|b| bytes_of(&b)).ok_or(KeyFailure::Failed)?;
        if signature.len() < MIN_SIGNATURE_BYTES {
            return Err(KeyFailure::Failed);
        }
        Ok(signature)
    }

    /// Only a name this app made can be deleted.
    fn delete_name(name: &str) {
        if name.starts_with(NAME_PREFIX) {
            let _ = KeyCredentialManager::DeleteAsync(&HSTRING::from(name)).and_then(|op| op.join());
        }
    }

    /// `wh1.<name>.<hex challenge>`; a name this code did not make, or a
    /// short challenge, is no handle.
    fn parse_handle(handle: &str) -> Option<(String, Vec<u8>)> {
        let (name, challenge) = handle.strip_prefix(HANDLE_PREFIX)?.rsplit_once('.')?;
        let suffix = name.strip_prefix(NAME_PREFIX)?;
        if suffix.len() != NAME_SUFFIX_CHARS || !suffix.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return None;
        }
        let challenge = from_hex(challenge)?;
        (challenge.len() == CHALLENGE_BYTES as usize).then(|| (name.to_owned(), challenge))
    }

    pub fn key_create(
        _app: &tauri::AppHandle,
        _reason: String,
        _cancel_label: String,
    ) -> Result<(String, String), KeyFailure> {
        init_apartment();
        let supported = KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .unwrap_or(false);
        if !supported {
            return Err(KeyFailure::Unsupported);
        }
        let name = format!("{NAME_PREFIX}{}", to_hex(&random(16)?));
        let challenge = random(CHALLENGE_BYTES)?;
        let created = KeyCredentialManager::RequestCreateAsync(
            &HSTRING::from(&name),
            KeyCredentialCreationOption::FailIfExists,
        )
        .and_then(|op| op.join())
        .map_err(|_| KeyFailure::Failed)?;
        let status = created.Status().map_err(|_| KeyFailure::Failed)?;
        if status != KeyCredentialStatus::Success {
            return Err(match status {
                KeyCredentialStatus::UserCanceled | KeyCredentialStatus::SecurityDeviceLocked => {
                    KeyFailure::Cancelled
                }
                _ => KeyFailure::Failed,
            });
        }
        let credential = created.Credential().map_err(|_| KeyFailure::Failed)?;
        match sign(&credential, &challenge) {
            Ok(signature) => Ok((
                format!("{HANDLE_PREFIX}{name}.{}", to_hex(&challenge)),
                to_hex(&signature),
            )),
            Err(failure) => {
                delete_name(&name);
                Err(if failure == KeyFailure::Cancelled {
                    KeyFailure::Cancelled
                } else {
                    KeyFailure::Failed
                })
            }
        }
    }

    pub fn key_open(
        _app: &tauri::AppHandle,
        handle: String,
        _reason: String,
        _cancel_label: String,
    ) -> Result<String, KeyFailure> {
        let (name, challenge) = parse_handle(&handle).ok_or(KeyFailure::Failed)?;
        init_apartment();
        let opened = KeyCredentialManager::OpenAsync(&HSTRING::from(&name))
            .and_then(|op| op.join())
            .map_err(|_| KeyFailure::Failed)?;
        let status = opened.Status().map_err(|_| KeyFailure::Failed)?;
        if status != KeyCredentialStatus::Success {
            return Err(status_failure(status));
        }
        let credential = opened.Credential().map_err(|_| KeyFailure::Failed)?;
        sign(&credential, &challenge).map(|signature| to_hex(&signature))
    }

    pub fn key_delete(_app: &tauri::AppHandle, handle: String) {
        if let Some((name, _)) = parse_handle(&handle) {
            init_apartment();
            delete_name(&name);
        }
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

    // The bound key: plugins/biometric-key (Kotlin) holds an RSA Keystore key
    // that a strong biometric releases through a CryptoObject. The plugin
    // rejects with the same codes KeyFailure carries.
    use tauri_plugin_biometric_key::BiometricKeyExt;

    fn failure(code: String) -> super::KeyFailure {
        match code.as_str() {
            "unsupported" => super::KeyFailure::Unsupported,
            "cancelled" => super::KeyFailure::Cancelled,
            "gone" => super::KeyFailure::Gone,
            "unenrolled" => super::KeyFailure::Unenrolled,
            _ => super::KeyFailure::Failed,
        }
    }

    pub fn key_create(
        app: &tauri::AppHandle,
        reason: String,
        cancel_label: String,
    ) -> Result<(String, String), super::KeyFailure> {
        app.biometric_key()
            .create(&reason, &cancel_label)
            .map(|created| (created.handle, created.secret))
            .map_err(failure)
    }

    pub fn key_open(
        app: &tauri::AppHandle,
        handle: String,
        reason: String,
        cancel_label: String,
    ) -> Result<String, super::KeyFailure> {
        app.biometric_key().open(&handle, &reason, &cancel_label).map_err(failure)
    }

    pub fn key_delete(app: &tauri::AppHandle, handle: String) {
        app.biometric_key().delete(&handle);
    }
}
