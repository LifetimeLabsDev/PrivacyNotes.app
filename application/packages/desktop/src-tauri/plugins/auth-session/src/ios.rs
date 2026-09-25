//! The ASWebAuthenticationSession sheet, completed on an https callback.

#![allow(non_snake_case)]

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send, AllocAnyThread, MainThreadMarker, MainThreadOnly};
use objc2_authentication_services::{
    ASWebAuthenticationPresentationContextProviding, ASWebAuthenticationSession,
    ASWebAuthenticationSessionCallback, ASWebAuthenticationSessionErrorCode,
    ASWebAuthenticationSessionErrorDomain,
};
use objc2_foundation::{NSError, NSObject, NSObjectProtocol, NSString, NSURL};
use objc2_ui_kit::{UIApplication, UIScene, UIWindowScene};

// The presentation context provider: the object the sheet asks for the window
// to anchor to.

pub struct ProviderIvars {
    _placeholder: Cell<bool>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "TauriAppleAuthPresentationProvider"]
    #[ivars = ProviderIvars]
    pub struct AuthPresentationProvider;

    unsafe impl NSObjectProtocol for AuthPresentationProvider {}

    unsafe impl ASWebAuthenticationPresentationContextProviding for AuthPresentationProvider {
        #[unsafe(method_id(presentationAnchorForWebAuthenticationSession:))]
        fn presentation_anchor(&self, _session: &ASWebAuthenticationSession) -> Retained<NSObject> {
            get_key_window_as_anchor()
        }
    }
);

impl AuthPresentationProvider {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(ProviderIvars {
            _placeholder: Cell::new(false),
        });
        unsafe { msg_send![super(this), init] }
    }
}

/// The first window of a connected scene, as the anchor the sheet presents over.
fn get_key_window_as_anchor() -> Retained<NSObject> {
    let mtm = unsafe { MainThreadMarker::new_unchecked() };
    let app = UIApplication::sharedApplication(mtm);
    let scenes = app.connectedScenes();
    for scene in &scenes {
        // In a Tauri iOS app every connected scene is a UIWindowScene, which is
        // a subclass of UIScene, so the pointer cast is valid.
        let scene_ptr: *const UIScene = &*scene;
        let ws: &UIWindowScene = unsafe { &*(scene_ptr as *const UIWindowScene) };
        let windows = ws.windows();
        if let Some(window) = windows.firstObject() {
            // UIWindow -> UIView -> UIResponder -> NSObject
            return Retained::into_super(Retained::into_super(Retained::into_super(window)));
        }
    }
    panic!("No windows available for ASWebAuthenticationSession presentation anchor");
}

/// Holds the active session and what it depends on, so nothing is released
/// before the completion handler fires. Every access happens on the main
/// thread: creation through `DispatchQueue::main().exec_async`, completion
/// through the framework, which calls the handler on the main thread too.
struct ActiveSession {
    _session: Retained<ASWebAuthenticationSession>,
    _provider: Retained<AuthPresentationProvider>,
    _completion: RcBlock<dyn Fn(*mut NSURL, *mut NSError)>,
}

thread_local! {
    static ACTIVE_SESSION: RefCell<Option<ActiveSession>> = const { RefCell::new(None) };
}

/// Present the sheet and resolve with the callback URL it completes on.
///
/// The callback is an https host and path, which iOS matches against every
/// main-frame navigation in the sheet. The host has to be one of the app's
/// associated web-credentials domains, and that is what binds the return
/// address to this app and to no other. A custom scheme is not offered,
/// because any app can claim one. The exact origin-and-path check on the URL
/// that comes back belongs to the caller, which owns the code exchange.
pub async fn start_session(
    auth_url: String,
    callback_host: String,
    callback_path: String,
) -> Result<String, String> {
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<String, String>>();

    // The session has to be created and started on the main thread.
    dispatch2::DispatchQueue::main().exec_async(move || {
        let mtm = unsafe { MainThreadMarker::new_unchecked() };

        // Drop a previous session whose cleanup has not run yet, such as one
        // that was cancelled.
        ACTIVE_SESSION.with(|s| {
            *s.borrow_mut() = None;
        });

        let url_nsstring = NSString::from_str(&auth_url);
        let Some(url) = NSURL::URLWithString(&url_nsstring) else {
            let _ = tx.send(Err(format!("Invalid auth URL: {auth_url}")));
            return;
        };

        let host = NSString::from_str(&callback_host);
        let path = NSString::from_str(&callback_path);
        let callback =
            unsafe { ASWebAuthenticationSessionCallback::callbackWithHTTPSHost_path(&host, &path) };

        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
        let tx_clone = Arc::clone(&tx);

        let completion_handler =
            RcBlock::new(move |callback_url: *mut NSURL, error: *mut NSError| {
                let result = if !error.is_null() {
                    let error = unsafe { &*error };
                    let domain = error.domain();
                    let code = error.code();

                    let expected_domain: &NSString =
                        unsafe { ASWebAuthenticationSessionErrorDomain };
                    let is_cancelled = *domain == *expected_domain
                        && code == ASWebAuthenticationSessionErrorCode::CanceledLogin.0;

                    if is_cancelled {
                        Err("user_cancelled".to_string())
                    } else {
                        let description = error.localizedDescription();
                        Err(format!("Auth session error: {description}"))
                    }
                } else if callback_url.is_null() {
                    Err("Auth session completed without a callback URL".to_string())
                } else {
                    let url = unsafe { &*callback_url };
                    match url.absoluteString() {
                        Some(s) => Ok(s.to_string()),
                        None => Err("Failed to get callback URL string".to_string()),
                    }
                };

                if let Some(tx) = tx_clone.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(result);
                }

                // Release the session, the provider and this block. Safe because
                // the framework holds its own strong reference to the block for
                // the duration of this call.
                ACTIVE_SESSION.with(|s| {
                    *s.borrow_mut() = None;
                });
            });

        let session = unsafe {
            ASWebAuthenticationSession::initWithURL_callback_completionHandler(
                ASWebAuthenticationSession::alloc(),
                &url,
                &callback,
                RcBlock::as_ptr(&completion_handler),
            )
        };

        // The sheet needs a window to anchor to before it can start.
        let provider = AuthPresentationProvider::new(mtm);
        unsafe {
            session.setPresentationContextProvider(Some(ProtocolObject::from_ref(&*provider)));
        }

        let started = unsafe { session.start() };
        if !started {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(Err("Failed to start ASWebAuthenticationSession".to_string()));
            }
            return;
        }

        // Kept alive until the completion handler clears it.
        ACTIVE_SESSION.with(|s| {
            *s.borrow_mut() = Some(ActiveSession {
                _session: session,
                _provider: provider,
                _completion: completion_handler,
            });
        });
    });

    rx.await
        .unwrap_or_else(|_| Err("Auth session channel dropped unexpectedly".to_string()))
}
