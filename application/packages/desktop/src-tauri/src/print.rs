//! Native print for the Apple webviews: macOS and iOS.
//!
//! WKWebView does not implement JavaScript's `window.print()`. The call returns
//! without opening anything and without an error, so the hidden-iframe print
//! path in `packages/web/src/export.ts` silently does nothing in the macOS and
//! iOS apps - while working in every browser and in the Windows build, whose
//! WebView2 does implement it.
//!
//! A webview also cannot print a frame inside itself, so the note document is
//! loaded into a throwaway WKWebView of our own and handed to the OS print UI:
//! `NSPrintOperation` on macOS, `UIPrintInteractionController` on iOS. Both take
//! the document exactly as `export.ts` built it - same markup, same `@media
//! print` CSS, same inlined images - so a printed note looks the same on every
//! platform.
//!
//! Bound with raw `msg_send!` like `biometric.rs`, so no new package enters
//! Cargo.lock: WebKit, AppKit and UIKit are all linked already by tao/wry.
//!
//! The throwaway webview is parented at the bottom of the app's own view
//! hierarchy rather than left detached. WebKit throttles a web view that belongs
//! to no window, and the print path needs a laid-out document; the app's opaque
//! root view covers it, so it is never visible. It is torn down as soon as the
//! print UI is finished with it, which is why macOS runs the panel app-modally
//! (`runOperation` returns when the user is done) and iOS does its cleanup in
//! the print controller's completion block.

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Bool};
use objc2::msg_send;
#[cfg(target_os = "macos")]
use objc2::sel;
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};
use std::cell::Cell;

/// A4 at 96dpi. Only the initial layout: both print paths re-lay the document
/// out for whatever paper the user picks in the print UI.
const PAGE_WIDTH: f64 = 794.0;
const PAGE_HEIGHT: f64 = 1123.0;

/// How long to let the document settle before printing. Every image is already
/// inlined as a data URI by the caller, so this normally passes on the first
/// tick; the ceiling is only there so a document that never finishes loading
/// still reaches the print UI instead of hanging silently.
const POLL_SECONDS: f64 = 0.1;
const POLL_TICKS: u32 = 50;

/// Loads `html` into a throwaway webview and presents the OS print UI for it.
///
/// Returns as soon as the work is queued on the main thread - the print UI
/// outlives the call, and the user's choices inside it are their own business.
/// Every UI step below has to be on the main thread: AppKit and UIKit both
/// require it, and WKWebView is main-thread-only in the first place.
pub fn print(app: &tauri::AppHandle, html: String, job_name: String) -> Result<(), String> {
    app.run_on_main_thread(move || {
        let Some(webview) = build_webview() else {
            eprintln!("print: WKWebView is unavailable");
            return;
        };
        attach(&webview);

        let html = NSString::from_str(&html);
        unsafe {
            let _: () = msg_send![
                &*webview,
                loadHTMLString: &*html,
                baseURL: std::ptr::null_mut::<AnyObject>(),
            ];
        }
        print_when_loaded(webview, job_name);
    })
    .map_err(|e| e.to_string())
}

/// `[[WKWebView alloc] init]`, then a frame: the zero frame a bare `init` leaves
/// behind lays nothing out, and an unlaid document prints blank pages.
fn build_webview() -> Option<Retained<AnyObject>> {
    let class = AnyClass::get(c"WKWebView")?;
    unsafe {
        let webview: Retained<AnyObject> = msg_send![class, new];
        let frame = NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(PAGE_WIDTH, PAGE_HEIGHT),
        );
        let _: () = msg_send![&*webview, setFrame: frame];
        Some(webview)
    }
}

/// Polls `isLoading` until the document settles, then prints. A repeating
/// `NSTimer` rather than a navigation delegate: the block-based timer keeps
/// every reference on the main thread, where they all have to live anyway, and
/// saves defining an Objective-C delegate class for one callback.
fn print_when_loaded(webview: Retained<AnyObject>, job_name: String) {
    let Some(class) = AnyClass::get(c"NSTimer") else {
        return;
    };
    let ticks_left = Cell::new(POLL_TICKS);

    let tick = RcBlock::new(move |timer: *mut AnyObject| {
        let loading: Bool = unsafe { msg_send![&*webview, isLoading] };
        if loading.as_bool() && ticks_left.get() > 0 {
            ticks_left.set(ticks_left.get() - 1);
            return;
        }

        // Take owned copies onto the stack BEFORE invalidating: invalidating
        // releases the timer's copy of this very block, which is the only one
        // left, so everything the closure captured is freed mid-call.
        let webview = webview.clone();
        let job_name = job_name.clone();
        unsafe {
            let _: () = msg_send![timer, invalidate];
        }
        present(webview, &job_name);
    });

    unsafe {
        let _: Retained<AnyObject> = msg_send![
            class,
            scheduledTimerWithTimeInterval: POLL_SECONDS,
            repeats: Bool::YES,
            block: &*tick,
        ];
    }
}

/// Parents the webview under the app's own root view, at the bottom of the
/// z-order so the opaque UI hides it.
fn attach(webview: &AnyObject) {
    let Some(host) = host_view() else {
        return;
    };
    unsafe {
        #[cfg(target_os = "macos")]
        {
            // NSWindowBelow: under every sibling, i.e. behind the whole app.
            let _: () = msg_send![
                &*host,
                addSubview: webview,
                positioned: -1isize,
                relativeTo: std::ptr::null_mut::<AnyObject>(),
            ];
        }
        #[cfg(target_os = "ios")]
        {
            let _: () = msg_send![&*host, insertSubview: webview, atIndex: 0isize];
        }
    }
}

/// The app's root view: the key window's content view on macOS, the key window
/// itself on iOS. `keyWindow` is null while the app is in the background or
/// (on iOS) under some scene setups, hence the fallbacks.
#[cfg(target_os = "macos")]
fn host_view() -> Option<Retained<AnyObject>> {
    let class = AnyClass::get(c"NSApplication")?;
    unsafe {
        let app: Retained<AnyObject> = msg_send![class, sharedApplication];
        let mut window: *mut AnyObject = msg_send![&*app, keyWindow];
        if window.is_null() {
            window = msg_send![&*app, mainWindow];
        }
        if window.is_null() {
            return None;
        }
        let view: *mut AnyObject = msg_send![window, contentView];
        Retained::retain(view)
    }
}

#[cfg(target_os = "ios")]
fn host_view() -> Option<Retained<AnyObject>> {
    let class = AnyClass::get(c"UIApplication")?;
    unsafe {
        let app: Retained<AnyObject> = msg_send![class, sharedApplication];
        let mut window: *mut AnyObject = msg_send![&*app, keyWindow];
        if window.is_null() {
            let windows: *mut AnyObject = msg_send![&*app, windows];
            if !windows.is_null() {
                window = msg_send![windows, firstObject];
            }
        }
        Retained::retain(window)
    }
}

/// macOS: the standard print panel, run app-modally. Its "PDF" menu is the
/// "Save as PDF" half of what the menu item promises, so one panel covers both.
#[cfg(target_os = "macos")]
fn present(webview: Retained<AnyObject>, job_name: &str) {
    unsafe {
        // printOperationWithPrintInfo: is macOS 11+. Below that there is no
        // supported way to print a WKWebView, and nothing to fall back to.
        let responds: Bool = msg_send![&*webview, respondsToSelector: sel!(printOperationWithPrintInfo:)];
        if !responds.as_bool() {
            eprintln!("print: this macOS is too old to print a webview");
            return;
        }
        let Some(class) = AnyClass::get(c"NSPrintInfo") else {
            return;
        };
        let info: Retained<AnyObject> = msg_send![class, sharedPrintInfo];
        // The document draws its own 20mm page padding (the @media print block
        // in export.ts), so AppKit's one-inch default margins would stack on
        // top of it and crush the text into the middle of the page.
        let _: () = msg_send![&*info, setTopMargin: 0.0f64];
        let _: () = msg_send![&*info, setRightMargin: 0.0f64];
        let _: () = msg_send![&*info, setBottomMargin: 0.0f64];
        let _: () = msg_send![&*info, setLeftMargin: 0.0f64];

        let operation: Retained<AnyObject> = msg_send![&*webview, printOperationWithPrintInfo: &*info];
        let title = NSString::from_str(job_name);
        let _: () = msg_send![&*operation, setJobTitle: &*title];
        // Blocks until the user prints or cancels, which is what makes the
        // teardown below safe to do inline.
        let _: Bool = msg_send![&*operation, runOperation];

        let _: () = msg_send![&*webview, removeFromSuperview];
    }
}

/// iOS: the system print sheet. Presentation is asynchronous, so the webview has
/// to stay alive and parented until the completion block says otherwise - it is
/// what the print formatter renders from.
#[cfg(target_os = "ios")]
fn present(webview: Retained<AnyObject>, job_name: &str) {
    unsafe {
        let Some(class) = AnyClass::get(c"UIPrintInteractionController") else {
            return;
        };
        let available: Bool = msg_send![class, isPrintingAvailable];
        if !available.as_bool() {
            eprintln!("print: printing is unavailable on this device");
            let _: () = msg_send![&*webview, removeFromSuperview];
            return;
        }
        let controller: Retained<AnyObject> = msg_send![class, sharedPrintController];

        if let Some(info_class) = AnyClass::get(c"UIPrintInfo") {
            let info: Retained<AnyObject> = msg_send![info_class, printInfo];
            let name = NSString::from_str(job_name);
            let _: () = msg_send![&*info, setJobName: &*name];
            let _: () = msg_send![&*controller, setPrintInfo: &*info];
        }

        let formatter: Retained<AnyObject> = msg_send![&*webview, viewPrintFormatter];
        let _: () = msg_send![&*controller, setPrintFormatter: &*formatter];

        // Resolved before the block below takes ownership of the webview: the
        // iPad popover hangs off the same view the webview was parented to.
        let host: *mut AnyObject = msg_send![&*webview, superview];

        // Owns the webview until the sheet is gone, then unparents it. Dropping
        // the block drops the last reference and deallocates it.
        let done = RcBlock::new(
            move |_controller: *mut AnyObject, _completed: Bool, _error: *mut AnyObject| {
                let _: () = msg_send![&*webview, removeFromSuperview];
            },
        );

        // iPad has no modal print sheet: presentAnimated: raises there, and the
        // popover variant is the only supported presentation.
        if is_pad() {
            if host.is_null() {
                return;
            }
            let bounds: NSRect = msg_send![host, bounds];
            let anchor = NSRect::new(
                NSPoint::new(bounds.size.width / 2.0, bounds.size.height / 2.0),
                NSSize::new(1.0, 1.0),
            );
            let _: Bool = msg_send![
                &*controller,
                presentFromRect: anchor,
                inView: host,
                animated: Bool::YES,
                completionHandler: &*done,
            ];
        } else {
            let _: Bool = msg_send![
                &*controller,
                presentAnimated: Bool::YES,
                completionHandler: &*done,
            ];
        }
    }
}

/// `UIUserInterfaceIdiomPad`.
#[cfg(target_os = "ios")]
fn is_pad() -> bool {
    let Some(class) = AnyClass::get(c"UIDevice") else {
        return false;
    };
    unsafe {
        let device: Retained<AnyObject> = msg_send![class, currentDevice];
        let idiom: isize = msg_send![&*device, userInterfaceIdiom];
        idiom == 1
    }
}
