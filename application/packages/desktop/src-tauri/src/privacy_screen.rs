//! The cover iOS photographs in place of the notes.
//!
//! iOS takes a picture of an app as it leaves the screen and shows that picture
//! in the app switcher. The picture is also written to disk under the app's own
//! caches. An open note is readable in both, and the app lock never runs,
//! because the app was never opened.
//!
//! There is no flag for this on iOS the way there is on Android. The fix is to
//! put an opaque view over the app's own window before the picture is taken and
//! take it away when the app comes back. It has to be a native view: when iOS
//! backgrounds an app the web content process is already being suspended, so a
//! cover painted from JavaScript races the picture and loses.
//! Spec: ops/docs/plans/app-switcher-privacy-screen.md
//!
//! Bound with raw `msg_send!` like `biometric.rs` and `print.rs`, so no new
//! package enters Cargo.lock: UIKit is linked already by tao and wry.
//!
//! **The notification is `willResignActive`, on every device, and the choice is
//! the whole feature.** Apple documents `didEnterBackground` as the hook for the
//! snapshot, and it is the tidier answer: it fires for a backgrounding and
//! nothing else. It also does not fire when somebody opens the app switcher and
//! looks, because that never reaches the background - the app goes inactive and
//! stays there. So the one case this feature exists for is the one case that
//! hook misses.
//!
//! The Android half learned the same lesson the expensive way: `onPause` looked
//! right, and pressing recents from inside the app never pauses the activity.
//! Losing focus is the signal on both platforms.
//!
//! `willResignActive` also fires for things that are not a backgrounding: a
//! system prompt, Control Center, an incoming call, the in-app purchase sheet.
//! Each of those puts the cover behind something the user is already looking at,
//! which costs nothing. The one place it shows is an iPad in Split View, where
//! the unfocused pane resigns active and goes black while the other pane is
//! used. That is the accepted cost of the hook that works.

use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "ios")]
use block2::RcBlock;
#[cfg(target_os = "ios")]
use objc2::msg_send;
#[cfg(target_os = "ios")]
use objc2::rc::Retained;
#[cfg(target_os = "ios")]
use objc2::runtime::{AnyClass, AnyObject};
#[cfg(target_os = "ios")]
use objc2_foundation::{NSRect, NSString};

/// Whether the app lock is on. Pushed by the frontend, which is the only side
/// that knows. False until it pushes, which is safe: enabling the app lock
/// strips the stored phrase, so a cold start with it on shows the lock screen
/// and a picture taken in that window holds no notes.
static ARMED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "ios")]
/// Identifies the cover among the window's subviews, so adding and removing it
/// needs no global of our own. `viewWithTag:` is the UIKit way to find a view
/// you put somewhere, and everything here runs on the main thread anyway.
const COVER_TAG: isize = 0x504E_4353;

#[cfg(target_os = "ios")]
/// `UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight`, so a
/// rotation while the app is away cannot leave an uncovered strip.
const FLEXIBLE_SIZE: usize = (1 << 1) | (1 << 4);

/// The frontend's push. Also the switch that disarms, which is the half that
/// breaks in silence: a cover that never comes off is a protection the user
/// took away and still has.
pub fn set(enabled: bool) {
    ARMED.store(enabled, Ordering::Relaxed);
}

#[cfg(target_os = "ios")]
/// Watch the two transitions. Called once from the app's setup, on the main
/// thread. The observers live for the life of the process on purpose: there is
/// no later moment at which not covering the app would be correct.
pub fn observe() {
    let Some(centre) = notification_centre() else {
        return;
    };

    add_observer(&centre, "UIApplicationWillResignActiveNotification", cover);
    add_observer(&centre, "UIApplicationDidBecomeActiveNotification", uncover);
}

#[cfg(target_os = "ios")]
fn notification_centre() -> Option<Retained<AnyObject>> {
    let class = AnyClass::get(c"NSNotificationCenter")?;
    unsafe { Some(msg_send![class, defaultCenter]) }
}

#[cfg(target_os = "ios")]
/// The queue argument is null on purpose: UIKit posts both of these on the main
/// thread, so the block already runs where UIKit requires it, and asking for
/// the main queue instead would defer the work to a later turn of the run loop.
/// Later is exactly what this cannot be.
///
/// The returned observer token is deliberately leaked. Dropping it would
/// unregister the observer, and there is no point in the process's life at
/// which we want that.
fn add_observer(centre: &Retained<AnyObject>, name: &str, action: fn()) {
    let name = NSString::from_str(name);
    let block = RcBlock::new(move |_note: *mut AnyObject| action());
    unsafe {
        let token: Retained<AnyObject> = msg_send![
            &**centre,
            addObserverForName: &*name,
            object: std::ptr::null_mut::<AnyObject>(),
            queue: std::ptr::null_mut::<AnyObject>(),
            usingBlock: &*block,
        ];
        std::mem::forget(token);
        std::mem::forget(block);
    }
}

#[cfg(target_os = "ios")]
fn cover() {
    if !ARMED.load(Ordering::Relaxed) {
        return;
    }
    let Some(window) = host_window() else {
        return;
    };
    let Some(class) = AnyClass::get(c"UIView") else {
        return;
    };
    unsafe {
        // Already covered: two notifications can both fire before the app comes
        // back, and a second view over the first would never be removed.
        let existing: *mut AnyObject = msg_send![&*window, viewWithTag: COVER_TAG];
        if !existing.is_null() {
            return;
        }
        // `new` then `setFrame:`, not `alloc` + `initWithFrame:`: objc2 models
        // the allocated-but-uninitialised state as its own type, which an
        // `AnyObject` binding cannot hold. `print.rs` builds its webview the
        // same way, for the same reason.
        let bounds: NSRect = msg_send![&*window, bounds];
        let view: Retained<AnyObject> = msg_send![class, new];
        let _: () = msg_send![&*view, setFrame: bounds];
        let _: () = msg_send![&*view, setTag: COVER_TAG];
        let _: () = msg_send![&*view, setAutoresizingMask: FLEXIBLE_SIZE];
        if let Some(black) = black() {
            let _: () = msg_send![&*view, setBackgroundColor: &*black];
        }
        let _: () = msg_send![&*window, addSubview: &*view];
    }
}

#[cfg(target_os = "ios")]
/// Runs whatever the armed state is. A user who turns the app lock off while
/// the app is away must not come back to an opaque rectangle.
fn uncover() {
    let Some(window) = host_window() else {
        return;
    };
    unsafe {
        let existing: *mut AnyObject = msg_send![&*window, viewWithTag: COVER_TAG];
        if existing.is_null() {
            return;
        }
        let _: () = msg_send![existing, removeFromSuperview];
    }
}

/// Black, on every theme. It could as easily be the app's own surface colour,
/// which the frontend already computes for the Android bar strips, but the two
/// platforms could not agree on it: above API 33 Android draws its own card and
/// gives us no say in its colour. One fixed colour on the side we control is
/// the honest version of a consistent look.
#[cfg(target_os = "ios")]
fn black() -> Option<Retained<AnyObject>> {
    let class = AnyClass::get(c"UIColor")?;
    unsafe { Some(msg_send![class, blackColor]) }
}

#[cfg(target_os = "ios")]
/// The window the cover goes over. `keyWindow` is null in some states, hence
/// the fallback; `print.rs` reaches the same view the same way.
fn host_window() -> Option<Retained<AnyObject>> {
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

/// Nothing to watch anywhere else: Android sets a window property of its own
/// from MainActivity.kt, and no desktop leaves a stored picture behind.
#[cfg(not(target_os = "ios"))]
pub fn observe() {}
