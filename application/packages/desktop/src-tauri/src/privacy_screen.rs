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
//!
//! The capture block on iOS has no API either. It uses the one thing iOS keeps
//! out of every screenshot and recording, the content of a password field: the
//! app's window layer is moved inside the drawing layer of a secure text field,
//! so a capture shows the field's black background instead (the shield below).
//! That is undocumented and an iOS update can end it without a sign, which the
//! setting's own line allows for. Where the shield cannot be put in place, the
//! cover above stays up while the screen is recorded or mirrored instead. On
//! macOS and Windows the capture block is a window property, set by
//! `set_capture_block` below. Spec: ops/docs/plans/app-switcher-privacy-screen.md (section 14)

use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "ios")]
use std::sync::atomic::AtomicPtr;

#[cfg(target_os = "ios")]
use block2::RcBlock;
#[cfg(target_os = "ios")]
use objc2::msg_send;
#[cfg(target_os = "ios")]
use objc2::rc::Retained;
#[cfg(target_os = "ios")]
use objc2::runtime::{AnyClass, AnyObject, Bool};
#[cfg(target_os = "ios")]
use objc2_foundation::{NSRect, NSString};

/// Whether the app lock or the capture block is on. Pushed by the frontend,
/// which is the only side that knows. False until it pushes, which is safe:
/// enabling the app lock strips the stored phrase, so a cold start with it on
/// shows the lock screen and a picture taken in that window holds no notes.
static ARMED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "ios")]
/// Whether the user turned on the capture block on this device.
static CAPTURE_BLOCK: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "ios")]
/// Between `willResignActive` and `didBecomeActive`. The cover has two reasons
/// to be up, so the notifications record the state and `refresh` decides.
static INACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "ios")]
/// The secure text field whose drawing layer holds the window's layer while the
/// capture block is on, retained here and null while it is off. Touched on the
/// main thread only.
static SHIELD: AtomicPtr<AnyObject> = AtomicPtr::new(std::ptr::null_mut());

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

/// The frontend's push for the capture block. Off is the half that matters as
/// much as on: a cover or a flag that stays after the switch is off is a
/// window the user can no longer capture for no reason they can see.
#[cfg(target_os = "ios")]
pub fn set_capture_block<R: tauri::Runtime>(app: &tauri::AppHandle<R>, enabled: bool) {
    CAPTURE_BLOCK.store(enabled, Ordering::Relaxed);
    // A recording that is already running must be covered now, not at the
    // next notification. UIKit work belongs on the main thread.
    let _ = app.run_on_main_thread(refresh);
}

/// macOS sets the window's sharing type to none and Windows excludes it from
/// capture, so a screenshot, a recording or a shared screen shows what is
/// behind the window. Linux has no such property and the switch is not
/// offered there, so this call is a no-op on it.
#[cfg(desktop)]
pub fn set_capture_block<R: tauri::Runtime>(app: &tauri::AppHandle<R>, enabled: bool) {
    use tauri::Manager;
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_content_protected(enabled);
    }
}

/// Android raises FLAG_SECURE from MainActivity.kt, through its own bridge.
#[cfg(target_os = "android")]
pub fn set_capture_block<R: tauri::Runtime>(_app: &tauri::AppHandle<R>, _enabled: bool) {}

#[cfg(target_os = "ios")]
/// Watch the two transitions and the screen capture state. Called once from
/// the app's setup, on the main thread. The observers live for the life of the
/// process on purpose: there is no later moment at which not covering the app
/// would be correct.
pub fn observe() {
    let Some(centre) = notification_centre() else {
        return;
    };

    add_observer(&centre, "UIApplicationWillResignActiveNotification", resign);
    add_observer(&centre, "UIApplicationDidBecomeActiveNotification", activate);
    add_observer(&centre, "UIScreenCapturedDidChangeNotification", refresh);
    // The shield's frame follows the window through a rotation. Counted, so
    // asking for the notifications cannot stop them for anybody else.
    if let Some(class) = AnyClass::get(c"UIDevice") {
        unsafe {
            let device: *mut AnyObject = msg_send![class, currentDevice];
            if !device.is_null() {
                let _: () = msg_send![device, beginGeneratingDeviceOrientationNotifications];
            }
        }
    }
    add_observer(&centre, "UIDeviceOrientationDidChangeNotification", refresh);
}

#[cfg(target_os = "ios")]
fn resign() {
    INACTIVE.store(true, Ordering::Relaxed);
    refresh();
}

#[cfg(target_os = "ios")]
fn activate() {
    INACTIVE.store(false, Ordering::Relaxed);
    refresh();
}

#[cfg(target_os = "ios")]
/// Put the cover up or take it down, from the state and nothing else. Runs
/// whatever the armed state is on the way back: a user who turns the app lock
/// off while the app is away must not come back to an opaque rectangle.
fn refresh() {
    let blocked = CAPTURE_BLOCK.load(Ordering::Relaxed);
    let shielded = if blocked {
        shield_on()
    } else {
        shield_off();
        false
    };
    let away = INACTIVE.load(Ordering::Relaxed) && ARMED.load(Ordering::Relaxed);
    // The fallback only: with the shield in place a recording already shows
    // black, and the cover would black out the user's own screen for nothing.
    let recorded = blocked && !shielded && screen_captured();
    if away || recorded {
        cover();
    } else {
        uncover();
    }
}

#[cfg(target_os = "ios")]
/// Put the window's layer inside a secure text field, or refit it when it is
/// already there. Returns whether the shield is in place.
///
/// Ported from the react-native-screenguard package, which Notesnook ships,
/// with two changes. A window with no superlayer is refused rather than given
/// the field as a subview, because moving a window's layer into a layer the
/// window itself holds makes a cycle. And the field takes the window's place in
/// the layer order, so taking the shield away puts the window back where it was.
fn shield_on() -> bool {
    let Some(window) = host_window() else {
        return false;
    };
    unsafe {
        let bounds: NSRect = msg_send![&*window, bounds];
        let existing = SHIELD.load(Ordering::Relaxed);
        if !existing.is_null() {
            let _: () = msg_send![existing, setFrame: bounds];
            return true;
        }
        let Some(class) = AnyClass::get(c"UITextField") else {
            return false;
        };
        let layer: *mut AnyObject = msg_send![&*window, layer];
        let home: *mut AnyObject = msg_send![layer, superlayer];
        if home.is_null() {
            return false;
        }
        let field: Retained<AnyObject> = msg_send![class, new];
        let _: () = msg_send![&*field, setFrame: bounds];
        let _: () = msg_send![&*field, setUserInteractionEnabled: Bool::NO];
        let _: () = msg_send![&*field, setSecureTextEntry: Bool::YES];
        if let Some(black) = black() {
            let _: () = msg_send![&*field, setBackgroundColor: &*black];
        }
        let field_layer: *mut AnyObject = msg_send![&*field, layer];
        let _: () = msg_send![home, insertSublayer: field_layer, above: layer];
        // The first sublayer is the field's text canvas, the layer iOS leaves
        // out of captures while the field is secure. No canvas means this iOS
        // draws the field some other way, and the cover takes over.
        let sublayers: *mut AnyObject = msg_send![field_layer, sublayers];
        let canvas: *mut AnyObject = if sublayers.is_null() {
            std::ptr::null_mut()
        } else {
            msg_send![sublayers, firstObject]
        };
        if canvas.is_null() {
            let _: () = msg_send![field_layer, removeFromSuperlayer];
            return false;
        }
        let _: () = msg_send![canvas, addSublayer: layer];
        SHIELD.store(Retained::into_raw(field), Ordering::Relaxed);
    }
    true
}

#[cfg(target_os = "ios")]
/// Take the shield away and put the window's layer back in the field's place.
fn shield_off() {
    let field = SHIELD.swap(std::ptr::null_mut(), Ordering::Relaxed);
    if field.is_null() {
        return;
    }
    unsafe {
        let Some(field) = Retained::from_raw(field) else {
            return;
        };
        let _: () = msg_send![&*field, setSecureTextEntry: Bool::NO];
        let field_layer: *mut AnyObject = msg_send![&*field, layer];
        let home: *mut AnyObject = msg_send![field_layer, superlayer];
        if let Some(window) = host_window() {
            let layer: *mut AnyObject = msg_send![&*window, layer];
            let parent: *mut AnyObject = msg_send![layer, superlayer];
            let parent_home: *mut AnyObject = if parent.is_null() {
                std::ptr::null_mut()
            } else {
                msg_send![parent, superlayer]
            };
            if parent_home == field_layer && !home.is_null() {
                let _: () = msg_send![layer, removeFromSuperlayer];
                let _: () = msg_send![home, insertSublayer: layer, below: field_layer];
            }
        }
        let _: () = msg_send![field_layer, removeFromSuperlayer];
    }
}

#[cfg(target_os = "ios")]
/// True while the screen is recorded, mirrored or sent over AirPlay.
/// `isCaptured` is marked for a future deprecation in favour of the scene trait
/// `sceneCaptureState`. It still answers on every iOS this app supports, and it
/// pairs with a plain notification, where the trait needs a trait observer.
fn screen_captured() -> bool {
    let Some(class) = AnyClass::get(c"UIScreen") else {
        return false;
    };
    unsafe {
        let screen: *mut AnyObject = msg_send![class, mainScreen];
        if screen.is_null() {
            return false;
        }
        let captured: Bool = msg_send![screen, isCaptured];
        captured.as_bool()
    }
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
