//! No form bar above the iOS keyboard.
//!
//! WKWebView puts its own bar (previous, next, Done) above the keyboard for
//! every focused field. The note editor has a format bar of its own that sits
//! on the keyboard, so the system bar only stacks a second row between the two
//! and takes the space of a line of text (GitHub #533).
//!
//! There is no setting for it. The bar is the `inputAccessoryView` of the web
//! view's private content view (`WKContentView`), which UIKit asks for each time
//! a field takes focus. The content view is moved to a subclass made at run
//! time whose `inputAccessoryView` returns nil, the way Capacitor's keyboard
//! plugin hides the same bar. A load can replace the content view, so this runs
//! again on every page load; a view already moved is left alone.
//!
//! Bound with raw `msg_send!` like `privacy_screen.rs`, so no new package
//! enters Cargo.lock: UIKit and WebKit are linked already by tao and wry.

use objc2::msg_send;
use objc2::runtime::{AnyClass, AnyObject, ClassBuilder, Sel};
use objc2::sel;

const SUBCLASS: &std::ffi::CStr = c"PNContentViewNoAccessory";

extern "C" fn no_accessory(_this: *mut AnyObject, _cmd: Sel) -> *mut AnyObject {
    std::ptr::null_mut()
}

/// The subclass of `base` with no accessory view, made once.
unsafe fn subclass_of(base: &AnyClass) -> Option<&'static AnyClass> {
    if let Some(existing) = AnyClass::get(SUBCLASS) {
        return Some(existing);
    }
    let mut builder = ClassBuilder::new(SUBCLASS, base)?;
    builder.add_method(
        sel!(inputAccessoryView),
        no_accessory as extern "C" fn(*mut AnyObject, Sel) -> *mut AnyObject,
    );
    Some(builder.register())
}

/// Moves the web view's content view to the subclass. `webview` is the
/// WKWebView the window renders in.
pub unsafe fn hide(webview: *mut AnyObject) {
    if webview.is_null() {
        return;
    }
    let scroll: *mut AnyObject = msg_send![webview, scrollView];
    if scroll.is_null() {
        return;
    }
    let subviews: *mut AnyObject = msg_send![scroll, subviews];
    let count: usize = msg_send![subviews, count];
    for i in 0..count {
        let view: *mut AnyObject = msg_send![subviews, objectAtIndex: i];
        let Some(view) = view.as_ref() else { continue };
        let class = view.class();
        let name = class.name().to_bytes();
        if name == SUBCLASS.to_bytes() {
            return;
        }
        if name.starts_with(b"WKContent") {
            if let Some(sub) = subclass_of(class) {
                AnyObject::set_class(view, sub);
                // A field that already has focus keeps the bar it was given
                // until UIKit asks again.
                let _: () = msg_send![view, reloadInputViews];
            }
            return;
        }
    }
}

/// Runs `hide` on a web view of the app.
pub fn hide_in<R: tauri::Runtime>(view: &tauri::Webview<R>) {
    let _ = view.with_webview(|webview| unsafe {
        hide(webview.inner() as *mut AnyObject);
    });
}
