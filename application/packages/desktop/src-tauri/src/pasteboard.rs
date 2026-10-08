//! The pictures of the web archive that Safari puts on the pasteboard.
//!
//! A copy of a page selection in Safari writes a web archive
//! (`com.apple.webarchive`) that holds the bytes of every picture in it. The
//! web view hands the page the pasted HTML with each picture as its `https:`
//! address, and the page policy keeps the page off other hosts, so those
//! bytes are reachable only from here. The command takes no argument: it
//! answers from the pasteboard alone and fetches nothing, so a caller cannot
//! point it anywhere.
//!
//! Bound with `msg_send!` rather than the `objc2-app-kit` / `objc2-ui-kit`
//! bindings, so no new package enters Cargo.lock - the same trade
//! `file_assoc.rs` and `biometric.rs` make.
//!
//! Spec: ops/docs/plans/paste-pictures.md (section 3.4)

use serde::Serialize;

/// One picture of the archive. `data` is base64, because the page receives a
/// JSON answer.
#[derive(Serialize)]
pub struct ArchivePicture {
    url: String,
    mime: String,
    data: String,
}

/// A count, the largest per-file cap of any tier, and a total well under what
/// a phone holds comfortably: the base64 answer and its decode are copies too.
/// Safari's archive holds display-size pictures, so the total loses nothing.
#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
const MAX_PICTURES: usize = 30;
#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
const MAX_PICTURE_BYTES: usize = 50 * 1000 * 1000;
#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
const MAX_TOTAL_BYTES: usize = 40 * 1000 * 1000;
/// The archive itself is parsed whole by Foundation, so it is refused above
/// this size before any parse, and only this many entries are looked at.
#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
const MAX_ARCHIVE_BYTES: usize = 60 * 1000 * 1000;
#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
const MAX_ENTRIES: usize = 500;
/// Longer strings are not an address or a type we can use.
#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
const MAX_STRING_BYTES: usize = 16 * 1024;

/// `async` so the read runs off the main thread: iOS can hold the read until
/// the reader answers its "Allow Paste" question.
#[tauri::command]
pub async fn pasteboard_pictures() -> Vec<ArchivePicture> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        apple::read()
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        Vec::new()
    }
}

#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TABLE[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    use std::ffi::{c_char, c_void, CStr};

    use objc2::msg_send;
    use objc2::rc::{autoreleasepool, Retained};
    use objc2::runtime::{AnyClass, AnyObject};
    use objc2_foundation::NSString;

    use super::{
        base64, ArchivePicture, MAX_ARCHIVE_BYTES, MAX_ENTRIES, MAX_PICTURES, MAX_PICTURE_BYTES,
        MAX_STRING_BYTES, MAX_TOTAL_BYTES,
    };

    /// The modern type, then the name older WebKit writes.
    const TYPES: [&str; 2] = ["com.apple.webarchive", "Apple Web Archive pasteboard type"];

    pub fn read() -> Vec<ArchivePicture> {
        autoreleasepool(|_| archive_data().map(|data| parse(&data)).unwrap_or_default())
    }

    fn one_item_array(item: &AnyObject) -> Option<Retained<AnyObject>> {
        let class = AnyClass::get(c"NSArray")?;
        unsafe { msg_send![class, arrayWithObject: item] }
    }

    /// The types are checked first with a call that reads no content, so a
    /// paste with no archive never touches the pasteboard data.
    #[cfg(target_os = "macos")]
    fn archive_data() -> Option<Retained<AnyObject>> {
        let class = AnyClass::get(c"NSPasteboard")?;
        let board: Option<Retained<AnyObject>> = unsafe { msg_send![class, generalPasteboard] };
        let board = board?;
        for name in TYPES {
            let ty = NSString::from_str(name);
            let list = one_item_array(&ty)?;
            let found: Option<Retained<AnyObject>> =
                unsafe { msg_send![&*board, availableTypeFromArray: &*list] };
            if found.is_none() {
                continue;
            }
            let data: Option<Retained<AnyObject>> = unsafe { msg_send![&*board, dataForType: &*ty] };
            if data.is_some() {
                return data;
            }
        }
        None
    }

    #[cfg(target_os = "ios")]
    fn archive_data() -> Option<Retained<AnyObject>> {
        let class = AnyClass::get(c"UIPasteboard")?;
        let board: Option<Retained<AnyObject>> = unsafe { msg_send![class, generalPasteboard] };
        let board = board?;
        for name in TYPES {
            let ty = NSString::from_str(name);
            let list = one_item_array(&ty)?;
            let has: bool = unsafe { msg_send![&*board, containsPasteboardTypes: &*list] };
            if !has {
                continue;
            }
            let data: Option<Retained<AnyObject>> =
                unsafe { msg_send![&*board, dataForPasteboardType: &*ty] };
            if data.is_some() {
                return data;
            }
        }
        None
    }

    fn is_kind(obj: &AnyObject, class_name: &CStr) -> bool {
        let Some(class) = AnyClass::get(class_name) else { return false };
        unsafe { msg_send![obj, isKindOfClass: class] }
    }

    fn value(dict: &AnyObject, key: &str) -> Option<Retained<AnyObject>> {
        let key = NSString::from_str(key);
        unsafe { msg_send![dict, objectForKey: &*key] }
    }

    fn string(obj: &AnyObject) -> Option<String> {
        if !is_kind(obj, c"NSString") {
            return None;
        }
        let len: usize = unsafe { msg_send![obj, length] };
        if len > MAX_STRING_BYTES {
            return None;
        }
        let raw: *const c_char = unsafe { msg_send![obj, UTF8String] };
        if raw.is_null() {
            return None;
        }
        Some(unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned())
    }

    fn bytes(obj: &AnyObject) -> Option<Vec<u8>> {
        if !is_kind(obj, c"NSData") {
            return None;
        }
        let len: usize = unsafe { msg_send![obj, length] };
        if len == 0 || len > MAX_PICTURE_BYTES {
            return None;
        }
        let ptr: *const c_void = unsafe { msg_send![obj, bytes] };
        if ptr.is_null() {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) }.to_vec())
    }

    fn parse(data: &AnyObject) -> Vec<ArchivePicture> {
        let mut out = Vec::new();
        if !is_kind(data, c"NSData") {
            return out;
        }
        let archive_len: usize = unsafe { msg_send![data, length] };
        if archive_len == 0 || archive_len > MAX_ARCHIVE_BYTES {
            return out;
        }
        let Some(class) = AnyClass::get(c"NSPropertyListSerialization") else { return out };
        let plist: Option<Retained<AnyObject>> = unsafe {
            msg_send![
                class,
                propertyListWithData: data,
                options: 0usize,
                format: std::ptr::null_mut::<usize>(),
                error: std::ptr::null_mut::<*mut AnyObject>()
            ]
        };
        let Some(plist) = plist else { return out };
        if !is_kind(&plist, c"NSDictionary") {
            return out;
        }
        let Some(resources) = value(&plist, "WebSubresources") else { return out };
        if !is_kind(&resources, c"NSArray") {
            return out;
        }
        let count: usize = unsafe { msg_send![&*resources, count] };
        let mut total = 0usize;
        for i in 0..count.min(MAX_ENTRIES) {
            if out.len() >= MAX_PICTURES {
                break;
            }
            let item: Option<Retained<AnyObject>> = unsafe { msg_send![&*resources, objectAtIndex: i] };
            let Some(item) = item else { continue };
            if !is_kind(&item, c"NSDictionary") {
                continue;
            }
            let mime = value(&item, "WebResourceMIMEType").and_then(|m| string(&m)).unwrap_or_default();
            if !mime.starts_with("image/") {
                continue;
            }
            let Some(url) = value(&item, "WebResourceURL").and_then(|u| string(&u)) else { continue };
            let Some(raw) = value(&item, "WebResourceData").and_then(|d| bytes(&d)) else { continue };
            total += raw.len();
            if total > MAX_TOTAL_BYTES {
                break;
            }
            out.push(ArchivePicture { url, mime, data: base64(&raw) });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::base64;

    #[test]
    fn base64_matches_the_standard_alphabet_and_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(&[0xff, 0xfe, 0x00]), "//4A");
    }

    /// Manual: copy text and a picture in Safari on this Mac, then run
    /// `cargo test --lib pasteboard -- --ignored --nocapture`.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "reads the real pasteboard after a Safari copy"]
    fn reads_the_safari_archive_on_this_mac() {
        let pictures = super::apple::read();
        for p in &pictures {
            println!("{} {} {} base64 chars", p.url, p.mime, p.data.len());
        }
        assert!(!pictures.is_empty(), "no picture in the pasteboard's web archive");
    }
}
