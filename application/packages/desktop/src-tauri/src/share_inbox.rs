//! The inbox of items other apps shared into this one, through the system
//! share sheet.
//!
//! On iOS the share sheet runs our share extension, a separate process that
//! cannot reach the running app. It writes each item into a folder of the app
//! group both processes belong to. On Android the activity receives the share
//! itself (MainActivity.kt) and writes the same layout into the app's own data
//! folder. Either way the app takes the items from there once the user has
//! signed in and cleared the app lock: the frontend drains the inbox from
//! inside the authenticated shell, never before.
//!
//! Layout: `<inbox>/<uuid>/item.json`, plus `<inbox>/<uuid>/payload` for a file.
//! The extension writes an item under a temporary name and renames it into
//! place, so a folder named by a bare UUID is always complete.
//!
//! Everything read here is untrusted: any app on the phone can share into us,
//! and the extension copies what it is given. Kinds are a closed set, the
//! lengths are capped, a link must be http or https, an id must be a UUID
//! before it is joined onto a path, and a file is read only when it is a
//! regular file, never through a link, and never past its cap. An invalid item
//! is deleted; one that cannot be read right now stays for the next drain.
//! Spec: ops/docs/archive/share-into-app.md
#![cfg_attr(not(mobile), allow(dead_code))]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// The app group the iOS app and its share extension both belong to. The
/// extension's Swift source and both entitlements files carry the same string.
#[cfg(target_os = "ios")]
const APP_GROUP: &str = "group.app.privacynotes";

const ITEM_FILE: &str = "item.json";
/// Beside the inbox, never in it: `list_in` would delete it as an invalid item.
/// ShareViewController.swift reads the same name.
#[cfg_attr(not(target_os = "ios"), allow(dead_code))]
const LIMIT_FILE: &str = "ShareLimit";
const PAYLOAD_FILE: &str = "payload";
/// The largest per-file limit the app grants (the storage add-on); the app's
/// own check names the lower limits to the user. The extension holds the same cap.
const MAX_PAYLOAD_BYTES: u64 = 100 * 1000 * 1000;
const MAX_ITEM_JSON_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TEXT_CHARS: usize = 500_000;
const MAX_URL_CHARS: usize = 8_192;
const MAX_SHORT_CHARS: usize = 1_000;
/// A `.tmp-` folder older than this was abandoned by an extension that was
/// stopped mid-copy, and is deleted.
const STALE_TMP: Duration = Duration::from_secs(60 * 60);

#[derive(Deserialize)]
struct RawItem {
    v: u32,
    kind: String,
    created: Option<u64>,
    url: Option<String>,
    title: Option<String>,
    text: Option<String>,
    name: Option<String>,
    mime: Option<String>,
}

/// One item, as the frontend receives it. A `file` carries no bytes here: the
/// frontend reads them with `share_inbox_read` when it stores the file.
#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SharedItem {
    pub id: String,
    pub kind: &'static str,
    pub created: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// A UUID in its canonical text form, either case. The only shape of name
/// that is ever joined onto the inbox path.
fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn capped(s: Option<String>, max: usize) -> Option<String> {
    let s = s?.trim().to_string();
    if s.is_empty() {
        return None;
    }
    Some(s.chars().take(max).collect())
}

fn web_url(s: Option<String>) -> Option<String> {
    let s = s?.trim().to_string();
    if s.chars().count() > MAX_URL_CHARS {
        return None;
    }
    let url = tauri::Url::parse(&s).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.to_string())
}

/// A file name with no directory part, so it can only ever name the file.
fn file_name(s: Option<String>) -> Option<String> {
    let s = capped(s, MAX_SHORT_CHARS)?;
    let last = s.rsplit(['/', '\\']).next().unwrap_or("").trim();
    (!last.is_empty() && last != "." && last != "..").then(|| last.to_string())
}

enum Capped {
    Bytes(Vec<u8>),
    /// Not a regular file, a link, or over the cap: never usable.
    Invalid,
    /// Missing or unreadable now, for example while file protection holds it.
    Unreadable,
}

/// Reads a regular file, never through a link, and never more than `cap`
/// bytes, so a file that grows after the size check is still refused.
fn read_capped(path: &Path, cap: u64) -> Capped {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return Capped::Unreadable };
    if !meta.is_file() || meta.len() > cap {
        return Capped::Invalid;
    }
    let Ok(file) = std::fs::File::open(path) else { return Capped::Unreadable };
    // The path was checked, then opened: refuse it when what was opened is not
    // the file that was checked, which is how a link swapped in between shows.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(opened) = file.metadata() else { return Capped::Unreadable };
        if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
            return Capped::Invalid;
        }
    }
    let mut bytes = Vec::new();
    if file.take(cap + 1).read_to_end(&mut bytes).is_err() {
        return Capped::Unreadable;
    }
    if bytes.len() as u64 > cap {
        return Capped::Invalid;
    }
    Capped::Bytes(bytes)
}

enum ItemRead {
    Item(SharedItem),
    Invalid,
    Unreadable,
}

/// Read and validate one item folder.
fn read_item(dir: &Path, id: &str) -> ItemRead {
    match read_capped(&dir.join(ITEM_FILE), MAX_ITEM_JSON_BYTES) {
        Capped::Bytes(bytes) => parse_item(dir, id, &bytes).map_or(ItemRead::Invalid, ItemRead::Item),
        Capped::Invalid => ItemRead::Invalid,
        Capped::Unreadable => ItemRead::Unreadable,
    }
}

fn parse_item(dir: &Path, id: &str, bytes: &[u8]) -> Option<SharedItem> {
    let raw: RawItem = serde_json::from_slice(bytes).ok()?;
    if raw.v != 1 {
        return None;
    }
    let base = SharedItem {
        id: id.to_string(),
        kind: "text",
        created: raw.created.unwrap_or(0),
        url: None,
        title: None,
        text: None,
        name: None,
        mime: None,
        size: None,
    };
    match raw.kind.as_str() {
        "url" => Some(SharedItem {
            kind: "url",
            url: Some(web_url(raw.url)?),
            title: capped(raw.title, MAX_SHORT_CHARS),
            ..base
        }),
        "text" => Some(SharedItem { kind: "text", text: Some(capped(raw.text, MAX_TEXT_CHARS)?), ..base }),
        "file" => {
            let meta = std::fs::symlink_metadata(dir.join(PAYLOAD_FILE)).ok()?;
            if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_PAYLOAD_BYTES {
                return None;
            }
            Some(SharedItem {
                kind: "file",
                name: Some(file_name(raw.name).unwrap_or_else(|| "file".to_string())),
                mime: capped(raw.mime, MAX_SHORT_CHARS),
                size: Some(meta.len()),
                ..base
            })
        }
        _ => None,
    }
}

/// Every complete item in `inbox`, oldest first. An invalid item is deleted on
/// the way, and so are the `.tmp-` folders a copier abandoned; while any of
/// them is younger than `STALE_TMP` a share is still being written and all of
/// them are left alone.
pub fn list_in(inbox: &Path) -> Vec<SharedItem> {
    let Ok(entries) = std::fs::read_dir(inbox) else { return Vec::new() };
    let mut items = Vec::new();
    let mut temps = Vec::new();
    for entry in entries.flatten() {
        let Some(id) = entry.file_name().to_str().map(str::to_string) else { continue };
        let path = entry.path();
        let Ok(kind) = entry.file_type() else { continue };
        if !is_uuid(&id) {
            if id.starts_with(".tmp-") && kind.is_dir() {
                temps.push(path);
            }
            continue;
        }
        let read = if kind.is_dir() { read_item(&path, &id) } else { ItemRead::Invalid };
        match read {
            ItemRead::Item(item) => items.push(item),
            ItemRead::Unreadable => {}
            ItemRead::Invalid => {
                let _ = if kind.is_dir() { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
            }
        }
    }
    // A share of several files stages each one in a temp folder of its own
    // and renames them together at the end, so while any temp folder is
    // fresh a share is still copying and every finished one belongs to it.
    // Only when all of them are stale were they abandoned.
    if temps.iter().all(|p| is_stale(p)) {
        for path in temps {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
    items.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
    items
}

/// A temp folder is abandoned when neither it nor any entry directly inside
/// it changed for `STALE_TMP`. The Android copier streams the payload into
/// the folder without touching the folder itself, so the folder's own time
/// alone would delete a slow copy under it. An entry whose time cannot be
/// read counts as fresh.
fn is_stale(path: &Path) -> bool {
    let old = |p: &Path| {
        std::fs::symlink_metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .is_some_and(|age| age > STALE_TMP)
    };
    if !old(path) {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(path) else { return false };
    entries.flatten().all(|e| old(&e.path()))
}

pub fn read_in(inbox: &Path, id: &str) -> Result<Vec<u8>, String> {
    if !is_uuid(id) {
        return Err("bad_id".into());
    }
    let dir = inbox.join(id);
    if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
        return Err("missing".into());
    }
    match read_capped(&dir.join(PAYLOAD_FILE), MAX_PAYLOAD_BYTES) {
        Capped::Bytes(bytes) => Ok(bytes),
        Capped::Invalid => Err("bad_payload".into()),
        Capped::Unreadable => Err("unreadable".into()),
    }
}

pub fn remove_in(inbox: &Path, id: &str) -> Result<(), String> {
    if !is_uuid(id) {
        return Err("bad_id".into());
    }
    match std::fs::remove_dir_all(inbox.join(id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("not_removed".into()),
    }
}

#[cfg(target_os = "ios")]
fn group_dir() -> Option<PathBuf> {
    use objc2_foundation::{NSFileManager, NSString};
    let url = NSFileManager::defaultManager()
        .containerURLForSecurityApplicationGroupIdentifier(&NSString::from_str(APP_GROUP))?;
    Some(PathBuf::from(url.path()?.to_string()))
}

/// The inbox folder on this platform, or `None` where nothing writes one.
#[cfg(target_os = "ios")]
fn inbox_dir(_app: &tauri::AppHandle) -> Option<PathBuf> {
    Some(group_dir()?.join("ShareInbox"))
}

/// The activity's data folder, which is where MainActivity.kt writes.
#[cfg(target_os = "android")]
fn inbox_dir(app: &tauri::AppHandle) -> Option<PathBuf> {
    use tauri::Manager;
    Some(app.path().app_data_dir().ok()?.join("ShareInbox"))
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn inbox_dir(_app: &tauri::AppHandle) -> Option<PathBuf> {
    None
}

#[tauri::command]
pub fn share_inbox_list(app: tauri::AppHandle) -> Vec<SharedItem> {
    inbox_dir(&app).map(|d| list_in(&d)).unwrap_or_default()
}

#[tauri::command]
pub fn share_inbox_read(app: tauri::AppHandle, id: String) -> Result<tauri::ipc::Response, String> {
    let dir = inbox_dir(&app).ok_or("no_inbox")?;
    read_in(&dir, &id).map(tauri::ipc::Response::new)
}

/// The signed-in account's per-file limit, written where the iOS share
/// extension reads it, so a file the app would refuse is refused in the share
/// sheet with the reason instead of after a "Saved". A number, never content:
/// it tells the extension nothing about the notes. Clamped to the largest
/// limit the app grants. Android needs none: its share opens the app, whose
/// upload window names the limit at once.
fn limit_text(bytes: u64) -> String {
    bytes.clamp(1, MAX_PAYLOAD_BYTES).to_string()
}

#[tauri::command]
pub fn share_limit_set(bytes: u64) -> Result<(), String> {
    #[cfg(target_os = "ios")]
    {
        let dir = group_dir().ok_or("no_group")?;
        let tmp = dir.join(".share-limit.tmp");
        std::fs::write(&tmp, limit_text(bytes)).map_err(|_| "not_written".to_string())?;
        std::fs::rename(&tmp, dir.join(LIMIT_FILE)).map_err(|_| "not_written".to_string())?;
    }
    #[cfg(not(target_os = "ios"))]
    let _ = bytes;
    Ok(())
}

#[tauri::command]
pub fn share_inbox_remove(app: tauri::AppHandle, id: String) -> Result<(), String> {
    remove_in(&inbox_dir(&app).ok_or("no_inbox")?, &id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0A1B2C3D-0000-4000-8000-000000000001";
    const B: &str = "0a1b2c3d-0000-4000-8000-000000000002";

    /// One folder per test: the tests run in parallel.
    fn inbox() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("pn-share-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn put(inbox: &Path, id: &str, json: &str, payload: Option<&[u8]>) {
        let d = inbox.join(id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(ITEM_FILE), json).unwrap();
        if let Some(p) = payload {
            std::fs::write(d.join(PAYLOAD_FILE), p).unwrap();
        }
    }

    #[test]
    fn reads_each_kind_oldest_first() {
        let dir = inbox();
        put(&dir, A, r#"{"v":1,"kind":"url","created":2,"url":"https://example.com/a","title":" A page "}"#, None);
        put(&dir, B, r#"{"v":1,"kind":"file","created":1,"name":"../../x/photo.jpg","mime":"image/jpeg"}"#, Some(b"jpg"));
        let items = list_in(&dir);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind, "file");
        assert_eq!(items[0].name.as_deref(), Some("photo.jpg"));
        assert_eq!(items[0].size, Some(3));
        assert_eq!(items[1].url.as_deref(), Some("https://example.com/a"));
        assert_eq!(items[1].title.as_deref(), Some("A page"));
        assert_eq!(read_in(&dir, B).unwrap(), b"jpg");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn deletes_what_it_cannot_use() {
        let dir = inbox();
        put(&dir, A, r#"{"v":1,"kind":"url","url":"javascript:alert(1)"}"#, None);
        put(&dir, B, r#"{"v":1,"kind":"file","name":"empty.bin"}"#, None);
        let c = "0a1b2c3d-0000-4000-8000-000000000003";
        put(&dir, c, r#"{"v":2,"kind":"text","text":"from the future"}"#, None);
        assert!(list_in(&dir).is_empty());
        assert!(!dir.join(A).exists() && !dir.join(B).exists() && !dir.join(c).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn leaves_an_item_still_being_written() {
        let dir = inbox();
        let tmp = format!(".tmp-{A}");
        put(&dir, &tmp, r#"{"v":1,"kind":"text","text":"half"}"#, None);
        assert!(list_in(&dir).is_empty());
        assert!(dir.join(&tmp).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_id_is_never_a_path() {
        let dir = inbox();
        assert_eq!(read_in(&dir, "../item.json"), Err("bad_id".into()));
        assert!(!is_uuid("0A1B2C3D-0000-4000-8000-00000000000/"));
        std::fs::create_dir_all(dir.join("keep")).unwrap();
        assert_eq!(remove_in(&dir, "keep"), Err("bad_id".into()));
        assert!(dir.join("keep").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn never_reads_through_a_link() {
        let dir = inbox();
        let outside = dir.join("outside.json");
        std::fs::write(&outside, r#"{"v":1,"kind":"text","text":"secret"}"#).unwrap();
        std::fs::create_dir_all(dir.join(A)).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join(A).join(ITEM_FILE)).unwrap();
        assert!(list_in(&dir).is_empty());
        assert!(!dir.join(A).exists());
        std::fs::create_dir_all(dir.join(B)).unwrap();
        std::fs::write(dir.join(B).join(ITEM_FILE), r#"{"v":1,"kind":"file"}"#).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join(B).join(PAYLOAD_FILE)).unwrap();
        assert_eq!(read_in(&dir, B), Err("bad_payload".into()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keeps_a_fresh_temp_folder_and_drops_an_old_one() {
        let dir = inbox();
        let fresh = dir.join(format!(".tmp-{A}"));
        std::fs::create_dir_all(&fresh).unwrap();
        list_in(&dir);
        assert!(fresh.exists());
        std::fs::remove_dir_all(&fresh).unwrap();
        let old = dir.join(format!(".tmp-{B}"));
        std::fs::create_dir_all(&old).unwrap();
        let past = SystemTime::now() - STALE_TMP - Duration::from_secs(60);
        std::fs::File::open(&old).unwrap().set_modified(past).unwrap();
        list_in(&dir);
        assert!(!old.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keeps_an_old_temp_folder_whose_payload_is_still_being_written() {
        // The Android copier streams the payload into the folder and never
        // touches the folder itself, so a copy that runs past the limit has an
        // old folder and a fresh file.
        let dir = inbox();
        let slow = dir.join(format!(".tmp-{A}"));
        std::fs::create_dir_all(&slow).unwrap();
        std::fs::write(slow.join(PAYLOAD_FILE), b"partial").unwrap();
        let past = SystemTime::now() - STALE_TMP - Duration::from_secs(60);
        std::fs::File::open(&slow).unwrap().set_modified(past).unwrap();
        list_in(&dir);
        assert!(slow.join(PAYLOAD_FILE).exists());
        std::fs::File::open(slow.join(PAYLOAD_FILE)).unwrap().set_modified(past).unwrap();
        std::fs::File::open(&slow).unwrap().set_modified(past).unwrap();
        list_in(&dir);
        assert!(!slow.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keeps_the_finished_folders_of_a_share_that_is_still_copying() {
        // A share of several files stages each file in its own temp folder
        // and renames them all at the end, so a finished folder waits while a
        // later file copies, however long that takes.
        let dir = inbox();
        let past = SystemTime::now() - STALE_TMP - Duration::from_secs(60);
        let done = dir.join(format!(".tmp-{A}"));
        std::fs::create_dir_all(&done).unwrap();
        std::fs::write(done.join(PAYLOAD_FILE), b"first").unwrap();
        std::fs::File::open(done.join(PAYLOAD_FILE)).unwrap().set_modified(past).unwrap();
        std::fs::File::open(&done).unwrap().set_modified(past).unwrap();
        let copying = dir.join(format!(".tmp-{B}"));
        std::fs::create_dir_all(&copying).unwrap();
        std::fs::write(copying.join(PAYLOAD_FILE), b"second").unwrap();
        list_in(&dir);
        assert!(done.join(PAYLOAD_FILE).exists());
        std::fs::File::open(copying.join(PAYLOAD_FILE)).unwrap().set_modified(past).unwrap();
        std::fs::File::open(&copying).unwrap().set_modified(past).unwrap();
        list_in(&dir);
        assert!(!done.exists() && !copying.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_limit_is_a_plain_number_within_the_largest_grant() {
        assert_eq!(limit_text(5_000_000), "5000000");
        assert_eq!(limit_text(0), "1");
        assert_eq!(limit_text(u64::MAX), MAX_PAYLOAD_BYTES.to_string());
    }

    #[test]
    fn blank_text_is_not_an_item() {
        let dir = inbox();
        put(&dir, A, r#"{"v":1,"kind":"text","text":"   "}"#, None);
        assert!(list_in(&dir).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
