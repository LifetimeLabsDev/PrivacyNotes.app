//! Which app the OS opens Markdown files with, and - where the OS allows it -
//! pointing that at us.
//!
//! The bundle already REGISTERS the association (`bundle.fileAssociations` in
//! tauri.conf.json), which is what makes a double-click reach `lib.rs` at all.
//! This module is the separate question of who the OS considers the DEFAULT
//! handler, and it exists because the answer differs so much per platform that
//! one toggle cannot express it:
//!
//!   - **macOS** sets it in one synchronous call, no prompt.
//!   - **Linux** sets it through `xdg-mime`, which needs a `.desktop` file to
//!     point at (see `claim` for the two install shapes).
//!   - **Windows** cannot set it AT ALL. Microsoft blocked programmatic default
//!     association changes in Windows 8, and since Windows 10 `SHOpenWithDialog`
//!     ignores its own registration flags. The only sanctioned move is to open
//!     Settings on our page and let the user choose, so Windows reports
//!     `settable: false` and gets a different control rather than a broken one.
//!
//! Every path here is READ-ONLY until the user clicks. Nothing claims the
//! default at install time or at launch, unlike the `privacynotes://` scheme
//! registration in lib.rs: a scheme nobody else wants is not a hijack, and a
//! Markdown association taken from Obsidian or VS Code very much is.
//! Spec: ops/docs/plans/markdown-folder.md (section 11)

/// What the frontend needs to render the control. Four fields rather than a
/// boolean because "we are not the default" splits into cases that want
/// different words: another app owns it (name it), nothing owns it, or the OS
/// will not say.
#[derive(serde::Serialize)]
pub struct AssocStatus {
    /// `"macos"` / `"windows"` / `"linux"`. Reported from `cfg!` rather than
    /// sniffed from the user agent in the webview, so the frontend can pick
    /// "Finder" vs "File Explorer" vs "your file manager" from a fact that
    /// cannot be wrong, and the Markdown pillar needs no new import to do it.
    pub platform: &'static str,
    /// Whether `claim` can do anything. False on Windows, always.
    pub settable: bool,
    /// `"ours"` / `"other"` / `"none"` / `"unknown"`.
    pub owner: &'static str,
    /// Display name of the app that currently owns Markdown, when the OS will
    /// tell us. Cosmetic: `None` just means the UI says "another app".
    pub other_name: Option<String>,
}

impl AssocStatus {
    fn new(owner: &'static str, other_name: Option<String>) -> Self {
        Self {
            platform: PLATFORM,
            settable: SETTABLE,
            owner,
            other_name,
        }
    }

    /// The OS refused to answer. Distinct from `"none"`: nothing is claimed
    /// about who owns the type, so the UI offers the action without asserting
    /// what it will replace.
    ///
    /// Linux only, which is the one platform that can fail to answer at all -
    /// `xdg-mime` is a shell-out and a minimal system may not have it. macOS
    /// reads LaunchServices in-process, and a failed `AssocQueryStringW` on
    /// Windows cannot be told apart from "no handler registered", so both report
    /// what they know instead.
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn unknown() -> Self {
        Self::new("unknown", None)
    }
}

#[cfg(target_os = "macos")]
const PLATFORM: &str = "macos";
#[cfg(target_os = "windows")]
const PLATFORM: &str = "windows";
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const PLATFORM: &str = "linux";

/// Windows is the one platform where the user, and only the user, may change
/// this. See the module header.
const SETTABLE: bool = !cfg!(target_os = "windows");

/// Who opens Markdown files right now.
pub fn status(app: &tauri::AppHandle) -> AssocStatus {
    #[cfg(target_os = "macos")]
    return apple::status(app);
    #[cfg(target_os = "windows")]
    return windows_assoc::status();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    return linux::status(app);
}

/// Make us the default. macOS and Linux only - the command layer never calls
/// this on Windows, and the `unreachable` arm below is the compile-time proof
/// that no fourth platform quietly falls through to a no-op that reports
/// success.
pub fn claim(app: &tauri::AppHandle) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    return apple::claim(app);
    #[cfg(target_os = "windows")]
    {
        let _ = app;
        Err("Windows does not allow an app to set its own file associations.".to_owned())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    return linux::claim(app);
}

/// Open the OS screen where the user can set this themselves. Windows only:
/// it is the only platform that needs it, because it is the only one where we
/// cannot do the job.
pub fn open_os_settings() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    return windows_assoc::open_default_apps_settings();
    #[cfg(not(target_os = "windows"))]
    Err("Only Windows needs the system settings detour.".to_owned())
}

/// macOS: LaunchServices, bound with raw `extern "C"` and `msg_send!` rather
/// than the `objc2-app-kit` / `objc2-uniform-type-identifiers` bindings so that
/// no new package enters Cargo.lock - the same trade `biometric.rs` makes for
/// LAContext, and for the same reason.
#[cfg(target_os = "macos")]
mod apple {
    use objc2::msg_send;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject};
    use objc2_foundation::NSString;

    use super::AssocStatus;

    /// `kLSRolesEditor` from LSConstants.h (0x4, NOT 0x2 - Viewer is 0x2 and
    /// None is 0x1). Editor rather than `kLSRolesAll` because that is the role
    /// `CFBundleDocumentTypes` claims for Markdown, and LaunchServices matches
    /// the role asked about against the role the bundle declares.
    const LS_ROLES_EDITOR: u32 = 0x0000_0004;

    /// The established UTI for Markdown, declared by every Markdown editor on
    /// the platform and known to the system since macOS 13 as `UTType.markdown`.
    ///
    /// Deliberately NOT a type of our own: Markdown is not our format, and an
    /// app-specific UTI would set the default for a type nothing else uses.
    /// Tauri's own `extension_to_uti` has no `md` mapping at all, which is why
    /// `contentTypes` is spelled out in tauri.conf.json - without it the bundle
    /// claims only `public.plain-text` and LaunchServices refuses to make us the
    /// handler for a type we never declared.
    ///
    /// Covers `.md` and `.markdown`. `.mdown` and `.mkd` resolve to dynamic
    /// UTIs on most systems, so they stay openable through
    /// `CFBundleTypeExtensions` but cannot have a default set - which is why the
    /// UI says "Markdown files" and never enumerates four extensions.
    // Spec: ops/docs/plans/markdown-folder.md (section 11)
    const MARKDOWN_UTI: &str = "net.daringfireball.markdown";

    // CoreServices.framework is linked in build.rs. Both functions are
    // API_DEPRECATED in the SDK with no removal version (API_TO_BE_DEPRECATED)
    // and are present and working in the current one; the replacements live on
    // NSWorkspace and take a `UTType`, which would mean a new crate for one
    // string constant.
    //
    // Declared taking `*const NSString` rather than a CFStringRef binding
    // because NSString and CFString are the same object under toll-free
    // bridging. That keeps objc2-core-foundation out of the direct dependency
    // list and lets `NSString::from_str` build the arguments.
    #[link(name = "CoreServices", kind = "framework")]
    extern "C" {
        /// Returns the bundle id of the default handler, +1 retained (it is a
        /// `Copy` function), or null when nothing is registered.
        fn LSCopyDefaultRoleHandlerForContentType(
            content_type: *const NSString,
            role: u32,
        ) -> *mut NSString;
        /// `noErr` (0) on success.
        fn LSSetDefaultRoleHandlerForContentType(
            content_type: *const NSString,
            role: u32,
            handler_bundle_id: *const NSString,
        ) -> i32;
    }

    /// Current default handler's bundle id, or None when the type has none.
    fn current_handler() -> Option<Retained<NSString>> {
        let uti = NSString::from_str(MARKDOWN_UTI);
        // SAFETY: `uti` outlives the call, and the result is a +1 reference that
        // `Retained::from_raw` takes ownership of - matching the Core Foundation
        // Copy rule, so this neither leaks nor over-releases.
        unsafe {
            let raw = LSCopyDefaultRoleHandlerForContentType(&*uti, LS_ROLES_EDITOR);
            Retained::from_raw(raw)
        }
    }

    /// Best-effort human name for a bundle id ("md.obsidian" -> "Obsidian").
    ///
    /// Off the main thread on purpose: `NSWorkspace` documents its shared
    /// instance as thread-safe and this is a lookup rather than UI, so a
    /// main-thread hop on every window focus would buy nothing. It is also the
    /// only cosmetic call in this module - every failure path returns None and
    /// the UI falls back to "another app", so being wrong here costs a word.
    fn display_name(bundle_id: &NSString) -> Option<String> {
        let class = AnyClass::get(c"NSWorkspace")?;
        let workspace: Retained<AnyObject> = unsafe { msg_send![class, sharedWorkspace] };
        let url: Option<Retained<AnyObject>> =
            unsafe { msg_send![&*workspace, URLForApplicationWithBundleIdentifier: bundle_id] };
        // Both returns are typed Option because both are declared nullable in the
        // SDK - `lastPathComponent` included, which is easy to miss because it
        // never IS null for a file URL LaunchServices just handed us. Typing a
        // nullable return as a bare `Retained` is how a cosmetic lookup turns into
        // a crash on the one machine where the assumption does not hold.
        let last: Option<Retained<NSString>> = unsafe { msg_send![&*url?, lastPathComponent] };
        let name = last?.to_string();
        Some(name.strip_suffix(".app").unwrap_or(&name).to_owned())
    }

    pub fn status(app: &tauri::AppHandle) -> AssocStatus {
        let Some(handler) = current_handler() else {
            return AssocStatus::new("none", None);
        };
        // Bundle ids are case-insensitive to LaunchServices, so the comparison
        // has to be too - otherwise a differently-cased registration reads as
        // "some other app" and the UI offers to fix what is already right.
        if handler.to_string().eq_ignore_ascii_case(&app.config().identifier) {
            return AssocStatus::new("ours", None);
        }
        AssocStatus::new("other", display_name(&handler))
    }

    pub fn claim(app: &tauri::AppHandle) -> Result<(), String> {
        let uti = NSString::from_str(MARKDOWN_UTI);
        let bundle_id = NSString::from_str(&app.config().identifier);
        // SAFETY: both strings outlive the call and the function copies what it
        // needs. It returns an OSStatus rather than writing through a pointer.
        let os_status =
            unsafe { LSSetDefaultRoleHandlerForContentType(&*uti, LS_ROLES_EDITOR, &*bundle_id) };
        if os_status == 0 {
            return Ok(());
        }
        // The overwhelmingly likely cause is an unbundled binary: `tauri dev`
        // runs the bare executable with no Info.plist, so LaunchServices has
        // never seen an app with this bundle id claiming Markdown. Say that,
        // because the alternative is a user staring at a bare error code for a
        // build that was never going to work.
        Err(format!(
            "macOS refused to change the default app (OSStatus {os_status}). \
             This needs a bundled, launched copy of the app."
        ))
    }
}

/// Linux: `xdg-mime`, the same tool the deep-link plugin uses to register the
/// `privacynotes://` scheme. Both subprocesses are absent on a minimal system,
/// which is a plain error rather than a panic.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod linux {
    use std::path::PathBuf;
    use std::process::Command;

    use super::AssocStatus;

    /// The two MIME types a Markdown file can arrive as. `text/markdown` is the
    /// registered one (RFC 7763) and what shared-mime-info globs `*.md`,
    /// `*.mkd` and `*.markdown` to; `text/x-markdown` is the legacy spelling
    /// still emitted by older desktops. Both are claimed, and `text/plain` very
    /// deliberately is NOT - taking the default for all plain text would make
    /// us the editor for every README, log and config file on the machine.
    // Spec: ops/docs/plans/markdown-folder.md (section 11)
    const MARKDOWN_MIMES: [&str; 2] = ["text/markdown", "text/x-markdown"];

    /// `~/.local/share/applications`, where a per-user handler belongs.
    fn user_applications_dir(app: &tauri::AppHandle) -> Option<PathBuf> {
        use tauri::Manager;
        Some(app.path().data_dir().ok()?.join("applications"))
    }

    /// The desktop file id `xdg-mime` should point at, and whether we have to
    /// write it ourselves first.
    ///
    /// Two install shapes, and they differ in whether the system already has a
    /// desktop entry for us:
    ///   - **deb / rpm** install `PrivacyNotes.desktop` (the name our own
    ///     metainfo declares as `launchable`). Target that, so the machine ends
    ///     up with one entry rather than a duplicate in the application menu.
    ///   - **AppImage or a loose binary** install nothing at all, because an
    ///     AppImage is a single file no desktop environment ever indexes. Those
    ///     need an entry of our own.
    fn desktop_target(app: &tauri::AppHandle) -> (String, bool) {
        let packaged = "PrivacyNotes.desktop";
        let system_paths = [
            PathBuf::from("/usr/share/applications").join(packaged),
            PathBuf::from("/usr/local/share/applications").join(packaged),
        ];
        let user_path = user_applications_dir(app).map(|d| d.join(packaged));
        let exists = system_paths.iter().any(|p| p.exists())
            || user_path.as_ref().is_some_and(|p| p.exists());
        if exists {
            return (packaged.to_owned(), false);
        }
        ("privacynotes-markdown.desktop".to_owned(), true)
    }

    /// Read `Name=` out of a desktop file, for "currently opens with X".
    ///
    /// A deliberately small parser: scan the `[Desktop Entry]` section for the
    /// unlocalised `Name=` and stop at the next section header. Pulling in an
    /// ini crate to read one key would be the larger change, and every failure
    /// path here just returns None.
    fn desktop_entry_name(app: &tauri::AppHandle, id: &str) -> Option<String> {
        let mut dirs: Vec<PathBuf> = Vec::new();
        if let Some(dir) = user_applications_dir(app) {
            dirs.push(dir);
        }
        dirs.push(PathBuf::from("/usr/local/share/applications"));
        dirs.push(PathBuf::from("/usr/share/applications"));
        for dir in dirs {
            let Ok(text) = std::fs::read_to_string(dir.join(id)) else {
                continue;
            };
            let mut in_entry = false;
            for line in text.lines() {
                let line = line.trim();
                if line.starts_with('[') {
                    in_entry = line == "[Desktop Entry]";
                    continue;
                }
                if in_entry {
                    if let Some(name) = line.strip_prefix("Name=") {
                        return Some(name.trim().to_owned());
                    }
                }
            }
        }
        None
    }

    pub fn status(app: &tauri::AppHandle) -> AssocStatus {
        let Ok(out) = Command::new("xdg-mime")
            .args(["query", "default", MARKDOWN_MIMES[0]])
            .output()
        else {
            // No xdg-mime on the system. We cannot read the association and we
            // cannot set it either, but `settable` stays true: the button is
            // still the right offer, and it will report its own failure.
            return AssocStatus::unknown();
        };
        // A non-zero exit is NOT the same as an empty answer, and the difference
        // matters: `output()` succeeds as long as the process ran at all, so
        // without this a failing xdg-mime that printed a diagnostic to stdout
        // would be read as the name of the app that owns Markdown.
        if !out.status.success() {
            return AssocStatus::unknown();
        }
        let current = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if current.is_empty() {
            return AssocStatus::new("none", None);
        }
        // Compare against BOTH ids we could ever have registered, not just the
        // one we would target now: a user who claimed the default from an
        // AppImage and later installed the deb must still read as "ours".
        if current == "PrivacyNotes.desktop" || current == "privacynotes-markdown.desktop" {
            return AssocStatus::new("ours", None);
        }
        let name = desktop_entry_name(app, &current);
        AssocStatus::new("other", name)
    }

    pub fn claim(app: &tauri::AppHandle) -> Result<(), String> {
        let (id, needs_writing) = desktop_target(app);
        if needs_writing {
            write_handler_desktop_file(app, &id)?;
        }
        let mut args = vec!["default", id.as_str()];
        args.extend(MARKDOWN_MIMES);
        let status = Command::new("xdg-mime")
            .args(&args)
            .status()
            .map_err(|e| format!("xdg-mime could not be run: {e}"))?;
        if !status.success() {
            return Err("xdg-mime refused to change the default app.".to_owned());
        }
        Ok(())
    }

    /// Write a desktop entry for install shapes that have none.
    ///
    /// `%F` is the load-bearing character: a desktop entry whose `Exec` carries
    /// no field code is launched with NO arguments, so the file the user
    /// double-clicked never reaches argv and the app opens empty. That is
    /// exactly the bug the bundled entry had until `linux/privacynotes.desktop`
    /// overrode Tauri's own template, which still ships without one.
    ///
    /// `NoDisplay` is deliberately absent, unlike the deep-link plugin's
    /// scheme-handler file: this entry is a real Markdown editor the user chose,
    /// and it has to appear in a file manager's "Open with" list.
    // Spec: ops/docs/plans/markdown-folder.md (section 11)
    /// Escape one executable path for a double-quoted `Exec=` argument.
    ///
    /// The Desktop Entry spec asks for two separate things, and skipping either
    /// produces an entry the launcher silently rejects while `xdg-mime` still
    /// reports success - so `claim()` would return Ok and the UI would flip to the
    /// permanent "Markdown files open with PrivacyNotes" statement over a handler
    /// that opens nothing.
    ///
    /// 1. A literal `%` must be doubled, because `%` introduces a field code.
    ///    `~/Downloads/PrivacyNotes%20arm64.AppImage` is the case that matters:
    ///    browsers hand out percent-encoded filenames routinely, and `%20` reads
    ///    as the unknown field code `%2` followed by `0`, which invalidates the
    ///    whole `Exec` line.
    /// 2. Inside a quoted argument, `"`, backtick, `$` and backslash must each be
    ///    preceded by a backslash.
    ///
    /// Order matters: the backslash rule has to run before the `%` rule, or the
    /// backslashes it inserts get counted by the `%` pass.
    fn escape_exec_arg(path: &str) -> String {
        let mut out = String::with_capacity(path.len() + 8);
        for ch in path.chars() {
            match ch {
                '"' | '`' | '$' | '\\' => {
                    out.push('\\');
                    out.push(ch);
                }
                '%' => out.push_str("%%"),
                _ => out.push(ch),
            }
        }
        out
    }

    fn write_handler_desktop_file(app: &tauri::AppHandle, id: &str) -> Result<(), String> {
        use tauri::Manager;
        let dir = user_applications_dir(app)
            .ok_or_else(|| "No user data directory to write a desktop entry into.".to_owned())?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        // An AppImage's own path, not the extracted binary inside it: the
        // extracted path lives in a temporary mount that is gone by the time
        // anyone double-clicks a file.
        let exec = match app.env().appimage {
            Some(path) => PathBuf::from(path),
            None => std::env::current_exe().map_err(|e| e.to_string())?,
        };
        let body = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=PrivacyNotes\n\
             Exec=\"{}\" %F\n\
             Icon=privacynotes\n\
             Terminal=false\n\
             Categories=Office;TextEditor;\n\
             MimeType={};\n",
            escape_exec_arg(&exec.to_string_lossy()),
            MARKDOWN_MIMES.join(";"),
        );
        std::fs::write(dir.join(id), body).map_err(|e| e.to_string())?;
        // Without this the entry exists and no file manager knows it does.
        // A missing tool is not fatal: xdg-mime below still writes mimeapps.list.
        let _ = Command::new("update-desktop-database").arg(&dir).status();
        Ok(())
    }
}

/// Windows: read-only. `AssocQueryStringW` reports who owns `.md`;
/// nothing here can change it, by Microsoft's design.
#[cfg(target_os = "windows")]
mod windows_assoc {
    use windows::core::{w, PCWSTR, PWSTR};
    use windows::Win32::UI::Shell::{
        AssocQueryStringW, ShellExecuteW, ASSOCF_INIT_IGNOREUNKNOWN, ASSOCSTR,
        ASSOCSTR_EXECUTABLE, ASSOCSTR_FRIENDLYAPPNAME,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    use super::AssocStatus;

    /// The extension we ask about. One rather than all four: Windows resolves
    /// defaults per extension, and `.md` is the one every Markdown file on a
    /// real machine actually uses.
    const EXT: PCWSTR = w!(".md");
    const VERB: PCWSTR = w!("open");

    /// Deep link straight to our own page in Settings, rather than the generic
    /// Default apps list. Only resolves because the NSIS hook writes
    /// `HKCU\Software\RegisteredApplications` - Tauri's installer does not, and
    /// without that key Windows silently falls back to the top of the list.
    /// `registeredAppUser` and not `registeredAppMachine` because the installer
    /// runs in `currentUser` mode.
    // Spec: ops/docs/windows-release.md (default Markdown app)
    const DEFAULT_APPS_URI: PCWSTR = w!("ms-settings:defaultapps?registeredAppUser=PrivacyNotes");

    /// One `AssocQueryStringW` call. Called twice: once for the executable path
    /// (to decide whether the owner is us) and once for the friendly name (to
    /// say who it is otherwise).
    ///
    /// `ASSOCF_INIT_IGNOREUNKNOWN` is load-bearing, and `ASSOCF_NONE` here was a
    /// bug. Without the flag the shell resolves an UNCLAIMED extension through the
    /// `Unknown` ProgID rather than failing, and `HKCR\Unknown\shell\open\command`
    /// is `OpenWith.exe` - so a machine where nothing owns `.md` answers with a
    /// real path to Windows' own "Open with" picker. `status()` would then read
    /// that as "another app owns Markdown" and the UI would say "Markdown files
    /// currently open with Pick an app", making the `none` state unreachable on
    /// Windows. That is not an edge case: it is the state `windows/hooks.nsi`
    /// deliberately creates by undoing Tauri's default claim, so it is the normal
    /// first run for anyone without another Markdown editor installed. The flag
    /// says "ignore the Unknown ProgID, fail instead", which is what the empty
    /// length check below is written to expect.
    fn assoc_string(kind: ASSOCSTR) -> Option<String> {
        let mut len: u32 = 0;
        // First call sizes the buffer: with a null `pszOut` the function writes the
        // required character count (including the terminator) into `pcchOut` and
        // returns a non-success HRESULT to say so. The return value is therefore
        // deliberately ignored and only the length is trusted.
        unsafe {
            let _ = AssocQueryStringW(ASSOCF_INIT_IGNOREUNKNOWN, kind, EXT, VERB, None, &mut len);
        }
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u16; len as usize];
        // `is_err()` rather than `.ok()?`: this returns a bare HRESULT, not a
        // windows_core::Result, so `?` here would be trying to lift a Result into
        // this function's Option.
        let hr = unsafe {
            AssocQueryStringW(
                ASSOCF_INIT_IGNOREUNKNOWN,
                kind,
                EXT,
                VERB,
                Some(PWSTR(buf.as_mut_ptr())),
                &mut len,
            )
        };
        if hr.is_err() {
            return None;
        }
        // `len` comes back including the terminating NUL; trim at the first one
        // rather than trusting the count, which differs between Windows builds.
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let s = String::from_utf16_lossy(&buf[..end]);
        (!s.is_empty()).then_some(s)
    }

    pub fn status() -> AssocStatus {
        let Some(exe) = assoc_string(ASSOCSTR_EXECUTABLE) else {
            // No handler at all. Windows shows "How do you want to open this
            // file?" in this state, which is the "none" case exactly.
            return AssocStatus::new("none", None);
        };
        // Windows hands back an unpredictable mix of short and long paths and
        // arbitrary casing, so compare case-insensitively and accept a
        // filename match: a full-path comparison against `current_exe` fails
        // for a per-user install reached through a different path spelling.
        let ours = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_lowercase()));
        let owner_file = std::path::Path::new(&exe)
            .file_name()
            .map(|f| f.to_string_lossy().to_lowercase());
        if let (Some(a), Some(b)) = (&ours, &owner_file) {
            if a == b {
                return AssocStatus::new("ours", None);
            }
        }
        AssocStatus::new("other", assoc_string(ASSOCSTR_FRIENDLYAPPNAME))
    }

    /// Open Settings on our Default apps page. The user makes the change; we
    /// only get them to the right screen.
    pub fn open_default_apps_settings() -> Result<(), String> {
        // SAFETY: a null hwnd is documented and correct for a shell verb with no
        // parent window. The return is a pseudo-HINSTANCE where any value <= 32
        // is a failure code, which is the whole of its error protocol.
        let result = unsafe {
            ShellExecuteW(
                None,
                w!("open"),
                DEFAULT_APPS_URI,
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        if result.0 as usize <= 32 {
            return Err("Windows could not open the Default apps settings page.".to_owned());
        }
        Ok(())
    }
}
