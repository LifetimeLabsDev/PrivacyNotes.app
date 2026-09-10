/// Native biometric gate: Touch ID / Face ID on macOS + iOS, Windows Hello on
/// Windows, BiometricPrompt on Android. `native_biometric` is set by build.rs
/// for exactly those targets; Linux falls through to the WebAuthn path.
/// Spec: ops/docs/biometric-unlock.md, backlog #101 (LAContext must run on the main thread; Windows Hello must not)
#[cfg(native_biometric)]
mod biometric;

/// Who the OS opens Markdown files with, and pointing it at us on the two
/// platforms that permit it. Desktop only: neither mobile OS has user-settable
/// file associations. Spec: ops/docs/plans/markdown-folder.md (section 11)
#[cfg(desktop)]
mod file_assoc;

/// Native print for the two platforms whose webview refuses to print itself:
/// macOS and iOS both render in WKWebView, which never implements JavaScript's
/// `window.print()`. Windows (WebView2) and Linux (WebKitGTK) do implement it
/// and keep using the frontend's own print path.
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod print;

/// Files the OS asked us to open before the webview was ready to hear about it.
///
/// A cold start from a double-click delivers the path within milliseconds, long
/// before the frontend has booted, let alone cleared the auth gate and the app
/// lock. Emitting straight away would drop it on the floor and the user would
/// be left staring at a login screen wondering why their file did not open, so
/// the path waits here until the frontend says it is listening.
/// Spec: ops/docs/plans/markdown-folder.md (section 11)
#[cfg(desktop)]
static PENDING_OPEN: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Extensions the bundle registers. Kept in step with `fileAssociations` in
/// tauri.conf.json, and checked here because argv carries anything the shell
/// felt like passing - flags, a deep link, a file we never claimed.
#[cfg(desktop)]
const OPENABLE_EXT: [&str; 5] = ["md", "markdown", "mdown", "mkd", "txt"];

/// The URL scheme the bundle registers, kept in step with `plugins.deep-link`
/// in tauri.conf.json and asserted against it by
/// `tests/desktopCapabilities.test.ts`.
#[cfg(desktop)]
const APP_SCHEME: &str = "privacynotes:";

/// True when the argument is one of our own deep links.
///
/// Case-insensitively, because a scheme is case-insensitive and the shell
/// hands over whatever the sender typed.
#[cfg(desktop)]
fn announces_app_scheme(arg: &str) -> bool {
    arg.len() >= APP_SCHEME.len()
        && arg[..APP_SCHEME.len()].eq_ignore_ascii_case(APP_SCHEME)
}

#[cfg(desktop)]
fn is_openable(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| OPENABLE_EXT.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// True when the argument announces a URL scheme, `file:` included.
///
/// Shape, not a parser, and deliberately. A bare Windows path such as
/// `C:\notes\a.md` parses as a URL with scheme "c", so asking a parser what
/// the scheme is would mangle every Windows double-click; a drive letter is
/// one character and a scheme is at least two. And the colon has to come
/// before any separator, because `/tmp/my:file.md` is a legal name on Unix.
///
/// The `://` form is not enough on its own: a scheme can carry an opaque
/// value after a single colon, which is how `privacynotes:x|...` slipped
/// past an earlier version of this test.
#[cfg(desktop)]
fn has_url_scheme(arg: &str) -> bool {
    let Some(colon) = arg.find(':') else { return false };
    let scheme = &arg[..colon];
    if scheme.len() < 2 || scheme.contains('/') || scheme.contains('\\') {
        return false;
    }
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Turn one argv entry into a filesystem path we claimed, or None.
///
/// The extension check is the obvious job. Two others are not.
///
/// A URL is not a file, whatever its last segment looks like: the app's own
/// scheme arrives on this same argv, and `privacynotes://x/y.md` ends in a
/// registered extension. The deep-link plugin owns those, and handing one to
/// the filesystem is how a link somebody else wrote became a path the app
/// opened.
///
/// The one exception is `file://`, which a Linux file manager launching a
/// `%F` desktop entry may hand over instead of a bare path, and which needs a
/// parser rather than a `strip_prefix` because `file:///home/a/my%20note.md`
/// has to come back with a real space. It is scoped away from Windows, which
/// never sends one: there the single-instance forwarder joins argv with a
/// pipe and splits the payload on the same character, so one crafted deep
/// link arrives as several arguments and the second of them was unwrapped
/// into a path - a local file, or a UNC name pointing at a host of the
/// sender's choosing.
///
/// Spec: ops/docs/audit-adversarial-2026-09-bfg.md (SEC-20)
#[cfg(desktop)]
fn openable_path(arg: &str) -> Option<String> {
    #[cfg(not(target_os = "windows"))]
    if arg.starts_with("file://") {
        let path = tauri::Url::parse(arg)
            .ok()?
            .to_file_path()
            .ok()?
            .to_string_lossy()
            .into_owned();
        return is_openable(&path).then_some(path);
    }
    if has_url_scheme(arg) {
        return None;
    }
    is_openable(arg).then_some(arg.to_owned())
}

/// Queue every openable path in an argv-style list. Windows and Linux deliver
/// file opens this way, both on a cold start and through single-instance.
#[cfg(desktop)]
fn queue_from_args<I: IntoIterator<Item = String>>(args: I) {
    let args: Vec<String> = args.into_iter().collect();
    // A batch carrying one of our own deep links is a link delivery, not a
    // file open, and the two must never be mixed. On Windows the
    // single-instance forwarder joins argv with a pipe and the receiver
    // splits the payload on the same character, so ONE crafted link arrives
    // as several arguments and every argument after the first looks exactly
    // like a file the shell handed over - a local path, or a network name
    // whose owner learns who opened it.
    //
    // Nothing legitimate is lost, because the deep-link plugin refuses that
    // same batch: it takes the argument after the binary only when there is
    // no second one (tauri-plugin-deep-link-2.4.10/src/lib.rs:203-210), so a
    // split payload is already dead as a link before our callback runs. This
    // closes the delivery rather than the shape, which is why a double-click
    // on a note that lives on a file server is still an ordinary open.
    // Spec: ops/docs/audit-adversarial-2026-09-bfg.md (SEC-20)
    if args.iter().any(|a| announces_app_scheme(a)) {
        return;
    }
    let mut queue = PENDING_OPEN.lock().unwrap();
    for arg in args.into_iter().skip(1) {
        if let Some(path) = openable_path(&arg) {
            queue.push(path);
        }
    }
}

/// Drain the queue. Called by the frontend once it is ready to act on a path,
/// which is why this is a command rather than an event: the frontend asks when
/// it is ready, instead of us guessing when that is.
#[tauri::command]
#[cfg(desktop)]
fn take_pending_opens(app: tauri::AppHandle) -> Vec<String> {
    use tauri_plugin_fs::FsExt;

    let paths = std::mem::take(&mut *PENDING_OPEN.lock().unwrap());
    // Widen the fs scope to each path before the frontend ever sees it. The
    // static capability grants stop at `$HOME/**` and the only runtime widening
    // is the one `pickDirectory` gets for free from the dialog plugin - and a
    // double-click never goes through a picker. Without this, a file on an
    // external volume, in /tmp, or on a second Windows drive is ACL-denied the
    // instant the frontend tries to read it, with nothing but a rejected promise
    // in the webview console to say why.
    // Widening happens HERE rather than at queue time because this is the first
    // point that has an AppHandle: the two queue sites are a plugin callback and
    // `std::env::args()`.
    // Spec: ops/docs/plans/markdown-folder.md (section 11)
    if let Some(scope) = app.try_fs_scope() {
        // The last one only, which is the one the frontend opens: a
        // multi-select hands over several, and the widening this grants is
        // process-wide and permanent, so granting the rest keeps whatever
        // they name reachable for the life of the run and buys nothing.
        // A path that cannot be granted is still worth returning: the read
        // will fail with the frontend's own error state rather than being
        // silently dropped here, which is the more debuggable of the two.
        if let Some(path) = paths.last() {
            let _ = scope.allow_file(path);
        }
    }
    paths
}

/// Which app the OS currently opens Markdown files with. Read-only, and cheap
/// enough to re-ask on every window focus - the association can change while we
/// are running, because another installer can take it.
#[tauri::command(async)]
#[cfg(desktop)]
fn markdown_assoc_status(app: tauri::AppHandle) -> file_assoc::AssocStatus {
    file_assoc::status(&app)
}

/// Make us the default Markdown app. Only ever reached from an explicit click:
/// nothing claims the association at install time or at launch.
#[tauri::command(async)]
#[cfg(desktop)]
fn markdown_assoc_claim(app: tauri::AppHandle) -> Result<(), String> {
    file_assoc::claim(&app)
}

/// Open the OS screen where the user sets this themselves. Windows only, where
/// the OS reserves the choice for the user and answers `settable: false` above.
#[tauri::command(async)]
#[cfg(desktop)]
fn markdown_assoc_open_os_settings() -> Result<(), String> {
    file_assoc::open_os_settings()
}

/// Whether the process holding the single-instance rendezvous is this app.
///
/// The desktop app answers "am I already running?" by seeing whether anything
/// replies at a meeting point, and on macOS that meeting point is a Unix
/// socket at a fixed path under `/tmp`, a directory every account on the
/// machine can write to. The plugin's rule is that whatever replies there IS
/// the running app: it hands that listener this launch's arguments and its
/// working directory, then exits. So anything that gets there first stops the
/// app from ever starting and reads the path of the file somebody tried to
/// open with it.
///
/// Two questions, because one test cannot answer both. A socket owned by
/// another account is not ours and never can be, since nobody else can create
/// one owned by us. A socket owned by THIS user still proves nothing, because
/// a program running as the person owns whatever it creates, so the listener
/// is asked which executable it is and the answer has to be this one.
///
/// The order matters. Nothing there at all means the plugin creates the
/// socket and owns it. A socket nothing listens on is a leftover from a
/// crash, which the plugin removes before taking the rendezvous over. Past
/// that point something is listening, and anything short of proof is refused:
/// the plugin stays unregistered and the app starts. Losing second-launch
/// forwarding for one run is a far smaller cost than a run that never
/// happens, and `/tmp`'s sticky bit means removing a squatter's socket was
/// never an option anyway.
///
/// The connection this makes carries nothing. Arguments and the working
/// directory travel on the plugin's own connect, which happens after this has
/// decided, so a listener that fails the test learns only that somebody
/// looked.
/// Spec: ops/docs/security-backlog.md (SEC-28)
#[cfg(all(desktop, target_os = "macos"))]
fn rendezvous_is_ours(config: &tauri::Config) -> bool {
    let identifier = config.identifier.replace(['.', '-'], "_");
    rendezvous_holder_matches(
        &format!("/tmp/{identifier}_si.sock"),
        std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .ok(),
    )
}

/// The decision itself, with both of its inputs handed in so a test can put
/// a real socket at a real path and ask about a real process.
#[cfg(all(desktop, target_os = "macos"))]
fn rendezvous_holder_matches(path: &str, expected: Option<std::path::PathBuf>) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    match std::fs::symlink_metadata(path) {
        Err(_) => return true,
        Ok(meta) => {
            if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
                return false;
            }
        }
    }

    let Ok(stream) = UnixStream::connect(path) else {
        return true;
    };

    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let asked = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::addr_of_mut!(pid).cast(),
            &mut len,
        )
    };
    if asked != 0 || pid <= 0 {
        return false;
    }

    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let written =
        unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if written <= 0 {
        return false;
    }
    buf.truncate(written as usize);

    // Both sides are resolved before they are compared, so one of them
    // arriving through a symbolic link cannot read as a different program.
    let peer = String::from_utf8(buf)
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());
    peer.is_some() && peer == expected
}

/// The rendezvous decision, every branch of it, against real sockets in a
/// real directory and a real listening process.
///
/// The positive case is the one worth having: the listener is this test
/// binary, so the peer the kernel names IS the executable asked about, which
/// is the same proof the app makes of a running copy of itself.
/// Spec: ops/docs/security-backlog.md (SEC-28)
#[cfg(all(test, desktop, target_os = "macos"))]
mod rendezvous_tests {
    use super::rendezvous_holder_matches;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    fn me() -> Option<PathBuf> {
        std::env::current_exe().and_then(std::fs::canonicalize).ok()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("pn-rendezvous-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn nothing_there_is_ours_to_take() {
        let path = scratch("absent.sock");
        assert!(rendezvous_holder_matches(path.to_str().unwrap(), me()));
    }

    #[test]
    fn a_plain_file_is_not_a_rendezvous() {
        let path = scratch("plain");
        std::fs::write(&path, b"").unwrap();
        assert!(!rendezvous_holder_matches(path.to_str().unwrap(), me()));
    }

    #[test]
    fn a_symbolic_link_is_not_a_rendezvous() {
        let target = scratch("link-target.sock");
        let link = scratch("link");
        let _listener = UnixListener::bind(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // The link points at a socket this process is listening on, so only
        // reading the link itself rather than its target refuses it.
        assert!(!rendezvous_holder_matches(link.to_str().unwrap(), me()));
    }

    #[test]
    fn a_socket_nobody_listens_on_is_a_leftover() {
        let path = scratch("stale.sock");
        drop(UnixListener::bind(&path).unwrap());
        // The file outlives the listener, and the plugin removes it before it
        // takes the rendezvous over.
        assert!(rendezvous_holder_matches(path.to_str().unwrap(), me()));
    }

    #[test]
    fn a_listener_that_is_this_executable_is_ours() {
        let path = scratch("live.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        assert!(rendezvous_holder_matches(path.to_str().unwrap(), me()));
    }

    #[test]
    fn a_listener_that_is_another_executable_is_not() {
        let path = scratch("impostor.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        assert!(!rendezvous_holder_matches(
            path.to_str().unwrap(),
            Some(PathBuf::from("/bin/sh")),
        ));
    }

    #[test]
    fn an_unknowable_executable_is_not_ours() {
        let path = scratch("unknown.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        // Nothing to compare against is not the same as a match, and the
        // wrong answer here hands a stranger this launch's arguments.
        assert!(!rendezvous_holder_matches(path.to_str().unwrap(), None));
    }
}

/// Linux keeps the rendezvous on the session bus and Windows in a named
/// mutex, and neither is reachable from another account, so there is nothing
/// here to check.
#[cfg(all(desktop, not(target_os = "macos")))]
fn rendezvous_is_ours(_config: &tauri::Config) -> bool {
    true
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // WebKitGTK's DMA-BUF renderer paints nothing on some Linux GPUs (NVIDIA
    // proprietary drivers, certain Wayland compositors): the window opens but
    // stays blank. Force the stable render path. Must run before any GTK code,
    // and stays overridable so a user can re-enable the fast path for debugging.
    // Spec: ops/docs/gotchas.md (Linux blank window / WebKitGTK DMA-BUF)
    #[cfg(target_os = "linux")]
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }

    // Built here rather than at the end of the chain: the rendezvous check
    // below reads the identifier out of it.
    let context = tauri::generate_context!();

    let builder = tauri::Builder::default();

    // single-instance MUST be the first plugin registered. With the
    // deep-link feature it forwards a privacynotes:// callback caught by a
    // second on-disk copy of the app to the already-running instance,
    // instead of letting that copy launch fresh and swallow the OAuth
    // redirect. Desktop only. Spec: ops/docs/macos-ios-setup.md (native OAuth)
    #[cfg(desktop)]
    let builder = if !rendezvous_is_ours(context.config()) {
        builder
    } else {
        builder.plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
        use tauri::{Emitter, Manager};
        // A second launch carrying a file path is a double-click while we are
        // already running. The args were discarded here until file
        // associations existed; now they are the whole point of the callback.
        queue_from_args(args);
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.set_focus();
        }
            let _ = app.emit("markdown-open-pending", ());
        }))
    };

    let builder = builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init())
        // Save As dialog + file write. The webview has no download handler, so
        // exports/backups/QR saves go through these instead of <a download>.
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init());

    // Self-updater is desktop-only; iOS/Android update via their stores.
    // process plugin powers the updater's "Restart" button (relaunch()).
    // window-state persists the main window's size/position across launches;
    // the About window stays out so it always opens centered at its fixed size.
    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(
            tauri_plugin_window_state::Builder::default()
                .with_denylist(&["about"])
                .build(),
        );

    // Native in-app purchase (StoreKit on iOS, Play Billing on Android). One
    // plugin covers both; the desktop DMG never compiles it. The macOS App
    // Store build adds it for macOS under the `mas` feature (MAS track).
    // Spec: ops/docs/billing-integration.md (also drives Android storage-tier upgrades via subscriptionReplacementMode)
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_iap::init());

    // In-app OAuth (ASWebAuthenticationSession sheet). iOS only - see the
    // Cargo.toml entry for why Android stays on the system browser.
    #[cfg(target_os = "ios")]
    let builder = builder.plugin(tauri_plugin_auth_session::init());

    // The Android half of the biometric gate (src/biometric.rs). The other three
    // platforms call their OS from Rust and need no plugin; Android's API is
    // Kotlin, so the prompt arrives as one. It is registered without a
    // capability entry on purpose: the webview must not be able to invoke it,
    // and does not need to, because our own two commands call it from Rust.
    #[cfg(target_os = "android")]
    let builder = builder.plugin(tauri_plugin_biometric::init());

    // App-defined commands. These need no ACL/capability entry (only plugin
    // commands do). The biometric pair is registered on every platform and
    // answers "unavailable" where no OS gate exists (Linux), so the frontend can
    // always ask and fall back to WebAuthn on a false. The updater command is
    // desktop-only, which is the only reason there are two lists.
    #[cfg(desktop)]
    let builder = builder.invoke_handler(tauri::generate_handler![
        can_self_update,
        is_scoop_install,
        biometric_available,
        biometric_authenticate,
        print_html,
        take_pending_opens,
        markdown_assoc_status,
        markdown_assoc_claim,
        markdown_assoc_open_os_settings
    ]);
    #[cfg(mobile)]
    let builder = builder.invoke_handler(tauri::generate_handler![
        biometric_available,
        biometric_authenticate,
        print_html
    ]);

    builder
        .setup(|app| {
            // Bring the main window to the foreground on launch. After an
            // updater relaunch() the new process can otherwise come up behind
            // other windows, making it look like the restart did nothing.
            #[cfg(desktop)]
            {
                use tauri::Manager;
                // Cold start from a double-click on Windows and Linux: the path
                // is in our own argv. macOS does not use argv for this - it
                // sends an Apple Event, handled by RunEvent::Opened below.
                //
                // `args_os` and not `args`: `std::env::args()` PANICS on any
                // argument that is not valid Unicode, and a Linux filename is a
                // byte string with no encoding guarantee at all. Double-clicking
                // a legally-named file would have taken the app down on launch,
                // which is a worse failure than not opening it. Arguments that
                // will not convert are dropped rather than lossily mangled: the
                // frontend takes a path as a `String`, so a replacement-character
                // path could not be read anyway and would only fail later, in a
                // place that does not name the cause.
                queue_from_args(std::env::args_os().filter_map(|a| a.into_string().ok()));
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.set_focus();
                }
            }

            // Linux is the only desktop platform where nothing registers the
            // privacynotes:// scheme at install time: macOS gets it from the
            // bundle's Info.plist via LaunchServices and Windows from the NSIS
            // installer, but an AppImage is a loose file no desktop
            // environment ever indexes, so the system has no handler for the
            // scheme and every deep link is dropped with no error anywhere -
            // native Google sign-in hands the browser a link that goes
            // nowhere. Register it against this
            // binary on every launch: that covers the AppImage, repairs the
            // handler after it is moved or renamed, and keeps a .deb install
            // pointed at itself. Off-thread because it shells out to
            // update-desktop-database and xdg-mime, and a failure (neither
            // tool installed) must never block startup.
            // Spec: ops/docs/gotchas.md (Linux registers privacynotes:// at runtime)
            #[cfg(target_os = "linux")]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle.deep_link().register_all() {
                        eprintln!("failed to register the privacynotes:// scheme: {e}");
                    }
                });
            }

            // Swap the predefined About item in the app menu for our own,
            // which opens a styled About window (rendered by the web bundle)
            // instead of the unstylable system About panel. macOS only:
            // Windows/Linux builds have no app menu and keep their behavior.
            #[cfg(target_os = "macos")]
            {
                use tauri::menu::{Menu, MenuItem, MenuItemKind};

                let menu = Menu::default(app.handle())?;
                if let Some(MenuItemKind::Submenu(app_submenu)) = menu.items()?.into_iter().next()
                {
                    // Item 0 of the default app submenu is the predefined About.
                    app_submenu.remove_at(0)?;
                    let about = MenuItem::with_id(
                        app.handle(),
                        "about",
                        "About PrivacyNotes",
                        true,
                        None::<&str>,
                    )?;
                    app_submenu.insert(&about, 0)?;
                }
                app.set_menu(menu)?;
                app.on_menu_event(|app, event| {
                    if event.id().as_ref() == "about" {
                        open_about_window(app);
                    }
                });
            }

            let _ = &app;
            Ok(())
        })
        .build(context)
        .expect("error while building PrivacyNotes")
        .run(|_app, _event| {
            // macOS delivers a file open as an Apple Event, never in argv, so
            // this is the ONLY place a double-click arrives there. Reaching it
            // is why the builder ends in build()+run() rather than run() alone.
            // Spec: ops/docs/plans/markdown-folder.md (section 11)
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Opened { urls } = &_event {
                use tauri::Emitter;
                {
                    let mut queue = PENDING_OPEN.lock().unwrap();
                    for url in urls {
                        if let Ok(path) = url.to_file_path() {
                            if let Some(p) = path.to_str() {
                                if is_openable(p) {
                                    queue.push(p.to_string());
                                }
                            }
                        }
                    }
                }
                let _ = _app.emit("markdown-open-pending", ());
            }
        });
}

/// Whether this executable was unpacked by Scoop rather than installed by our NSIS
/// installer. Scoop keeps each app under `<root>\apps\<name>\<version>\` and treats that
/// path as its record of what is installed, so a build written into it out of band makes
/// the folder name a lie: `scoop list` keeps reporting the old version and the next
/// `scoop update` puts it back. The root is relocatable, so honour SCOOP and SCOOP_GLOBAL
/// before falling back to the default layout.
/// Spec: ops/docs/windows-release.md (a Scoop install updates through Scoop)
#[cfg(all(desktop, target_os = "windows"))]
fn unpacked_by_scoop() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        // Nothing to match against. Answering "not Scoop" keeps the ordinary NSIS
        // install self-updating, which is the far more common case.
        return false;
    };
    let exe = exe.to_string_lossy().to_lowercase();
    for var in ["SCOOP", "SCOOP_GLOBAL"] {
        let Some(root) = std::env::var_os(var) else { continue };
        let root = root.to_string_lossy().to_lowercase();
        let root = root.trim_end_matches('\\');
        if !root.is_empty() && exe.starts_with(&format!("{root}\\apps\\")) {
            return true;
        }
    }
    exe.contains("\\scoop\\apps\\")
}

/// Whether this install can self-update via the Tauri updater.
///
/// Two formats cannot, for the same underlying reason: the updater runs an installer
/// that writes somewhere other than where this copy lives. A Linux .deb sits in
/// root-owned /usr, so the AppImage payload fails to apply every launch; the APPIMAGE
/// env var the AppImage runtime sets is what tells the two apart. A Scoop install sits
/// in Scoop's own directory while our NSIS installer targets %LOCALAPPDATA%\PrivacyNotes,
/// so self-updating would leave a second copy the user's shortcut never points at.
/// The frontend nudges instead of installing whenever this is false.
/// Spec: ops/docs/linux-release.md (deb ships beside the AppImage; only the AppImage self-updates)
#[cfg(desktop)]
#[tauri::command]
fn can_self_update() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("APPIMAGE").is_some()
    }
    #[cfg(target_os = "windows")]
    {
        !unpacked_by_scoop()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        true
    }
}

/// Whether the nudge shown in place of a self-update should name Scoop. Both blocked
/// formats answer false to can_self_update, and their advice is opposite: a .deb user
/// fetches a newer package from the website, while a Scoop user must NOT, because the
/// download there is the NSIS installer that creates the second copy.
#[cfg(desktop)]
#[tauri::command]
fn is_scoop_install() -> bool {
    #[cfg(target_os = "windows")]
    {
        unpacked_by_scoop()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Whether this device can gate on the OS biometric (Touch ID, Face ID, Hello,
/// or an Android fingerprint or face).
///
/// The webview's own check is useless in a native build: embedded webviews expose
/// no WebAuthn platform authenticator, so `isUserVerifyingPlatformAuthenticator-
/// Available()` resolves false even on a Mac with Touch ID, which is why
/// Security > Biometric Lock claimed "not available on this device". False where
/// the OS has no gate to offer (Linux); the frontend then falls back to the
/// WebAuthn check. Async so the OS round trip never stalls the main thread
/// (a sync command would run there); it touches no UI.
/// Spec: ops/docs/biometric-unlock.md, backlog #101 (must check the same biometric class the prompt will request)
#[tauri::command(async)]
fn biometric_available(app: tauri::AppHandle) -> bool {
    #[cfg(native_biometric)]
    {
        biometric::available(&app)
    }
    #[cfg(not(native_biometric))]
    {
        let _ = app;
        false
    }
}

/// Presents the OS biometric prompt and resolves true only if it succeeded.
///
/// `Ok(false)` is every flavour of "no" (cancelled, wrong finger, fell back,
/// system interrupt) - the caller just keeps the app locked and offers PIN or
/// phrase. `Err` means no prompt could be shown at all. The wait always happens
/// on a blocking task; each platform backend then does its own thread hop, since
/// LAContext wants the main thread and Hello must not have it.
///
/// Both strings are rendered by the OS, so the frontend sends them translated:
/// the reason for the prompt, and the label for the cancel button that Android
/// draws itself.
#[tauri::command]
async fn biometric_authenticate(
    app: tauri::AppHandle,
    reason: String,
    cancel_label: String,
) -> Result<bool, String> {
    #[cfg(native_biometric)]
    {
        tauri::async_runtime::spawn_blocking(move || {
            biometric::authenticate(&app, reason, cancel_label)
        })
        .await
        .map_err(|e| e.to_string())?
    }
    #[cfg(not(native_biometric))]
    {
        let _ = (app, reason, cancel_label);
        Err("Native biometric authentication is not available on this platform.".to_owned())
    }
}

/// Prints one note from the standalone HTML document the frontend already
/// renders for the .html export - same markup, same print CSS, same inlined
/// images, so a printout matches the browser's on every platform.
///
/// Only macOS and iOS need this: their WKWebView silently ignores
/// `window.print()`, so the frontend's hidden-iframe path opened nothing there
/// (Windows and Linux implement it and keep that path). Everywhere else this
/// answers with an error, which the frontend reads as "print it yourself".
/// Async so a multi-megabyte document deserializes off the main thread; the
/// print UI itself is put up on the main thread by `print.rs`.
#[tauri::command]
async fn print_html(app: tauri::AppHandle, html: String, job_name: String) -> Result<(), String> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        print::print(&app, html, job_name)
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = (app, html, job_name);
        Err("Native printing is only needed on macOS and iOS.".to_owned())
    }
}

/// Opens (or focuses) the custom About window. The web bundle renders it:
/// main.tsx branches to AboutWindow.tsx when the URL carries ?about-window=1.
/// Fixed-size and closable only, mimicking the standard macOS About panel;
/// the overlay title bar puts the traffic lights over our themed background.
/// The window cannot resize itself, so the height is sized by hand to the
/// content: add or remove a link button in AboutWindow.tsx and this number
/// moves with it (~41px per button, including the gap).
#[cfg(target_os = "macos")]
fn open_about_window(app: &tauri::AppHandle) {
    use tauri::{Manager, TitleBarStyle, WebviewUrl, WebviewWindowBuilder};

    if let Some(existing) = app.get_webview_window("about") {
        let _ = existing.set_focus();
        return;
    }
    let _ = WebviewWindowBuilder::new(
        app,
        "about",
        WebviewUrl::App("index.html?about-window=1".into()),
    )
    .title("About PrivacyNotes")
    .inner_size(280.0, 485.0)
    .resizable(false)
    .minimizable(false)
    .maximizable(false)
    .hidden_title(true)
    .title_bar_style(TitleBarStyle::Overlay)
    .accept_first_mouse(true)
    .center()
    .build();
}

/// The argv side of the file association, which is the only part of it that
/// can be reached without an `AppHandle`.
///
/// Both of these came out of the September security review. A path is claimed
/// on its extension alone, and a `file://` value is unwrapped through a URL
/// parser, so a token that is neither still has to be refused. And the
/// unwrapping is scoped to the platform that needs it: a Linux file manager
/// launching a `%F` desktop entry may hand over a URL, while on Windows the
/// same code turned an attacker-supplied deep link into a filesystem path,
/// because the single-instance forwarder splits one argument into several.
///
/// Spec: ops/docs/audit-adversarial-2026-09-bfg.md (SEC-20, SEC-34)
#[cfg(all(test, desktop))]
mod tests {
    use super::*;

    #[test]
    fn claims_the_registered_extensions_and_nothing_else() {
        assert_eq!(openable_path("/tmp/a.md").as_deref(), Some("/tmp/a.md"));
        assert_eq!(openable_path("/tmp/a.MD").as_deref(), Some("/tmp/a.MD"));
        assert_eq!(openable_path("/tmp/a.txt").as_deref(), Some("/tmp/a.txt"));
        assert!(openable_path("/tmp/a.pdf").is_none());
        assert!(openable_path("--flag").is_none());
        assert!(openable_path("/tmp/noextension").is_none());
    }

    #[test]
    fn a_deep_link_is_not_a_file() {
        // The scheme is the app's own, and the last segment ends in one of the
        // registered extensions, which is all `is_openable` looks at.
        assert!(openable_path("privacynotes://x/y.md").is_none());
        // The opaque form, which is what the Windows forwarder splits.
        assert!(openable_path("privacynotes:x|file:///tmp/a.md").is_none());
        assert!(openable_path("https://example.com/a.md").is_none());
    }

    #[test]
    fn a_path_that_merely_contains_a_colon_is_still_a_path() {
        // One character before the colon is a Windows drive, not a scheme.
        assert_eq!(openable_path("C:\\notes\\a.md").as_deref(), Some("C:\\notes\\a.md"));
        // And a colon after a separator belongs to the file name.
        assert_eq!(openable_path("/tmp/my:file.md").as_deref(), Some("/tmp/my:file.md"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn unwraps_a_file_url_where_a_file_manager_sends_one() {
        assert_eq!(openable_path("file:///tmp/a.md").as_deref(), Some("/tmp/a.md"));
        // Percent-encoding is why this goes through a parser at all.
        assert_eq!(
            openable_path("file:///tmp/my%20note.md").as_deref(),
            Some("/tmp/my note.md"),
        );
    }

    /// The Windows refusal, pinned where every platform can run it.
    ///
    /// On Windows the `file://` unwrapping is compiled out, so such an
    /// argument falls to the general rule below, and this is that rule. A
    /// build for another platform cannot exercise the branch itself, so the
    /// predicate it depends on is asserted instead.
    #[test]
    fn a_file_url_is_a_url_by_the_general_rule() {
        assert!(has_url_scheme("file:///C:/Users/victim/notes/private.md"));
        assert!(has_url_scheme("file://attacker.example/share/x.md"));
        assert!(!has_url_scheme("C:\\notes\\a.md"));
        assert!(!has_url_scheme("/tmp/my:file.md"));
        assert!(!has_url_scheme("--flag"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn refuses_a_file_url_on_windows() {
        // Windows never delivers one, and the single-instance forwarder joins
        // argv with a pipe and splits the payload on the same character, so
        // one crafted deep link arrives as several arguments. Unwrapping here
        // turned the second of them into a path the app then opened, local or
        // a UNC name pointing at a host the sender chose.
        assert!(openable_path("file:///C:/Users/victim/notes/private.md").is_none());
        assert!(openable_path("file://attacker.example/share/x.md").is_none());
    }

    /// The third producer of the queue, and why it needs no scheme check.
    ///
    /// macOS delivers a double-click as an Apple Event rather than in argv,
    /// so `RunEvent::Opened` pushes straight onto the queue without going
    /// through `openable_path`. It calls `to_file_path()` first, which is a
    /// stronger rule than the one above rather than a missing one: a URL that
    /// is not a file URL has no file path to give. Asserted because the claim
    /// is about a library, not about our code.
    #[test]
    fn a_non_file_url_has_no_file_path() {
        let deep = tauri::Url::parse("privacynotes://x/y.md").unwrap();
        assert!(deep.to_file_path().is_err());
        let web = tauri::Url::parse("https://example.com/a.md").unwrap();
        assert!(web.to_file_path().is_err());
        let file = tauri::Url::parse("file:///tmp/a.md").unwrap();
        assert!(file.to_file_path().is_ok());
    }

    #[test]
    fn a_batch_carrying_the_app_scheme_queues_nothing() {
        // What the Windows forwarder produces from one crafted link: the
        // scheme token, then the payload, which announces nothing and ends in
        // a registered extension. A UNC name is the sharp one - opening it is
        // an outbound connection to a host the sender chose.
        PENDING_OPEN.lock().unwrap().clear();
        queue_from_args([
            "app.exe".to_string(),
            "privacynotes:x".to_string(),
            "\\\\attacker.example\\share\\x.md".to_string(),
        ]);
        assert!(PENDING_OPEN.lock().unwrap().is_empty());

        // And the same batch shape with a local path, which is the same
        // injection with a quieter payload.
        queue_from_args([
            "app.exe".to_string(),
            "privacynotes://auth-callback".to_string(),
            "C:\\Users\\victim\\notes\\private.md".to_string(),
        ]);
        assert!(PENDING_OPEN.lock().unwrap().is_empty());
        PENDING_OPEN.lock().unwrap().clear();
    }

    #[test]
    fn a_network_path_still_opens_when_nobody_smuggled_it() {
        // The refusal is about the delivery, not the shape: a double-click on
        // a note that lives on a real file server is an ordinary open.
        PENDING_OPEN.lock().unwrap().clear();
        queue_from_args([
            "app.exe".to_string(),
            "\\\\fileserver\\team\\notes.md".to_string(),
        ]);
        assert_eq!(
            PENDING_OPEN.lock().unwrap().clone(),
            vec!["\\\\fileserver\\team\\notes.md"],
        );
        PENDING_OPEN.lock().unwrap().clear();
    }

    /// What `readDir` reports for a symlink, which is the fact the folder
    /// scan's refusal rests on.
    ///
    /// The plugin derives `isFile`, `isDirectory` and `isSymlink` from one
    /// `DirEntry::file_type()` call and returns false for all three when it
    /// cannot stat the entry (tauri-plugin-fs-2.5.2/src/commands.rs:486-501).
    /// `file_type()` does not traverse a link, so a link reports itself
    /// rather than its target - which is why the frontend asks for a proven
    /// file rather than for "not a symlink". Asserted against a real link on
    /// a real filesystem, because it is an operating-system behaviour and
    /// the whole guard depends on it.
    ///
    /// Spec: ops/docs/audit-adversarial-2026-09-bfg.md (SEC-21)
    #[test]
    fn a_symlink_reports_itself_and_not_its_target() {
        let dir = std::env::temp_dir().join("pn-symlink-filetype-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.md");
        std::fs::write(&target, "real bytes").unwrap();
        let link = dir.join("link.md");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &link).unwrap();

        let mut seen = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let file_type = entry.file_type().unwrap();
            match entry.file_name().to_str().unwrap() {
                "target.md" => {
                    assert!(file_type.is_file());
                    assert!(!file_type.is_symlink());
                    seen += 1;
                }
                "link.md" => {
                    // The two the scan reads: a link is not a file, so asking
                    // for a proven file refuses it.
                    assert!(file_type.is_symlink());
                    assert!(!file_type.is_file());
                    assert!(!file_type.is_dir());
                    seen += 1;
                }
                other => panic!("unexpected entry {other}"),
            }
        }
        assert_eq!(seen, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn queue_skips_argv_zero_and_keeps_the_order_given() {
        PENDING_OPEN.lock().unwrap().clear();
        queue_from_args([
            "/Applications/PrivacyNotes.app/Contents/MacOS/a.md".to_string(),
            "/tmp/first.md".to_string(),
            "--flag".to_string(),
            "/tmp/second.txt".to_string(),
        ]);
        let queued = PENDING_OPEN.lock().unwrap().clone();
        assert_eq!(queued, vec!["/tmp/first.md", "/tmp/second.txt"]);
        PENDING_OPEN.lock().unwrap().clear();
    }
}
