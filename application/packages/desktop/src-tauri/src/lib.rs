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

#[cfg(desktop)]
fn is_openable(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| OPENABLE_EXT.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Turn one argv entry into a filesystem path we claimed, or None.
///
/// Two jobs. The extension check is the obvious one - argv carries flags, deep
/// links and files we never registered. The `file://` unwrapping is the subtle
/// one: a Linux file manager launching a `%F` desktop entry may hand over a URL
/// rather than a bare path, and `openPath` on the frontend passes its argument
/// straight to the fs plugin AS a path. A URL would sail through the extension
/// check (`.md` parses fine) and then fail to read, which looks exactly like a
/// broken feature. Percent-encoding is why this goes through a URL parser
/// instead of a `strip_prefix`: `file:///home/a/my%20note.md` has to come back
/// as a real space.
#[cfg(desktop)]
fn openable_path(arg: &str) -> Option<String> {
    // Only treat an argument as a URL when it says so. A bare Windows path -
    // `C:\notes\a.md` - parses as a URL with scheme "c", so parsing first and
    // asking about the scheme afterwards would mangle every Windows double-click.
    let path = if arg.starts_with("file://") {
        tauri::Url::parse(arg)
            .ok()?
            .to_file_path()
            .ok()?
            .to_string_lossy()
            .into_owned()
    } else {
        arg.to_owned()
    };
    is_openable(&path).then_some(path)
}

/// Queue every openable path in an argv-style list. Windows and Linux deliver
/// file opens this way, both on a cold start and through single-instance.
#[cfg(desktop)]
fn queue_from_args<I: IntoIterator<Item = String>>(args: I) {
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
        for path in &paths {
            // A path that cannot be granted is still worth returning: the read
            // will fail with the frontend's own error state rather than being
            // silently dropped here, which is the more debuggable of the two.
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

    let builder = tauri::Builder::default();

    // single-instance MUST be the first plugin registered. With the
    // deep-link feature it forwards a privacynotes:// callback caught by a
    // second on-disk copy of the app to the already-running instance,
    // instead of letting that copy launch fresh and swallow the OAuth
    // redirect. Desktop only. Spec: ops/docs/macos-ios-setup.md (native OAuth)
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
        use tauri::{Emitter, Manager};
        // A second launch carrying a file path is a double-click while we are
        // already running. The args were discarded here until file
        // associations existed; now they are the whole point of the callback.
        queue_from_args(args);
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.set_focus();
        }
        let _ = app.emit("markdown-open-pending", ());
    }));

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
        .build(tauri::generate_context!())
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
