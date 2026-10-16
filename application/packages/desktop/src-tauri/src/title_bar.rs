//! The Windows title bar in the app's own colors.
//!
//! The main window keeps the native title bar on Windows, so its buttons,
//! snap layouts and drag behave like every other window. Windows paints that
//! bar from the system theme, which leaves a light bar over a dark app theme
//! (and the reverse). The frontend pushes the color of the app shell and its
//! text on every theme change, and this paints the bar with them.
//!
//! Two layers, because Windows 10 ignores the color attributes. The window
//! theme makes the bar dark or light everywhere and also picks the color of
//! the caption buttons; the caption and text colors then give Windows 11 the
//! exact theme color. `dark: None` hands the theme back to the system: the
//! window theme also sets `prefers-color-scheme` in the web view, so pinning it
//! while the app follows the system would freeze the app on the pinned mode.
//! Spec: ops/docs/color-themes.md (section 1, the Windows title bar)

#[cfg(target_os = "windows")]
pub fn paint(window: &tauri::WebviewWindow, caption: [u8; 3], text: [u8; 3], dark: Option<bool>) {
    use tauri::Theme;
    use windows::Win32::Foundation::{COLORREF, HWND};
    use windows::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR,
    };

    let _ = window.set_theme(dark.map(|d| if d { Theme::Dark } else { Theme::Light }));
    let Ok(handle) = window.hwnd() else {
        return;
    };
    let hwnd = HWND(handle.0);
    // COLORREF is 0x00BBGGRR.
    let colorref =
        |[r, g, b]: [u8; 3]| COLORREF(u32::from(r) | u32::from(g) << 8 | u32::from(b) << 16);
    for (attribute, color) in [(DWMWA_CAPTION_COLOR, caption), (DWMWA_TEXT_COLOR, text)] {
        let value = colorref(color);
        // SAFETY: the pointer and size describe a live COLORREF on this stack
        // frame, which is the type both attributes document. Windows 10 returns
        // an error for these attributes, and the window theme above stands.
        let _ = unsafe {
            DwmSetWindowAttribute(
                hwnd,
                attribute,
                std::ptr::from_ref(&value).cast(),
                std::mem::size_of::<COLORREF>() as u32,
            )
        };
    }
}

/// macOS draws the app under an overlay title bar and Linux follows the GTK
/// theme, so there is nothing to paint there.
#[cfg(not(target_os = "windows"))]
pub fn paint(
    _window: &tauri::WebviewWindow,
    _caption: [u8; 3],
    _text: [u8; 3],
    _dark: Option<bool>,
) {
}
