package app.privacynotes

import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.print.PrintAttributes
import android.print.PrintManager
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import kotlin.math.max

class MainActivity : TauriActivity() {
  // Bar strip colors pushed by the web layer through the __pnBars bridge
  // below. Null until the first push, which is a cold start before the
  // app's JS has run; applyDecorBackground() then falls back to the
  // system uiMode, the best guess available at that point and correct
  // under the default 'auto' theme mode.
  private var webBarColor: Int? = null
  private var webBarDark: Boolean? = null
  // Holds the throwaway webview that renders a note for printing. A local
  // would be collected while the print job is still pulling pages out of
  // it, which prints blank; Android's own "print an HTML document" guidance
  // keeps the same field for the same reason. See PrintBridge below.
  private var printWebView: WebView? = null
  // Whether the app lock is on, pushed by the web layer through the
  // __pnPrivacy bridge below. Decides whether the recents card shows the
  // notes. Spec: ops/docs/plans/app-switcher-privacy-screen.md
  private var privacyScreenArmed = false
  // The black view laid over the content while the window has no focus.
  private var privacyCover: View? = null
  // Back press routing (#174). TauriActivity sets wry's
  // handleBackNavigation to false, so with no callback of our own a
  // back press finishes the activity - the app appears to quit from
  // every screen. Route presses into the web app first
  // (window.__pnHandleBack in packages/web/src/androidBack.ts closes
  // the topmost overlay / leaves the open note and returns true);
  // when nothing is left to dismiss, background the app with state
  // preserved, like a home press - never finish(). Covers both the
  // 3-button Back and gesture-nav back swipes (both route through
  // OnBackPressedDispatcher).
  //
  // Registered HERE, not in onCreate: tauri core registers its own
  // always-enabled AppPlugin back callback asynchronously after
  // onCreate but before webview creation, and the dispatcher is LIFO -
  // a callback added in onCreate would sit below AppPlugin's, which
  // calls webView.goBack() whenever the webview has history (any
  // same-document #anchor navigation creates an entry) and would
  // silently swallow the entire cascade. Registering on webview
  // creation keeps ours on top of the dispatcher stack.
  // Tracked in git; restore after any `tauri android init`.
  // Spec: ops/docs/android-setup.md (re-apply checklist)
  override fun onWebViewCreate(webView: WebView) {
    // Bar-color bridge (#205). wry calls setWebView() before it loads the
    // app URL, so the interface is in place for the very first document
    // and the boot-time paint already pushes. See applyDecorBackground().
    webView.addJavascriptInterface(BarsBridge(), "__pnBars")
    webView.addJavascriptInterface(PrintBridge(), "__pnPrint")
    webView.addJavascriptInterface(InstallerBridge(), "__pnInstaller")
    webView.addJavascriptInterface(PrivacyBridge(), "__pnPrivacy")

    onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
      override fun handleOnBackPressed() {
        webView.evaluateJavascript("window.__pnHandleBack ? window.__pnHandleBack() : false") { consumed ->
          if (consumed != "true") moveTaskToBack(true)
        }
      }
    })
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)

    // Soft-keyboard / edge-to-edge fix, community-verified for targetSdk 35+
    // (tauri-apps/tauri#10631): pad the DECOR view by the system bar insets
    // on all sides, use the keyboard inset for the bottom when it is taller,
    // and return CONSUMED so nothing below the decor - including Chromium's
    // own webview inset handling - applies the same insets again.
    // Weaker variants fail: content-view padding without consumption still
    // lets the webview shrink + pan its visual viewport a second time
    // (keyboard subtracted twice, header scrolled off-screen; verified on
    // device via logcat + visualViewport probes).
    // Consequences: the webview no longer draws under the bars, so CSS
    // env(safe-area-inset-*) reads 0 in the Android app, and the strips
    // behind the bars show the decor background, painted below to match the
    // app theme (pushed from paintNativeBars() in packages/web/src/theme.ts).
    //
    // enableEdgeToEdge() turns navigation-bar contrast enforcement ON, which
    // makes the framework paint a translucent scrim over the nav bar under
    // 3-button navigation. Against a strip we color ourselves that reads as a
    // seam between the app's bottom bar and the bar below it, so opt out.
    // Tracked in git; restore after any `tauri android init`.
    // Spec: ops/docs/android-setup.md (re-apply checklist)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      window.isNavigationBarContrastEnforced = false
    }
    applyDecorBackground()
    ViewCompat.setOnApplyWindowInsetsListener(window.decorView) { view, insets ->
      val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
      val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
      view.setPadding(bars.left, bars.top, bars.right, max(bars.bottom, ime.bottom))
      WindowInsetsCompat.CONSUMED
    }
  }

  override fun onConfigurationChanged(newConfig: Configuration) {
    super.onConfigurationChanged(newConfig)
    // uiMode is in configChanges, so a system light/dark switch lands here
    // instead of recreating the activity; keep the bar strips matching.
    // Once the web layer has pushed, this repaints the same colors and the
    // real update arrives from paintNativeBars() - under 'auto' the web
    // layer has its own matchMedia listener, and under a pinned mode an OS
    // flip must NOT change the strips at all.
    applyDecorBackground()
  }

  /**
   * Paint the strips behind the status and navigation bars, and pick the
   * glyph color that reads against them.
   *
   * Prefers what the web layer pushed, because only it knows the answer:
   * the light/dark MODE can be pinned against the OS, and on top of that
   * sits a color theme (Cream, Slate, Navy) whose surface is nowhere near
   * either default. Reading the system uiMode here got both wrong - a
   * Cream app on a dark phone showed black bars (#205).
   *
   * The fallback is the pre-bridge behavior and covers exactly one moment,
   * the cold start before the app's first paint.
   */
  private fun applyDecorBackground() {
    val dark = webBarDark ?: ((resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
      Configuration.UI_MODE_NIGHT_YES)
    window.decorView.setBackgroundColor(
      webBarColor ?: if (dark) Color.parseColor("#171514") else Color.parseColor("#F5F5F5")
    )
    // The gesture pill, the 3-button glyphs, the clock and the status
    // icons. enableEdgeToEdge() derives these from the system uiMode too,
    // so without this a light strip on a dark phone kept white glyphs and
    // the nav pill disappeared into the bar.
    WindowCompat.getInsetsController(window, window.decorView).apply {
      isAppearanceLightStatusBars = !dark
      isAppearanceLightNavigationBars = !dark
    }
  }

  /**
   * Hide the notes from the recents card while the app lock is on.
   *
   * Android photographs an activity as it leaves the screen and shows that
   * picture in recents. An open note is readable there, and the app lock never
   * runs, because the app was never opened.
   *
   * Two halves, because the overview draws the card two different ways and each
   * way needs its own answer. FLAG_SECURE marks the window's surface secure and
   * the snapshot system refuses a secure surface, so the stored picture is never
   * taken. That covers the card you meet coming back from another app. It does
   * NOT cover the card you meet pressing recents from inside the app, because
   * that one composites the live window rather than a stored picture, and a
   * live window is not something a flag can withhold. Only changing what the
   * window draws reaches it, which is what showPrivacyCover does, and it is the
   * same thing the iOS half does with a UIView.
   *
   * Both are raised the moment the window loses focus.
   *
   * The hook is onWindowFocusChanged and NOT onPause, which is the whole
   * difference between this working and not. Pressing the recents button from
   * inside the app does not pause the activity at all: the overview opens, the
   * system photographs the window, and onPause arrives later or never. Measured
   * on a Pixel 10 on Android 16, where the flag was absent from the window at
   * the moment the card was drawn. Losing window focus happens first, on every
   * route out of the app, so that is where the flag belongs.
   *
   * Focus also goes when a dialog, the notification shade or the biometric
   * prompt comes up. Raising the flag there costs nothing: the app is behind
   * something the user is already looking at, and focus returning clears it.
   *
   * The API 33 alternative, setRecentsScreenshotEnabled(false), reads like the
   * better fit because it touches nothing but the card. It was tried first and
   * does not hold: on a Pixel 10 running Android 16 the card still showed the
   * live screen with the flag set. Its own documentation calls it a hint, and
   * the system falls back to the window's theme background only when it feels
   * like it.
   *
   * FLAG_SECURE also blocks screenshots and screen recording, which would be
   * the wrong trade if it were always on. It is not: onPause raises it and
   * onResume clears it, and taking a screenshot does not pause an activity, so
   * a user photographing their own notes is unaffected.
   *
   * Tracked in git; restore after any `tauri android init`.
   * Spec: ops/docs/android-setup.md (re-apply checklist)
   */
  override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    if (hasFocus) {
      // Cleared whatever the armed state is: a user who turns the app lock off
      // while the app is away must not come back to a covered window that
      // still refuses screenshots.
      window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
      hidePrivacyCover()
    } else if (privacyScreenArmed) {
      window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
      showPrivacyCover()
    }
  }

  /**
   * Lay a black view over everything the window draws.
   *
   * FLAG_SECURE answers the picture the system stores, which is what the card
   * shows once the app has stopped. It does not answer the first moment: the
   * overview opened from inside the app composites the live window, and a live
   * window is not a stored picture. Only changing what the window draws
   * reaches that, which is the same thing the iOS half does with a UIView.
   *
   * The decor background goes black with it, because the view is laid out
   * inside the decor's padding and the bar strips would otherwise keep the
   * theme colour around a black rectangle.
   */
  private fun showPrivacyCover() {
    if (privacyCover != null) return
    val decor = window.decorView as? ViewGroup ?: return
    val cover = View(this)
    cover.setBackgroundColor(Color.BLACK)
    cover.layoutParams = ViewGroup.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT,
      ViewGroup.LayoutParams.MATCH_PARENT,
    )
    decor.addView(cover)
    decor.setBackgroundColor(Color.BLACK)
    privacyCover = cover
  }

  private fun hidePrivacyCover() {
    val cover = privacyCover ?: return
    (cover.parent as? ViewGroup)?.removeView(cover)
    privacyCover = null
    applyDecorBackground()
  }

  /**
   * JS -> native channel for the app lock state. `set` is called from
   * applyPrivacyScreen() in packages/web/src/privacyScreen.ts, from the one
   * place local settings are written, so turning the lock off disarms this on
   * the same path that turning it on arms it.
   *
   * @JavascriptInterface methods arrive on a binder thread, hence the hop.
   */
  private inner class PrivacyBridge {
    @JavascriptInterface
    fun set(enabled: Boolean) {
      runOnUiThread {
        privacyScreenArmed = enabled
        if (!enabled) {
          window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
      }
    }
  }

  /**
   * JS -> native channel for printing a note.
   *
   * Android's WebView ignores JavaScript's `window.print()` exactly the way
   * WKWebView does - it returns, throws nothing, logs nothing, and no dialog
   * appears - so the frontend's hidden-iframe print path was dead here too
   * (see ops/docs/gotchas.md). Printing on Android belongs to the app: only
   * PrintManager can start a job, and only a WebView can turn HTML into
   * printable pages. wry has no Android print of its own (its `print()` is an
   * empty stub), so unlike macOS and iOS there is nothing to reach from Rust
   * and this bridge is the whole native side.
   *
   * `html` is the standalone note document the frontend already builds for
   * the .html export, images inlined as data URIs, so a printout matches
   * every other platform's. Loaded into a webview of its own because the
   * app's own one is showing the app.
   *
   * @JavascriptInterface methods arrive on a binder thread, hence the hop.
   */
  private inner class PrintBridge {
    @JavascriptInterface
    fun print(html: String, jobName: String) {
      runOnUiThread {
        val webView = WebView(this@MainActivity)
        webView.webViewClient = object : WebViewClient() {
          override fun onPageFinished(view: WebView, url: String) {
            val manager = getSystemService(Context.PRINT_SERVICE) as? PrintManager ?: return
            manager.print(
              jobName,
              view.createPrintDocumentAdapter(jobName),
              PrintAttributes.Builder().build(),
            )
          }
        }
        // No base URL: the document is self-contained, and handing it one
        // would give it that origin's reach for no reason.
        webView.loadDataWithBaseURL(null, html, "text/html", "utf-8", null)
        printWebView = webView
      }
    }
  }

  /**
   * JS -> native channel for the installing package name.
   *
   * The direct APK is the same file whether a store put it here or the user
   * downloaded it in a browser, so the frontend cannot tell from the build
   * alone whether anything else is going to update this app. Android knows,
   * and this is the only way to ask: androidInstaller.ts turns the answer
   * into "a store keeps this current" and suppresses the update prompt on a
   * true. Spec: ops/docs/android-update-check.md (store-installed APKs)
   *
   * An empty string means nobody claimed the install, which is what a raw
   * sideload looks like. getInstallSourceInfo arrived in API 30 and the app
   * runs from API 24, hence the deprecated call underneath it.
   *
   * Tracked in git; restore after any `tauri android init`.
   * Spec: ops/docs/android-setup.md (re-apply checklist)
   */
  private inner class InstallerBridge {
    @JavascriptInterface
    fun get(): String {
      return try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          packageManager.getInstallSourceInfo(packageName).installingPackageName
        } else {
          @Suppress("DEPRECATION")
          packageManager.getInstallerPackageName(packageName)
        } ?: ""
      } catch (e: PackageManager.NameNotFoundException) {
        ""
      }
    }
  }

  /**
   * JS -> native channel for the bar colors. `set` is called from
   * paintNativeBars() in packages/web/src/theme.ts on every theme change,
   * with the resolved `--pn-surface-0` of the active palette.
   *
   * @JavascriptInterface methods arrive on a binder thread, hence the hop.
   */
  private inner class BarsBridge {
    @JavascriptInterface
    fun set(color: String, dark: Boolean) {
      val parsed = try {
        Color.parseColor(color)
      } catch (e: IllegalArgumentException) {
        return
      }
      runOnUiThread {
        webBarColor = parsed
        webBarDark = dark
        applyDecorBackground()
      }
    }
  }
}
