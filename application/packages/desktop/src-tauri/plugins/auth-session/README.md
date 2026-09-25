# auth-session

The in-app OAuth sheet for the iOS build: an `ASWebAuthenticationSession` that completes on an https return address bound to this app.

Forked from [tauri-plugin-auth-session 0.2.2](https://github.com/yanqianglu/tauri-plugin-auth-session) (MIT OR Apache-2.0; both licenses sit beside this file). It is a path dependency of `src-tauri/Cargo.toml` rather than a registry crate, so no dependency bump can swap the upstream behaviour back in.

What changed from upstream, and why:

- The `start` command takes `callbackHost` and `callbackPath` instead of `callbackUrlScheme`, and builds the session with `ASWebAuthenticationSessionCallback.https(host:path:)` through `initWithURL:callback:completionHandler:`, which exists from iOS 17.4. iOS completes the sheet on that URL only when the host is one of the app's associated `webcredentials` domains, a claim the OS checks against `https://use.privacynotes.app/.well-known/apple-app-site-association`. A custom scheme is a first-come claim that any app can make, so it is not offered at all.
- The `ephemeral` option is gone; the app never set it.
- iOS only. The macOS and Android halves, the guest JavaScript package and the Android project are removed, because this app compiles the crate for the iOS target alone: Android keeps the system browser and an App Link, and desktop returns to a page.
- `objc2-authentication-services` gains the `ASWebAuthenticationSessionCallback` feature, which the upstream manifest does not enable.

Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.2)
