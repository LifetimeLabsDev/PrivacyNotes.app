declare global {
  interface Window {
    /** Installed by MainActivity.kt in the Android app; absent everywhere else. */
    __pnInstaller?: { get: () => string };
  }
}

/**
 * Whether an app store installed this build and therefore keeps it updated.
 *
 * The direct APK is one artifact, byte for byte, however it reaches a phone.
 * A store that carries it (Zapstore, Obtainium) has its own updater, checks
 * for new releases in the background and applies them in place, because every
 * release is signed with the same certificate. A raw sideload - a browser
 * download, `adb install` - has nothing of the kind, which is the whole
 * reason AndroidUpdateToast exists.
 *
 * Android's installing package name is the only thing that separates the two,
 * and it reaches the frontend through MainActivity.kt's __pnInstaller bridge,
 * the same shape as the bar-color and print bridges beside it.
 *
 * KNOWN_STORES is an allowlist, not a denylist, and the asymmetry is the
 * point. An unrecognised installer counts as a sideload, so its user still
 * gets the update prompt: one redundant toast is the cost of being wrong.
 * Inverted, a store nobody listed here would strand its users on an old build
 * with nothing on screen to explain the silence. Add an entry when a new
 * store starts carrying the APK.
 */
const KNOWN_STORES = new Set([
  // https://zapstore.dev
  'dev.zapstore.app',
  // github.com/ImranR98/Obtainium, plus the id its F-Droid build ships under.
  'dev.imranr.obtainium',
  'dev.imranr.obtainium.fdroid',
]);

/**
 * The installing package, or null off Android and on a raw sideload.
 *
 * Read once: Android cannot change it while the app runs, and the bridge hop
 * is a synchronous JNI call.
 */
function readInstaller(): string | null {
  try {
    const value = window.__pnInstaller?.get();
    return value ? value : null;
  } catch {
    // No bridge (web, desktop, iOS) or a binder failure: treat as unknown,
    // which the allowlist below reads as a sideload.
    return null;
  }
}

const INSTALLER = readInstaller();

/** The allowlist decision on its own, so a test can state it without a webview. */
export function isStoreInstaller(pkg: string | null): boolean {
  return pkg !== null && KNOWN_STORES.has(pkg);
}

export function installedByStore(): boolean {
  return isStoreInstaller(INSTALLER);
}
