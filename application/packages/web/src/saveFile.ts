/**
 * Cross-platform "save a Blob to disk".
 *
 * On web we use the classic hidden-anchor + `download` attribute trick. In the
 * native (Tauri) webview that trick is a silent no-op - the webview has no
 * download handler - so exports, "Save QR", and phrase backups all did nothing
 * on desktop. On native we instead open a Save As dialog and write the bytes
 * with the fs plugin.
 *
 * The web branch runs synchronously up to the anchor click, so callers that do
 * not await still trigger the download inside the user-gesture task.
 *
 * The native branch verifies what actually landed on disk before it resolves.
 * On Android `save()` is ACTION_CREATE_DOCUMENT, which creates the file the
 * moment the user taps Save - so every way the following write can fail leaves
 * a real, empty, 0-byte file behind. A caller that does not hear about the
 * failure is worse than useless here: the user walks away holding a backup
 * that will not restore. Reported as issue #193.
 *
 * Spec: ops/docs/gotchas.md (native webview has no download handler; Android
 * SAF writes need a truncate-free retry and a size check)
 */
import { detectPlatform } from './devices';
import i18n from './i18n';

export async function saveBlob(blob: Blob, filename: string): Promise<void> {
  if (detectPlatform() === 'web') {
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } finally {
      // Defer revoke so the browser has time to start the download.
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    }
    return;
  }

  // Native: the webview cannot download, so prompt for a location and write the
  // bytes ourselves. `save` returns null when the user cancels the dialog.
  const [{ save }, fs] = await Promise.all([
    import('@tauri-apps/plugin-dialog'),
    import('@tauri-apps/plugin-fs'),
  ]);
  const path = await save({ defaultPath: filename });
  if (!path) return;
  const bytes = new Uint8Array(await blob.arrayBuffer());

  try {
    await fs.writeFile(path, bytes);
  } catch (err) {
    // plugin-fs opens the target in "wt" (write + truncate) mode. On Android
    // that mode reaches the DocumentsProvider behind the content:// URI, and
    // providers are free not to implement truncate - Drive-style ones reject
    // the open outright. The document the picker just created is empty by
    // definition, so appending is equivalent to writing: retry without the
    // truncate flag rather than hand back a 0-byte file. Only retry when the
    // target is confirmed still empty, so a write that died halfway can never
    // be appended to.
    if ((await fileSize(fs, path)) !== 0) throw err;
    await fs.writeFile(path, bytes, { append: true });
  }

  // Confirm the bytes are really there. `fileSize` returns null when the
  // platform cannot answer, and an unanswerable check must not fail a save
  // that probably worked - only a definite mismatch throws.
  const written = await fileSize(fs, path);
  if (written !== null && written !== bytes.length) {
    throw new Error(
      i18n.t('importExport:saveErrors.shortWrite', {
        written,
        expected: bytes.length,
      }),
    );
  }
}

/** Bytes currently on disk at `path`, or null when the size cannot be read
 *  (stat unsupported for this target, permission denied, file gone). */
async function fileSize(
  fs: typeof import('@tauri-apps/plugin-fs'),
  path: string,
): Promise<number | null> {
  try {
    return (await fs.stat(path)).size;
  } catch {
    return null;
  }
}
