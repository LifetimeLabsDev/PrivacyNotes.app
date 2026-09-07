/**
 * Cancels a file drop that no drop target claimed.
 *
 * A webview's default action for an unclaimed file drop is to navigate to
 * the dropped file, which replaces the running app with that file, or with
 * a blank window. Three surfaces take files on purpose - the editor's image
 * and attachment plugins and the Markdown file pane - and each one calls
 * `preventDefault()` on the events it handles. A drop anywhere else reaches
 * this listener on `window`, last in bubble order, and ends here. Over such
 * a spot the cursor shows the no-drop sign, so nothing looks like a drop
 * that silently failed.
 *
 * Only a drag carrying files is touched. A text drag into a title field or
 * an input is a default action worth keeping.
 *
 * The desktop app relies on this listener: its webview would otherwise route
 * every drag to a native handler that never lets the page see it (GitHub
 * #284), so `dragDropEnabled` is off in tauri.conf.json and the page owns
 * the default action described above.
 * Spec: ops/docs/design-decisions.md (Drag and drop in the desktop app)
 */
function cancelUnclaimedFileDrop(e: DragEvent): void {
  if (e.defaultPrevented) return;
  if (!e.dataTransfer?.types.includes('Files')) return;
  if (e.type === 'dragover') e.dataTransfer.dropEffect = 'none';
  e.preventDefault();
}

/** Called once from main.tsx, before React mounts. */
export function installStrayDropGuard(target: Window = window): void {
  target.addEventListener('dragover', cancelUnclaimedFileDrop);
  target.addEventListener('drop', cancelUnclaimedFileDrop);
}
