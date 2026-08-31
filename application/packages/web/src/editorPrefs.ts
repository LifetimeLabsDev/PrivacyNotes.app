const TOOLBAR_PREF_KEY = 'privacynotes.editor.toolbarVisible';

export function readToolbarPref(): boolean {
  try {
    const v = localStorage.getItem(TOOLBAR_PREF_KEY);
    if (v === null) return true; // default: visible
    return v === '1';
  } catch {
    return true;
  }
}

export function writeToolbarPref(visible: boolean) {
  try {
    localStorage.setItem(TOOLBAR_PREF_KEY, visible ? '1' : '0');
  } catch {
    /* ignore */
  }
}

// Spec: ops/docs/ui-patterns.md (outline panel) - remember the outline open/closed
// choice across notes and sessions, like the toolbar visibility pref.
const OUTLINE_PREF_KEY = 'privacynotes.editor.outlineOpen';

export function readOutlinePref(): boolean {
  try {
    return localStorage.getItem(OUTLINE_PREF_KEY) === '1';
  } catch {
    return false;
  }
}

export function writeOutlinePref(open: boolean) {
  try {
    localStorage.setItem(OUTLINE_PREF_KEY, open ? '1' : '0');
  } catch {
    /* ignore */
  }
}

/**
 * The swatch last picked from each of the editor's two colour popovers, so
 * the toolbar button can apply it again in one press. GitHub #248.
 *
 * Stored as the swatch NAME, never its value. The highlight palette's
 * default entry carries no colour at all - it serializes as `==text==` -
 * so a stored value cannot express it, and a name still resolves if the
 * palette values are ever re-tuned.
 *
 * Device-local, like the two prefs above. The settings blob takes the
 * remote copy for every scalar field, so a value that changes on each pick
 * would let two devices in one sitting overwrite each other's colour for
 * no gain: a fresh device trains itself on the first swatch its owner
 * picks. Spec: ops/docs/design-decisions.md (remembered editor colours)
 */
export type ColorPrefKind = 'text' | 'highlight';

const COLOR_PREF_KEYS: Record<ColorPrefKind, string> = {
  text: 'privacynotes.editor.lastTextColor',
  highlight: 'privacynotes.editor.lastHighlightColor',
};

export function readColorPref(kind: ColorPrefKind): string | null {
  try {
    return localStorage.getItem(COLOR_PREF_KEYS[kind]);
  } catch {
    return null;
  }
}

export function writeColorPref(kind: ColorPrefKind, name: string) {
  try {
    localStorage.setItem(COLOR_PREF_KEYS[kind], name);
  } catch {
    /* ignore */
  }
}
