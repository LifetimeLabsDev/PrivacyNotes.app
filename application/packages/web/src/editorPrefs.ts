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

// Where the format bar sits on a touch screen: at the top of the note, or at
// the bottom, above the keyboard. Per device, since a phone and a tablet can
// want different things. Spec: ops/docs/archive/format-bar.md (section 7)
const BAR_POSITION_KEY = 'privacynotes.editor.barPosition';
export type BarPosition = 'top' | 'bottom';

export function readBarPositionPref(): BarPosition {
  try {
    return localStorage.getItem(BAR_POSITION_KEY) === 'bottom' ? 'bottom' : 'top';
  } catch {
    return 'top';
  }
}

export function writeBarPositionPref(position: BarPosition) {
  try {
    localStorage.setItem(BAR_POSITION_KEY, position);
  } catch {
    /* ignore */
  }
}

// Spec: ops/docs/archive/ui-patterns.md (outline panel) - remember the outline open/closed
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

/**
 * The Kanban board a new insert starts from: the number of columns (3 or 4)
 * and each column's color, taken from the last board inserted or changed on
 * this device. The column names are not remembered: a new board always
 * starts from the default names in the reader's language. Device-local, for
 * the reason the colour picks above are.
 * Spec: ops/issues/0270.md (Spec, remember)
 */
export interface KanbanPref {
  count: 3 | 4;
  colors: string[];
}

const KANBAN_PREF_KEY = 'privacynotes.editor.kanban';

export function readKanbanPref(): KanbanPref | null {
  try {
    const raw = JSON.parse(localStorage.getItem(KANBAN_PREF_KEY) ?? 'null') as unknown;
    if (!raw || typeof raw !== 'object') return null;
    const { count, colors } = raw as { count?: unknown; colors?: unknown };
    if (count !== 3 && count !== 4) return null;
    if (!Array.isArray(colors) || !colors.every((c) => typeof c === 'string')) return null;
    return { count, colors: colors.slice(0, count) };
  } catch {
    return null;
  }
}

export function writeKanbanPref(pref: KanbanPref) {
  try {
    localStorage.setItem(KANBAN_PREF_KEY, JSON.stringify(pref));
  } catch {
    /* ignore */
  }
}

// The Connections panel shares the outline's corner and remembers its
// open/closed choice the same way. Spec: ops/issues/0351.md (Spec)
const CONNECTIONS_PREF_KEY = 'privacynotes.editor.connectionsOpen';

export function readConnectionsPref(): boolean {
  try {
    return localStorage.getItem(CONNECTIONS_PREF_KEY) === '1';
  } catch {
    return false;
  }
}

export function writeConnectionsPref(open: boolean) {
  try {
    localStorage.setItem(CONNECTIONS_PREF_KEY, open ? '1' : '0');
  } catch {
    /* ignore */
  }
}
