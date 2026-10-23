import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type React from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import type { ContextMenuItem } from './ContextMenu';
import type { ListPrefs } from './listPrefs';
import { isDemoMode } from './demo';
import { intlLocale } from './languages';
import { monthName, relativeDayName, toLocalIso } from './intlFormat';
import { deriveDisplayTitle, editedAtOf, entryDayOf } from './notesViewUtils';
import { CaretDown } from './icons';
import { OTHER_KEY, PINNED_KEY, SYMBOL_KEY, buildGroups, groupBasis, type ListGroup } from './listGroups';

/**
 * The group headers of a notes list: the hook every pane calls, the header
 * row, and the fold state behind it. A pane hands its sorted notes in and
 * renders the entries it gets back, so no pane holds a copy of the rules.
 * Spec: ops/docs/archive/list-groups.md
 */

// Device-local, like the layout. The demo gets its own key, because `?demo=1`
// runs on the same origin as a real install.
function foldKey(): string {
  return isDemoMode() ? 'privacynotes.demo.listGroupsFolded' : 'privacynotes.listGroupsFolded';
}

function readFolds(): Record<string, string[]> {
  try {
    const raw = JSON.parse(localStorage.getItem(foldKey()) ?? '{}') as unknown;
    return raw && typeof raw === 'object' ? (raw as Record<string, string[]>) : {};
  } catch {
    return {};
  }
}

/** The collapsed groups of one list scope (a view), kept on this device. */
function useGroupFold(scope: string) {
  const [all, setAll] = useState(readFolds);
  const folded = new Set(Array.isArray(all[scope]) ? all[scope] : []);
  /** Takes the next set from the latest one, so two clicks in one frame both count. */
  const update = useCallback(
    (fn: (prev: Set<string>) => Set<string>) => {
      setAll((prev) => {
        const next = fn(new Set(Array.isArray(prev[scope]) ? prev[scope] : []));
        const out = { ...prev, [scope]: [...next] };
        if (next.size === 0) delete out[scope];
        try {
          localStorage.setItem(foldKey(), JSON.stringify(out));
        } catch {
          // Storage refused (private mode, quota): the fold lasts for this session.
        }
        return out;
      });
    },
    [scope],
  );
  return { folded, update };
}

function capitalize(s: string, loc: string): string {
  const [first = '', ...rest] = [...s];
  return first.toLocaleUpperCase(loc) + rest.join('');
}

/** The words on a header. Month, year, today and yesterday come from Intl in
 *  the app language, so no catalog carries them. */
function groupLabel(key: string, t: (k: string) => string): string {
  const loc = intlLocale();
  if (key === PINNED_KEY) return t('notes:headerLabel.pinned');
  if (key === 'today' || key === 'yesterday') return capitalize(relativeDayName(key === 'today' ? 0 : -1), loc);
  if (key === 'prev7') return t('notes:listGroups.previous7Days');
  if (key === 'prev30') return t('notes:listGroups.previous30Days');
  if (key.startsWith('m:')) {
    const [y, m] = key.slice(2).split('-').map(Number);
    return capitalize(monthName(y!, m! - 1), loc);
  }
  if (key.startsWith('y:')) return key.slice(2);
  if (key === OTHER_KEY) return t('notes:listGroups.other');
  if (key === SYMBOL_KEY) return '#';
  return key.startsWith('l:') ? key.slice(2) : key;
}

const ListGroupHeader = memo(function ListGroupHeader({
  label,
  count,
  collapsed,
  foldable,
  grid,
  onToggle,
  onContextMenu,
}: {
  label: string;
  count: number;
  collapsed: boolean;
  /** False in selection mode, where every item stays on screen. */
  foldable: boolean;
  grid: boolean;
  onToggle: (e: React.MouseEvent) => void;
  onContextMenu: (e: React.MouseEvent) => void;
}) {
  return (
    // No data-item-id: the list keys and the tab middle-click skip a header.
    <li
      // The grid pads its scroll box by 16 px and a sticky item stops at that
      // padding, so in the grid the header reaches up through it (-top-4 with
      // pt-4): tiles never show above it. -mt-3 takes back the grid's gap-3
      // and no more, so the header's box never covers the tile above it.
      className={`sticky z-10 bg-surface-1 ${grid ? 'col-span-full -top-4 -mt-3 pt-4' : 'top-0 border-b border-divider/50'}`}
      onContextMenu={foldable ? onContextMenu : undefined}
    >
      <button
        type="button"
        onClick={foldable ? onToggle : undefined}
        aria-expanded={foldable ? !collapsed : undefined}
        aria-disabled={foldable ? undefined : true}
        className={`w-full flex items-center gap-1.5 text-start text-xs font-semibold text-pn-muted select-none ${
          grid ? 'py-1.5' : 'px-4 py-1.5'
        } ${foldable ? 'cursor-pointer hover:text-pn' : 'cursor-default'}`}
      >
        <CaretDown
          size={12}
          aria-hidden="true"
          className={`shrink-0 transition-transform ${foldable ? '' : 'opacity-40'} ${collapsed ? '-rotate-90 rtl:rotate-90' : ''}`}
        />
        <span className="min-w-0 truncate" dir="auto">{label}</span>
        <span className="ms-auto shrink-0 font-normal tabular-nums">{count}</span>
      </button>
    </li>
  );
});

/** One line of a grouped list: a header, or an item under it. */
export type ListEntry = { kind: 'header'; group: ListGroup; collapsed: boolean } | { kind: 'note'; note: LocalNote };

/** The collator `compareNotes` sorts titles with, so a letter group never cuts a run in two. */
const titleCollator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

/** Today's local date, renewed at local midnight and when the window comes
 *  back (a sleeping machine fires no timer on time), so a list left open
 *  overnight moves its "Today" items to "Yesterday". */
export function useToday(): string {
  const [today, setToday] = useState(() => toLocalIso(new Date()));
  useEffect(() => {
    const check = () => setToday(toLocalIso(new Date()));
    const now = new Date();
    const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    const timer = window.setTimeout(check, midnight.getTime() - now.getTime() + 1000);
    window.addEventListener('focus', check);
    document.addEventListener('visibilitychange', check);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener('focus', check);
      document.removeEventListener('visibilitychange', check);
    };
  }, [today]);
  return today;
}

function dayFromIso(iso: string): Date {
  const [y, m, d] = iso.split('-').map(Number);
  return new Date(y!, m! - 1, d!);
}

/**
 * The grouped form of a sorted list, or null entries when it is not grouped:
 * the switch is off, the sort has no groups, or a search is on (its order is
 * by match). Selection mode ignores the fold, so "Select all", a Shift range
 * and a bulk action never reach an item that is not on screen.
 */
export function useListGroups({
  notes,
  listPrefs,
  search,
  scope,
  entryDays,
  selectionMode,
  selectedId,
  isNoteLocked,
  onContextMenu,
}: {
  /** The list as sorted, by `compareNotes`. */
  notes: LocalNote[];
  listPrefs: ListPrefs;
  search: string;
  /** The fold scope, one per view. */
  scope: string;
  /** Journals: the created sort reads the day each entry is for. */
  entryDays: boolean;
  selectionMode: boolean;
  selectedId: string | null;
  isNoteLocked: (n: LocalNote) => boolean;
  onContextMenu: (e: React.MouseEvent, items: ContextMenuItem[]) => void;
}) {
  const { t } = useTranslation('notes');
  const today = useToday();
  const basis = listPrefs.showGroups && !search.trim() ? groupBasis(listPrefs.sortField) : null;
  const gatedRef = useRef(isNoteLocked);
  gatedRef.current = isNoteLocked;
  const groups = useMemo(() => {
    if (!basis) return null;
    const created = listPrefs.sortField === 'created';
    return buildGroups(notes, {
      basis,
      now: dayFromIso(today),
      dateOf: (n) =>
        created
          ? entryDays && n.type === 'journal' ? dayFromIso(entryDayOf(n)) : new Date(n.createdAt)
          : new Date(editedAtOf(n)),
      titleOf: (n) => deriveDisplayTitle(n, gatedRef.current(n)),
      isPinned: (n) => n.starred === 1,
      hidesTitle: (n) => gatedRef.current(n) && !(n.title ?? '').trim(),
      collator: titleCollator,
    });
  }, [basis, notes, listPrefs.sortField, entryDays, today]);

  const fold = useGroupFold(scope);
  const foldedKey = [...fold.folded].join('\n');
  const entries = useMemo((): ListEntry[] | null => {
    if (!groups) return null;
    const out: ListEntry[] = [];
    for (const group of groups) {
      const collapsed = !selectionMode && fold.folded.has(group.key);
      out.push({ kind: 'header', group, collapsed });
      if (!collapsed) {
        for (let i = group.start; i < group.start + group.count; i++) out.push({ kind: 'note', note: notes[i]! });
      }
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups, foldedKey, selectionMode, notes]);

  // Opening an item that sits in a collapsed group expands the group, so the
  // open row is always on screen. Keyed on the selection and on the groups
  // coming back (a note opened from a search): collapsing the group of the
  // open item afterwards is the person's choice and stays.
  const foldRef = useRef({ groups, fold, notes });
  foldRef.current = { groups, fold, notes };
  useEffect(() => {
    const { groups: gs, fold: f, notes: all } = foldRef.current;
    if (!selectedId || !gs) return;
    const index = all.findIndex((n) => n.id === selectedId);
    const group = gs.find((g) => index >= g.start && index < g.start + g.count);
    if (group && f.folded.has(group.key)) {
      f.update((prev) => {
        const next = new Set(prev);
        next.delete(group.key);
        return next;
      });
    }
  }, [selectedId, basis]);

  const header = (entry: Extract<ListEntry, { kind: 'header' }>, grid: boolean) => {
    const { group, collapsed } = entry;
    const keys = groups ? groups.map((g) => g.key) : [];
    return (
      <ListGroupHeader
        key={`h:${group.key}:${group.start}`}
        label={groupLabel(group.key, t)}
        count={group.count}
        collapsed={collapsed}
        foldable={!selectionMode}
        grid={grid}
        onToggle={(e) =>
          fold.update((prev) => {
            // Alt-click works as on a macOS disclosure triangle: every group
            // takes the state the clicked one moves to.
            if (e.altKey) return prev.has(group.key) ? new Set() : new Set(keys);
            const next = new Set(prev);
            if (next.has(group.key)) next.delete(group.key);
            else next.add(group.key);
            return next;
          })
        }
        onContextMenu={(e) =>
          onContextMenu(e, [
            { label: t('listGroups.collapseAll'), onSelect: () => fold.update(() => new Set(keys)) },
            { label: t('listGroups.expandAll'), onSelect: () => fold.update(() => new Set()) },
          ])
        }
      />
    );
  };

  return { entries, header };
}
