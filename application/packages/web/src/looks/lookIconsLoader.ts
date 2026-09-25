/**
 * Loads the look icon catalog once, on first need. Small and eager on
 * purpose: the glyph components import it, so the catalog itself can stay
 * out of every boot path. A failed load (a dropped connection on the web)
 * clears the promise, so the next glyph or the picker tries again; until then
 * every glyph draws its default.
 * Spec: ops/docs/plans/folder-tag-icons.md (section 8)
 */
import { useEffect, useState } from 'react';

type LookIconsModule = typeof import('./lookIcons');

let loaded: LookIconsModule | null = null;
let loading: Promise<LookIconsModule> | null = null;

function loadLookIcons(): Promise<LookIconsModule> {
  if (loaded) return Promise.resolve(loaded);
  loading ??= import('./lookIcons').then(
    (mod) => (loaded = mod),
    (err: unknown) => {
      loading = null;
      throw err;
    },
  );
  return loading;
}

/** The catalog once it is here, else null. `wanted` false never loads it:
 *  a folder without an icon costs nothing. */
export function useLookIcons(wanted = true): LookIconsModule | null {
  const [mod, setMod] = useState<LookIconsModule | null>(loaded);
  useEffect(() => {
    if (mod || !wanted) return;
    let live = true;
    loadLookIcons().then(
      (m) => {
        if (live) setMod(m);
      },
      () => {},
    );
    return () => {
      live = false;
    };
  }, [mod, wanted]);
  return mod;
}
