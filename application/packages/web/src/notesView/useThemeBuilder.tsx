import { lazy, Suspense, useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { customIdOf, getStoredColorTheme, reconcileCustomSlots } from '../theme';
import { canSaveCustomTheme, saveCustomTheme, type CustomThemes } from '../customThemes';
import { hasSettingsPulled, type UserSettings } from '../userSettings';
import { isDemoMode } from '../demo';

const ThemeBuilder = lazy(() => import('../ThemeBuilder').then((m) => ({ default: m.ThemeBuilder })));

/** What the builder opens on: a saved theme (id and code), a code to start
 *  from (a copy, a pasted code or a built-in palette's code), or nothing, for
 *  an exact copy of the theme on screen. */
export type ThemeBuilderTarget = {
  id?: string;
  code?: string;
  name?: string;
};

/**
 * The custom-theme wiring NotesView owns: the floating theme builder, and the
 * two light and dark slots kept in step with the synced theme list.
 *
 * The slots are device-local and the list is not, so after the list loads or
 * syncs a slot can point at a theme that another device edited (it repaints
 * with the new colors) or deleted (it goes back to Default). Before the
 * first pull the list is not the account's yet, so nothing is dropped.
 * Spec: ops/docs/color-themes.md (section 6)
 */
export function useThemeBuilder({
  customThemes,
  mutateSettings,
  canSave,
  onOpen,
  onOpenUpgrade,
}: {
  customThemes: CustomThemes;
  mutateSettings: (updater: (prev: UserSettings) => UserSettings) => void;
  /** Pro, or the demo. */
  canSave: boolean;
  /** Closes what the builder replaces: Settings and the Appearance popover. */
  onOpen: () => void;
  onOpenUpgrade: () => void;
}): { openThemeBuilder: (target: ThemeBuilderTarget) => void; resumeThemeBuilder: () => void; themeBuilder: ReactNode } {
  const [target, setTarget] = useState<ThemeBuilderTarget | null>(null);
  // Save with Pro closes the builder for the upgrade. Its draft waits here and
  // opens again when the upgrade closes, bought or not, so no work is lost.
  const parked = useRef<ThemeBuilderTarget | null>(null);

  const openThemeBuilder = useCallback(
    (next: ThemeBuilderTarget) => {
      onOpen();
      setTarget(next);
    },
    [onOpen],
  );

  const resumeThemeBuilder = useCallback(() => {
    const next = parked.current;
    parked.current = null;
    if (next) openThemeBuilder(next);
  }, [openThemeBuilder]);

  useEffect(() => {
    const inSlots = (['light', 'dark'] as const).some((m) => customIdOf(getStoredColorTheme(m)) !== null);
    if (!inSlots || !(isDemoMode() || hasSettingsPulled())) return;
    let live = true;
    void import('../customThemeUI').then(({ teamThemeEntries, customThemeEntries }) => {
      if (!live) return;
      const listed = [...teamThemeEntries(), ...customThemeEntries(customThemes)];
      const byId = new Map(listed.map((e) => [e.id, e.snapshot]));
      reconcileCustomSlots((id, mode) => {
        const snap = byId.get(id);
        return snap && snap.mode === mode ? snap : null;
      }, !isDemoMode());
    });
    return () => { live = false; };
  }, [customThemes]);

  const themeBuilder = target ? (
    <Suspense fallback={null}>
      <ThemeBuilder
        key={target.id ?? target.code ?? 'new'}
        target={target}
        canSave={canSave}
        hasRoom={(id) => canSaveCustomTheme(customThemes, id)}
        onSave={(id, code) => {
          // The builder stays open after a save; Close or Cancel ends it.
          mutateSettings((prev) => ({ ...prev, customThemes: saveCustomTheme(prev.customThemes, id, code) }));
        }}
        onClose={() => setTarget(null)}
        onOpenUpgrade={(code) => {
          parked.current = { id: target.id, code };
          setTarget(null);
          onOpenUpgrade();
        }}
      />
    </Suspense>
  ) : null;

  return { openThemeBuilder, resumeThemeBuilder, themeBuilder };
}
