import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { SUPPORTED_LOCALES } from './i18n';
import { LANGUAGE_META, Flag, setLanguage, currentLanguageChoice, activeLocale, preferredLocale, sortByNative } from './languages';
import { LOCALE_TO_SLUG } from './localeRoutes';
import { Check, CaretDown, CaretUp, Translate } from './icons';

type Props = {
  /** Open the menu upward (for placements near the bottom of the page). */
  dropUp?: boolean;
  /** Dark surface styling (e.g. the footer). */
  dark?: boolean;
  /** Navigate to the locale's URL slug instead of switching in place (marketing). */
  navigate?: boolean;
  /** Round icon-only trigger, matching the header's hamburger button. */
  iconOnly?: boolean;
  /** Smaller icon-only trigger, matching the sticky header's hamburger. */
  compact?: boolean;
};

/**
 * Compact language switcher: the current flag + name opens a dropdown of flags.
 * No forced redirect; the visitor picks.
 */
export function LanguageMenu({ dropUp = false, dark = false, navigate = false, iconOnly = false, compact = false }: Props) {
  const { t } = useTranslation('settings');
  const [open, setOpen] = useState(false);
  const [choice, setChoice] = useState<string>(() => currentLanguageChoice());
  const ref = useRef<HTMLDivElement>(null);
  const current = activeLocale();

  useEffect(() => {
    if (!open) return;
    function onDown(e: PointerEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onEsc(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false);
    }
    const id = window.setTimeout(() => document.addEventListener('pointerdown', onDown), 0);
    document.addEventListener('keydown', onEsc);
    return () => {
      window.clearTimeout(id);
      document.removeEventListener('pointerdown', onDown);
      document.removeEventListener('keydown', onEsc);
    };
  }, [open]);

  function pick(value: string) {
    setChoice(value);
    setLanguage(value);
    if (navigate) {
      // Always land on a locale slug, never the bare apex: '/' is the smart
      // entry, so a signed-in visitor picking a language would be dropped into
      // their notes instead of staying on the marketing page (issue #203).
      // 'system' resolves through the same table the app itself uses, so the
      // slug and the language that renders there agree.
      const target = value === 'system' ? preferredLocale() : value;
      window.location.assign(LOCALE_TO_SLUG[target] ?? '/en');
      return;
    }
    setOpen(false);
  }

  const options: Array<{ value: string; label: string }> = [
    { value: 'system', label: t('appearance.languageSystem') },
    ...sortByNative(SUPPORTED_LOCALES).map((c) => ({ value: c, label: LANGUAGE_META[c]?.native ?? c })),
  ];

  // Washi variables, not neutral grays: this menu renders only on washi
  // surfaces (marketing headers, overlay, auth view). The `dark` variant
  // is for the footer, whose slab is fixed ink in both modes.
  const buttonClass = dark
    ? 'border-white/15 bg-white/10 text-neutral-200 hover:bg-white/20'
    : 'border-[var(--wl-line)] bg-[var(--wl-card)] text-[var(--wl-ink)] hover:bg-[var(--wl-tint)]';
  const Caret = dropUp ? CaretUp : CaretDown;

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-label={`${t('appearance.language')}: ${LANGUAGE_META[current]?.native ?? current}`}
        aria-haspopup="menu"
        aria-expanded={open}
        className={iconOnly
          ? `inline-flex items-center justify-center rounded-full border-[1.5px] border-[var(--wl-ink)] text-[var(--wl-ink)] hover:bg-[var(--wl-ink)]/10 transition ${compact ? 'h-9 w-9' : 'h-10 w-10'}`
          : `inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-sm font-medium transition ${buttonClass}`}
      >
        {iconOnly ? (
          <Translate size={compact ? 18 : 20} />
        ) : (
          <>
            <Flag code={current} />
            <span>{LANGUAGE_META[current]?.native ?? current}</span>
            <Caret size={12} aria-hidden="true" />
          </>
        )}
      </button>
      {open && (
        <div
          role="menu"
          className={`absolute end-0 z-50 w-48 rounded-xl border border-[var(--wl-line)] bg-[var(--wl-card)] shadow-lg py-1 ${dropUp ? 'bottom-full mb-2' : 'mt-2'}`}
        >
          {options.map((opt) => {
            const active = choice === opt.value;
            return (
              <button
                key={opt.value}
                type="button"
                role="menuitemradio"
                aria-checked={active}
                onClick={() => pick(opt.value)}
                className="flex w-full items-center gap-2.5 px-3 py-1.5 text-sm text-[var(--wl-ink)] hover:bg-[var(--wl-tint)] transition"
              >
                {opt.value === 'system' ? (
                  <span className="flex items-center justify-center rounded-[3px] bg-accent/10 text-accent" style={{ width: 26, height: 19, flexShrink: 0 }}>
                    <Translate size={13} />
                  </span>
                ) : (
                  <Flag code={opt.value} />
                )}
                <span className="flex-1 text-start">{opt.label}</span>
                {active && <Check size={13} className="text-accent" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
