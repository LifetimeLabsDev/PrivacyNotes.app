import { useMemo, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { createPortal } from 'react-dom';
import { BIP39_WORDS } from '@notes/shared';
import { ArrowsClockwise, Check, Copy, MinusCircle, PlusCircle, RocketLaunch, X } from './icons';
import { HoverLabel } from './HoverLabel';
import { useEscapeToClose } from './useEscapeToClose';
import { useCopyToClipboard } from './clipboard';
import { loadLocalSettings, saveLocalSettings, type UserSettings } from './userSettings';
import { proUnlocked } from './demo';
import { PasswordText } from './PasswordText';
import { isImeComposing } from './imeComposing';
import {
  EXACT_COUNT_MAX,
  PASSPHRASE_WORDS,
  PASSWORD_LENGTH,
  SEPARATORS,
  generatePassphrase,
  generatePassword,
  passphraseBits,
  passwordBits,
  strengthOf,
  type PassphraseOptions,
  type PasswordOptions,
  type Strength,
} from './passwordGen';

/* ────────────────────────────────────────────────────────────────
 * The password generator: one modal, two modes.
 *
 * The password mode builds from letters, exact counts of digits and
 * symbols; the passphrase mode draws words from the BIP-39 list the
 * recovery phrase already ships with. Both paint the preview through
 * PasswordText and show the bits the settings are worth.
 *
 * The passphrase mode is Pro. The toggle stays visible to a free account
 * with the rocket on it, and a tap opens the upgrade modal; the demo
 * unlocks it through `proUnlocked` like every other client-side gate.
 * Spec: ops/docs/pro-features.md (passphrase generator)
 * ──────────────────────────────────────────────────────────────── */

type PwGen = UserSettings['pwGen'];

const LENGTH_PRESETS = [12, 16, 20, 32, 64];
const WORD_PRESETS = [4, 8, 12, 16, 20];

function passwordOptions(g: PwGen): PasswordOptions {
  return {
    length: g.length,
    lowercase: g.lowercase,
    uppercase: g.uppercase,
    digits: g.numbers ? g.exactNumbers : 0,
    symbols: g.symbols ? g.exactSymbols : 0,
  };
}

function passphraseOptions(g: PwGen): PassphraseOptions {
  return { words: g.words, separator: g.separator, capitalize: g.capitalize, number: g.addNumber, symbol: g.addSymbol };
}

function generate(g: PwGen): string {
  return g.mode === 'passphrase'
    ? generatePassphrase(passphraseOptions(g), BIP39_WORDS)
    : generatePassword(passwordOptions(g));
}

const PILL_ON = 'border-accent bg-accent/10 text-accent font-medium';
const PILL_OFF = 'border-divider text-neutral-600 dark:text-neutral-400 hover:bg-neutral-100 dark:hover:bg-surface-1';

/** A segment of a pill row: one press selects it. */
function Pill({ active, onClick, children, label }: { active: boolean; onClick: () => void; children: ReactNode; label?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      aria-label={label}
      className={`flex-1 min-w-0 inline-flex items-center justify-center gap-1.5 text-xs py-1.5 px-2 rounded-md border transition ${active ? PILL_ON : PILL_OFF}`}
    >
      {children}
    </button>
  );
}

/** A small round chip under a slider that jumps it to one value. */
function Preset({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`text-[11px] px-2 py-0.5 rounded-full border tabular-nums transition ${active ? PILL_ON : PILL_OFF}`}
    >
      {children}
    </button>
  );
}

const ICON_BTN = 'rounded p-1 text-neutral-400 hover:text-accent disabled:opacity-30 disabled:hover:text-neutral-400 transition';
const LABEL = 'text-xs text-neutral-500 dark:text-neutral-400';

/**
 * A slider with a typed twin. The field keeps its own text while it is
 * being edited, so a value that passes through an out-of-range number on
 * the way to a valid one (typing 12 starts at 1) is not thrown out on the
 * first keystroke; the commit happens for every in-range value as it is
 * typed, and the blur snaps whatever is left to the nearest bound.
 */
function CountSlider({ label, value, min, max, onChange }: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (v: number) => void;
}) {
  const [draft, setDraft] = useState<string | null>(null);
  const clamp = (v: number) => Math.min(max, Math.max(min, v));
  const commitDraft = () => {
    if (draft === null) return;
    const n = Number.parseInt(draft, 10);
    onChange(Number.isFinite(n) ? clamp(n) : value);
    setDraft(null);
  };
  return (
    <div className="flex items-center gap-2">
      <label className={`${LABEL} w-14 shrink-0`}>{label}</label>
      <input
        type="range"
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        aria-label={label}
        className="flex-1 min-w-0 accent-accent"
      />
      {/* A text field with a numeric keyboard, the same as the PIN and card
          fields: a number input draws the platform's spin buttons, which
          look foreign in the app's field style, and the presets and the
          slider already do that job. */}
      <input
        type="text"
        inputMode="numeric"
        pattern="[0-9]*"
        value={draft ?? value}
        onChange={(e) => {
          setDraft(e.target.value);
          const n = Number.parseInt(e.target.value, 10);
          if (n >= min && n <= max) onChange(n);
        }}
        onBlur={commitDraft}
        onKeyDown={(e) => { if (e.key === 'Enter' && !isImeComposing(e)) commitDraft(); }}
        aria-label={label}
        className="w-14 shrink-0 text-xs text-center tabular-nums px-1.5 py-1 rounded border border-divider bg-surface-0"
      />
    </div>
  );
}

/** Minus, the count, plus. The buttons stop at the bounds. */
function Stepper({ value, max, onChange, decreaseLabel, increaseLabel }: {
  value: number;
  max: number;
  onChange: (v: number) => void;
  decreaseLabel: string;
  increaseLabel: string;
}) {
  return (
    <div className="flex items-center justify-between rounded-md border border-divider px-1.5 py-1">
      <button type="button" onClick={() => onChange(value - 1)} disabled={value <= 0} aria-label={decreaseLabel} className={ICON_BTN}>
        <MinusCircle size={16} />
      </button>
      <span className="text-sm tabular-nums" aria-live="polite">{value}</span>
      <button type="button" onClick={() => onChange(value + 1)} disabled={value >= max} aria-label={increaseLabel} className={ICON_BTN}>
        <PlusCircle size={16} />
      </button>
    </div>
  );
}

const TIER_SEGMENTS: Record<Strength, number> = { weak: 1, fair: 2, strong: 3, veryStrong: 4 };
const TIER_FILL: Record<Strength, string> = {
  weak: 'bg-red-500',
  fair: 'bg-amber-500',
  strong: 'bg-emerald-500',
  veryStrong: 'bg-emerald-600 dark:bg-emerald-500',
};
const TIER_TEXT: Record<Strength, string> = {
  weak: 'text-red-600 dark:text-red-400',
  fair: 'text-amber-600 dark:text-amber-400',
  strong: 'text-emerald-600 dark:text-emerald-400',
  veryStrong: 'text-emerald-600 dark:text-emerald-400',
};

function StrengthMeter({ bits }: { bits: number }) {
  const { t } = useTranslation('auth');
  const tier = strengthOf(bits);
  const names: Record<Strength, string> = {
    weak: t('loginForm.strengthWeak'),
    fair: t('loginForm.strengthFair'),
    strong: t('loginForm.strengthStrong'),
    veryStrong: t('loginForm.strengthVeryStrong'),
  };
  return (
    <div className="mt-2 flex items-center gap-2.5">
      <div className="flex-1 flex gap-1" aria-hidden="true">
        {[1, 2, 3, 4].map((n) => (
          <span key={n} className={`flex-1 h-1 rounded-full ${n <= TIER_SEGMENTS[tier] ? TIER_FILL[tier] : 'bg-neutral-200 dark:bg-neutral-700'}`} />
        ))}
      </div>
      <span className={`text-[11px] tabular-nums whitespace-nowrap ${TIER_TEXT[tier]}`}>
        {names[tier]} · {t('loginForm.strengthBits', { count: Math.round(bits) })}
      </span>
    </div>
  );
}

// Spec: ops/docs/ui-patterns.md (button standards)
const SECONDARY_BTN = 'flex-1 inline-flex items-center justify-center gap-1.5 rounded-md border border-neutral-300 dark:border-neutral-800 hover:bg-neutral-100 dark:hover:bg-neutral-900 px-4 py-2 text-sm transition';
const PRIMARY_BTN = 'w-full inline-flex items-center justify-center gap-1.5 rounded-md bg-accent text-white hover:bg-accent-hover px-4 py-2 text-sm font-medium transition';

function PasswordGenerator({ isPro, onOpenUpgrade, onGenerate }: {
  isPro: boolean | null;
  onOpenUpgrade: () => void;
  onGenerate: (value: string) => void;
}) {
  const { t } = useTranslation('auth');
  const unlocked = proUnlocked(isPro);
  // A stored passphrase mode belongs to a Pro device; a free account opens
  // on the password tab regardless, and stores nothing until it changes something.
  const [gen, setGen] = useState<PwGen>(() => {
    const saved = loadLocalSettings().pwGen;
    return unlocked ? saved : { ...saved, mode: 'password' };
  });
  const [preview, setPreview] = useState(() => generate(gen));
  const { copy, copied } = useCopyToClipboard();

  const update = (patch: Partial<PwGen>) => {
    const next = { ...gen, ...patch };
    setGen(next);
    setPreview(generate(next));
    saveLocalSettings({ ...loadLocalSettings(), pwGen: next });
  };
  const regenerate = () => setPreview(generate(gen));

  const passphrase = gen.mode === 'passphrase';
  const bits = useMemo(
    () => (passphrase ? passphraseBits(passphraseOptions(gen), BIP39_WORDS.length) : passwordBits(passwordOptions(gen))),
    [gen, passphrase],
  );
  const digits = gen.numbers ? gen.exactNumbers : 0;
  const symbols = gen.symbols ? gen.exactSymbols : 0;

  const selectPassphrase = () => {
    if (!unlocked) {
      onOpenUpgrade();
      return;
    }
    update({ mode: 'passphrase' });
  };

  return (
    <div className="p-3 space-y-3">
      <div className="flex gap-1.5">
        <Pill active={!passphrase} onClick={() => update({ mode: 'password' })}>{t('loginForm.modePassword')}</Pill>
        <Pill active={passphrase} onClick={selectPassphrase}>
          {t('loginForm.modePassphrase')}
          {!isPro && <RocketLaunch size={11} weight="fill" className="text-pro" />}
        </Pill>
      </div>

      <div className="bg-surface-0 rounded px-3 py-2">
        <div className="flex items-start gap-2">
          <div dir="ltr" className={`flex-1 min-w-0 font-mono text-base leading-snug select-all ${passphrase ? 'break-words' : 'break-all'}`} /* rtl-ok: a secret is a code, never reordered */>
            <PasswordText value={preview} />
          </div>
          {/* End-aligned: the icon sits at the end of the row inside a
              scroll container, and a centred tip hangs past its edge, which
              gives the modal a horizontal scrollbar. */}
          <HoverLabel label={t('loginForm.regenerate')} position="above-end">
            <button
              type="button"
              onClick={regenerate}
              aria-label={t('loginForm.regenerate')}
              className="shrink-0 -me-1 -mt-0.5 inline-flex items-center justify-center w-8 h-8 rounded-md border border-divider bg-surface-2 text-neutral-500 dark:text-neutral-400 hover:text-accent hover:border-accent transition"
            >
              <ArrowsClockwise size={16} />
            </button>
          </HoverLabel>
        </div>
        <StrengthMeter bits={bits} />
      </div>

      {passphrase ? (
        <>
          <div className="space-y-1.5">
            <CountSlider
              label={t('loginForm.wordsLabel')}
              value={gen.words}
              min={PASSPHRASE_WORDS.min}
              max={PASSPHRASE_WORDS.max}
              onChange={(words) => update({ words })}
            />
            <div className="flex gap-1.5 ps-16">
              {WORD_PRESETS.map((n) => (
                <Preset key={n} active={gen.words === n} onClick={() => update({ words: n })}>{n}</Preset>
              ))}
            </div>
          </div>

          <div>
            <p className={`${LABEL} mb-1`}>{t('loginForm.separatorLabel')}</p>
            <div className="flex gap-1.5">
              {SEPARATORS.map((sep) => (
                <Pill key={sep} active={gen.separator === sep} onClick={() => update({ separator: sep })} label={sep === ' ' ? t('loginForm.separatorSpace') : undefined}>
                  {sep === ' ' ? t('loginForm.separatorSpace') : <span className="font-mono">{sep}</span>}
                </Pill>
              ))}
            </div>
          </div>

          <div>
            <p className={`${LABEL} mb-1`}>{t('loginForm.optionsLabel')}</p>
            <div className="space-y-1">
              {([
                ['capitalize', t('loginForm.capitalizeWord')],
                ['addNumber', t('loginForm.addNumber')],
                ['addSymbol', t('loginForm.addSymbol')],
              ] as const).map(([key, label]) => (
                <label key={key} className="flex items-center gap-1.5 text-xs cursor-pointer">
                  <input type="checkbox" checked={gen[key]} onChange={() => update({ [key]: !gen[key] })} className="rounded accent-accent" />
                  {label}
                </label>
              ))}
            </div>
          </div>
          <p className="text-[11px] text-neutral-400 dark:text-neutral-500 !mt-1.5">{t('loginForm.passphraseHint')}</p>
        </>
      ) : (
        <>
          <div className="space-y-1.5">
            <CountSlider
              label={t('loginForm.lengthLabel')}
              value={gen.length}
              min={PASSWORD_LENGTH.min}
              max={PASSWORD_LENGTH.max}
              onChange={(length) => update({ length })}
            />
            <div className="flex gap-1.5 ps-16">
              {LENGTH_PRESETS.map((n) => (
                <Preset key={n} active={gen.length === n} onClick={() => update({ length: n })}>{n}</Preset>
              ))}
            </div>
          </div>

          <div>
            <p className={`${LABEL} mb-1`}>{t('loginForm.lettersLabel')}</p>
            <div className="flex gap-1.5">
              {/* One letter set always stays on: the fill pool is letters,
                  and a pool with nothing in it has nothing to draw. */}
              <Pill active={gen.lowercase} onClick={() => { if (gen.uppercase) update({ lowercase: !gen.lowercase }); }}>
                <span className="font-mono">a-z</span>
              </Pill>
              <Pill active={gen.uppercase} onClick={() => { if (gen.lowercase) update({ uppercase: !gen.uppercase }); }}>
                <span className="font-mono">A-Z</span>
              </Pill>
            </div>
            <p className="mt-1 text-[11px] text-neutral-400 dark:text-neutral-500">{t('loginForm.lettersHint')}</p>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <p className={`${LABEL} mb-1`}>{t('loginForm.digitsLabel')}</p>
              <Stepper
                value={digits}
                max={EXACT_COUNT_MAX}
                onChange={(n) => update({ numbers: n > 0, exactNumbers: n })}
                decreaseLabel={t('loginForm.decrease')}
                increaseLabel={t('loginForm.increase')}
              />
            </div>
            <div>
              <p className={`${LABEL} mb-1`}>{t('loginForm.symbolsLabel')}</p>
              <Stepper
                value={symbols}
                max={EXACT_COUNT_MAX}
                onChange={(n) => update({ symbols: n > 0, exactSymbols: n })}
                decreaseLabel={t('loginForm.decrease')}
                increaseLabel={t('loginForm.increase')}
              />
            </div>
          </div>
          <p className="text-[11px] text-neutral-400 dark:text-neutral-500 !mt-1.5">{t('loginForm.ambiguousHint')}</p>
        </>
      )}

      {/* Leaving without applying is the header's X, Escape or the backdrop;
          the one filled button is the one that writes the value. */}
      <div className="flex gap-2">
        <button type="button" onClick={regenerate} className={SECONDARY_BTN}>
          <ArrowsClockwise size={14} />
          {t('loginForm.regenerate')}
        </button>
        <button type="button" onClick={() => copy(preview, 'generated')} className={SECONDARY_BTN}>
          {copied ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
          {copied ? t('shell:vaultItem.copied') : t('loginForm.copyGenerated')}
        </button>
      </div>
      <button type="button" onClick={() => onGenerate(preview)} className={`${PRIMARY_BTN} !mt-2`}>
        <Check size={14} />
        {passphrase ? t('loginForm.usePassphrase') : t('loginForm.usePassword')}
      </button>
    </div>
  );
}

/** The generator in a centred dialog with a backdrop; Escape and the backdrop close it. */
export function PasswordGeneratorModal({ isPro, onOpenUpgrade, onGenerate, onClose }: {
  isPro: boolean | null;
  onOpenUpgrade: () => void;
  onGenerate: (value: string) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('auth');
  useEscapeToClose(onClose);
  return createPortal(
    <div className="fixed inset-0 bg-black/30 dark:bg-black/50 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div
        className="bg-surface-2 border border-divider rounded-lg max-w-sm w-full shadow-lg max-h-full overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 pt-4 pb-0">
          <h2 className="text-base font-semibold text-pn">{t('loginForm.generateTitle')}</h2>
          <button onClick={onClose} className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1" aria-label={t('common:actions.close')}>
            <X size={18} />
          </button>
        </div>
        <PasswordGenerator isPro={isPro} onOpenUpgrade={onOpenUpgrade} onGenerate={onGenerate} />
      </div>
    </div>,
    document.body,
  );
}
