import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { createPortal } from 'react-dom';
import { ArrowsClockwise, Check, Copy, Eye, EyeSlash, FloppyDisk, Info, Password, X } from './icons';
import { hasPin } from './pin';
import { PinInfoModal } from './PinInfoModal';
import { HoverLabel } from './HoverLabel';
import { useEscapeToClose } from './useEscapeToClose';
import { loadLocalSettings, saveLocalSettings } from './userSettings';
import { useCopyToClipboard } from './clipboard';
import { parseTotpInput, generateTotpCode, totpSecondsRemaining } from '@notes/shared';
import { proUnlocked } from './demo';

/* ────────────────────────────────────────────────────────────────
 * LoginData - the JSON blob stored in the note body for login-type
 * notes. Fields: url (the website), username, password, freeform notes,
 * totp (the raw authenticator key/URI as pasted - never canonicalized).
 * The note's `title` field serves as the display name (e.g. "GitHub")
 * and is auto-derived from the URL domain when empty.
 * ──────────────────────────────────────────────────────────────── */
export interface LoginData {
  url: string;
  username: string;
  password: string;
  totp: string;
  notes: string;
}

export function parseLoginBody(body: string): LoginData {
  try {
    const parsed = JSON.parse(body);
    return {
      url: typeof parsed.url === 'string' ? parsed.url : '',
      username: typeof parsed.username === 'string' ? parsed.username : '',
      password: typeof parsed.password === 'string' ? parsed.password : '',
      totp: typeof parsed.totp === 'string' ? parsed.totp : '',
      notes: typeof parsed.notes === 'string' ? parsed.notes : '',
    };
  } catch {
    return { url: '', username: '', password: '', totp: '', notes: '' };
  }
}

export function serializeLoginBody(data: LoginData): string {
  return JSON.stringify({
    url: data.url,
    username: data.username,
    password: data.password,
    totp: data.totp,
    notes: data.notes,
  });
}

/** Extract a display-friendly domain from a URL string. */
export function domainFromUrl(raw: string): string {
  let s = raw.trim();
  if (!s) return '';
  // Add protocol if missing so URL() can parse it.
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  try {
    return new URL(s).hostname.replace(/^www\./, '');
  } catch {
    // Fallback: strip protocol + path by hand.
    return raw.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/^www\./, '');
  }
}

/* ────────────────────────────────────────────────────────────────
 * Password generator
 * Ambiguous characters (0, O, o, l, 1, I) excluded from all sets.
 * Symbols limited to universally accepted set (no brackets, pipes,
 * semicolons, angle brackets - those trigger WAF / regex rejections).
 * ──────────────────────────────────────────────────────────────── */
const CHAR_SETS = {
  lowercase: 'abcdefghjkmnpqrstuvwxyz',       // no l, o
  uppercase: 'ABCDEFGHJKLMNPQRSTUVWXYZ',       // no I, O
  numbers: '23456789',                          // no 0, 1
  symbols: '!@#$%^&*-_+=?~',                   // safe subset
};

function generatePassword(
  length: number,
  sets: { lowercase: boolean; uppercase: boolean; numbers: boolean; symbols: boolean },
  exactNumbers: number,
  exactSymbols: number,
): string {
  const rng = (charset: string) => {
    const a = new Uint32Array(1);
    crypto.getRandomValues(a);
    return charset.charAt(a[0]! % charset.length);
  };

  // Exact-count characters
  const exact: string[] = [];
  if (sets.numbers) for (let i = 0; i < exactNumbers; i++) exact.push(rng(CHAR_SETS.numbers));
  if (sets.symbols) for (let i = 0; i < exactSymbols; i++) exact.push(rng(CHAR_SETS.symbols));

  // Fill pool: only letter sets (no numbers/symbols - those are exact-count)
  let fillPool = '';
  if (sets.lowercase) fillPool += CHAR_SETS.lowercase;
  if (sets.uppercase) fillPool += CHAR_SETS.uppercase;
  if (!fillPool) fillPool = CHAR_SETS.lowercase; // fallback

  const remaining = Math.max(0, length - exact.length);
  const arr = new Uint32Array(remaining);
  crypto.getRandomValues(arr);
  const fill = Array.from(arr, (v) => fillPool.charAt(v % fillPool.length));

  // Combine and shuffle with Fisher-Yates
  const result = [...exact, ...fill];
  const shuffleArr = new Uint32Array(result.length);
  crypto.getRandomValues(shuffleArr);
  for (let i = result.length - 1; i > 0; i--) {
    const j = shuffleArr[i]! % (i + 1);
    [result[i], result[j]] = [result[j]!, result[i]!];
  }
  return result.join('');
}

/* ────────────────────────────────────────────────────────────────
 * PasswordGenerator popover
 * ──────────────────────────────────────────────────────────────── */
function PasswordGenerator({ onGenerate }: { onGenerate: (pw: string) => void }) {
  const { t } = useTranslation('auth');
  const saved = useMemo(() => loadLocalSettings().pwGen, []);
  const [length, setLength] = useState(saved.length);
  const [exactNumbers, setExactNumbers] = useState(saved.exactNumbers);
  const [exactSymbols, setExactSymbols] = useState(saved.exactSymbols);
  const [sets, setSets] = useState({
    lowercase: true, // always required
    uppercase: saved.uppercase,
    numbers: saved.numbers,
    symbols: saved.symbols,
  });
  const [preview, setPreview] = useState('');

  // Persist settings to UserSettings (syncs across devices)
  const persist = (
    l: number,
    s: typeof sets,
    en: number,
    es: number,
  ) => {
    const cur = loadLocalSettings();
    saveLocalSettings({
      ...cur,
      pwGen: { length: l, ...s, exactNumbers: en, exactSymbols: es },
    });
  };

  // Generate with explicit params - never reads stale state
  const gen = (
    l: number,
    s: typeof sets,
    en: number,
    es: number,
  ) => {
    setPreview(generatePassword(l, s, en, es));
    persist(l, s, en, es);
  };

  // Generate on mount
  useEffect(() => {
    setPreview(generatePassword(saved.length, saved, saved.exactNumbers, saved.exactSymbols));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const updateLength = (v: number) => { setLength(v); gen(v, sets, exactNumbers, exactSymbols); };
  const updateExactNumbers = (v: number) => { const n = Math.max(0, Math.min(9, v)); setExactNumbers(n); gen(length, sets, n, exactSymbols); };
  const updateExactSymbols = (v: number) => { const n = Math.max(0, Math.min(9, v)); setExactSymbols(n); gen(length, sets, exactNumbers, n); };
  const toggle = (key: keyof typeof sets) => {
    if (key === 'lowercase') return; // lowercase is always required
    setSets((prev) => {
      const next = { ...prev, [key]: !prev[key] };
      if (!next.uppercase && !next.numbers && !next.symbols) return prev;
      gen(length, next, exactNumbers, exactSymbols);
      return next;
    });
  };

  return (
    <div className="p-3 space-y-3">
      <div className="font-mono text-sm bg-surface-0 rounded px-3 py-2 break-all select-all leading-snug">
        {preview}
      </div>
      <div className="flex items-center gap-2">
        <label className="text-xs text-neutral-500 shrink-0">{t('loginForm.lengthLabel')}</label>
        <input
          type="range"
          min={8}
          max={64}
          value={length}
          onChange={(e) => updateLength(Number(e.target.value))}
          className="flex-1 min-w-0 accent-accent"
        />
        <span className="text-xs tabular-nums w-6 text-end shrink-0">{length}</span>
      </div>
      <div className="grid grid-cols-2 gap-x-3 gap-y-1">
        <HoverLabel label={t('loginForm.lowercaseAlwaysIncluded')} position="above-start">
          <label className="flex items-center gap-1.5 text-xs cursor-default opacity-60">
            <input
              type="checkbox"
              checked
              disabled
              className="rounded accent-accent"
            />
            {t('loginForm.charLowercase')}
          </label>
        </HoverLabel>
        {(['uppercase', 'numbers', 'symbols'] as const).map((key) => (
          <label key={key} className="flex items-center gap-1.5 text-xs cursor-pointer">
            <input
              type="checkbox"
              checked={sets[key]}
              onChange={() => toggle(key)}
              className="rounded accent-accent"
            />
            {t(`loginForm.char${key.charAt(0).toUpperCase() + key.slice(1)}`)}
          </label>
        ))}
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-[11px] text-neutral-500 dark:text-neutral-400 block mb-1">{t('loginForm.charNumbers')}</label>
          <input
            type="number"
            min={0}
            max={9}
            value={exactNumbers}
            onChange={(e) => updateExactNumbers(Number(e.target.value) || 0)}
            disabled={!sets.numbers}
            className="w-full text-xs px-2 py-1.5 rounded border border-divider bg-surface-0 disabled:opacity-40"
          />
        </div>
        <div>
          <label className="text-[11px] text-neutral-500 dark:text-neutral-400 block mb-1">{t('loginForm.charSymbols')}</label>
          <input
            type="number"
            min={0}
            max={9}
            value={exactSymbols}
            onChange={(e) => updateExactSymbols(Number(e.target.value) || 0)}
            disabled={!sets.symbols}
            className="w-full text-xs px-2 py-1.5 rounded border border-divider bg-surface-0 disabled:opacity-40"
          />
        </div>
      </div>
      <p className="text-[11px] text-neutral-400 dark:text-neutral-500 !mt-1">
        {t('loginForm.ambiguousHint')}
      </p>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => gen(length, sets, exactNumbers, exactSymbols)}
          className="flex-1 inline-flex items-center justify-center gap-1 text-xs py-1.5 rounded border border-divider hover:bg-neutral-100 dark:hover:bg-surface-1 transition"
        >
          <ArrowsClockwise size={13} />
          {t('loginForm.regenerate')}
        </button>
        <button
          type="button"
          onClick={() => onGenerate(preview)}
          className="flex-1 inline-flex items-center justify-center gap-1 text-xs py-1.5 rounded bg-accent text-white hover:bg-accent-hover transition font-medium"
        >
          <Check size={13} />
          {t('loginForm.usePassword')}
        </button>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * PasswordGeneratorModal - centered popover with backdrop
 * ──────────────────────────────────────────────────────────────── */
function PasswordGeneratorModal({
  onGenerate,
  onClose,
}: {
  onGenerate: (pw: string) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('auth');
  useEscapeToClose(onClose);
  return createPortal(
    <div className="fixed inset-0 bg-black/30 dark:bg-black/50 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div
        className="bg-surface-2 border border-divider rounded-lg max-w-sm w-full shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 pt-4 pb-0">
          <h2 className="text-base font-semibold text-pn">{t('loginForm.generateTitle')}</h2>
          <button onClick={onClose} className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1" aria-label={t('common:actions.close')}>
            <X size={18} />
          </button>
        </div>
        <PasswordGenerator onGenerate={onGenerate} />
        <div className="px-3 pb-3">
          <button
            type="button"
            onClick={onClose}
            className="w-full rounded border border-divider text-neutral-600 dark:text-neutral-400 hover:bg-neutral-100 dark:hover:bg-neutral-800 px-4 py-1.5 text-xs transition"
          >
            {t('common:actions.close')}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}

/* ────────────────────────────────────────────────────────────────
 * Copy button (reused for username / password / URL)
 * ──────────────────────────────────────────────────────────────── */
function CopyBtn({
  onClick,
  active,
  title,
}: {
  onClick: () => void;
  active: boolean;
  title: string;
}) {
  const cls =
    'shrink-0 rounded-md p-2 text-neutral-400 hover:text-accent hover:bg-neutral-100 dark:hover:bg-surface-0 transition';
  return (
    <HoverLabel label={title} position="start">
      <button type="button" onClick={onClick} aria-label={title} className={cls}>
        {active ? (
          <Check size={16} className="text-emerald-500" />
        ) : (
          <Copy size={16} />
        )}
      </button>
    </HoverLabel>
  );
}

/* ────────────────────────────────────────────────────────────────
 * LoginForm - the editor replacement for login-type notes.
 * Renders structured fields instead of TipTap.
 * ──────────────────────────────────────────────────────────────── */
interface LoginFormProps {
  noteId: string;
  title: string;
  body: string;
  locked: boolean;
  pinProtected: boolean;
  onTitleChange: (id: string, title: string) => void;
  onBodyChange: (id: string, body: string) => void;
  onPinProtectedChange: (id: string, value: boolean) => void;
  onSave: () => void;
  onCancel: () => void;
  isNew: boolean;
  saveError?: string;
  /** Whether the rotating-code preview may render below the field - the
   *  key itself is always visible and editable regardless of tier. */
  isPro: boolean | null;
}

export function LoginForm({
  noteId,
  title,
  body,
  locked,
  pinProtected,
  onTitleChange,
  onBodyChange,
  onPinProtectedChange,
  onSave,
  onCancel,
  isNew,
  saveError,
  isPro,
}: LoginFormProps) {
  const { t } = useTranslation('auth');
  const data = parseLoginBody(body);
  const { copy, copied } = useCopyToClipboard();
  const pinConfigured = useMemo(() => hasPin(), []);
  const [showPinInfo, setShowPinInfo] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const urlRef = useRef<HTMLInputElement>(null);

  /** Soft URL hint - shown when the field has content that doesn't
   *  look like a URL. Not a hard block; users can store anything. */
  const urlHint = (() => {
    const v = data.url.trim();
    if (!v) return null;
    // Contains a dot or known scheme → probably fine.
    if (v.includes('.') || /^https?:\/\//i.test(v)) return null;
    return t('loginForm.urlHint');
  })();

  /** Parsed authenticator key - null when empty or unparseable. */
  const totpParams = useMemo(() => (data.totp.trim() ? parseTotpInput(data.totp) : null), [data.totp]);
  const totpUnlocked = proUnlocked(isPro);
  const [totpNow, setTotpNow] = useState(() => Date.now());

  // Tick once a second only while there's something valid to show -
  // no interval running for an empty or invalid key.
  useEffect(() => {
    if (!totpParams || !totpUnlocked) return;
    const id = setInterval(() => setTotpNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [totpParams, totpUnlocked]);

  const totpCode = totpParams && totpUnlocked ? generateTotpCode(totpParams, totpNow) : null;
  const totpSecondsLeft = totpParams && totpUnlocked ? totpSecondsRemaining(totpParams.period, totpNow) : null;

  const updateBody = useCallback(
    (patch: Partial<LoginData>) => {
      const next = { ...data, ...patch };
      onBodyChange(noteId, serializeLoginBody(next));
    },
    [noteId, data, onBodyChange]
  );

  const handleUrlChange = useCallback(
    (url: string) => {
      updateBody({ url });
    },
    [updateBody]
  );

  /** Auto-derive title from URL domain on blur, only if title is still empty. */
  const handleUrlBlur = useCallback(() => {
    if (!title.trim() && data.url.trim()) {
      const domain = domainFromUrl(data.url);
      if (domain) onTitleChange(noteId, domain);
    }
  }, [noteId, title, data.url, onTitleChange]);

  const fieldClass =
    'w-full rounded-md border border-divider bg-surface-1 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-60';
  const labelClass = 'block text-xs font-medium text-neutral-500 dark:text-neutral-400 mb-1';

  return (
    /* Width comes from VAULT_COLUMN on the VaultItem wrapper. */
    <div className="flex-1 overflow-y-auto p-6">
      <div className="space-y-4">
        {/* Username */}
        <div>
          <label className={labelClass}>{t('loginForm.usernameLabel')}</label>
          <div className="flex gap-1.5">
            <input
              type="text"
              value={data.username}
              onChange={(e) => updateBody({ username: e.target.value })}
              placeholder="user@example.com"
              disabled={locked}
              autoComplete="off"
              className={fieldClass}
            />
            <CopyBtn
              onClick={() => copy(data.username, 'username')}
              active={copied === 'username'}
              title={t('loginForm.copyUsername')}
            />
          </div>
        </div>

        {/* Password */}
        <div>
          <label className={labelClass}>{t('loginForm.passwordLabel')}</label>
          <div className="flex gap-1.5">
            <div className="relative flex-1">
              <input
                type={showPassword ? 'text' : 'password'}
                value={data.password}
                onChange={(e) => updateBody({ password: e.target.value })}
                placeholder={t('loginForm.passwordPlaceholder')}
                disabled={locked}
                autoComplete="off"
                className={`${fieldClass} ${locked ? 'pe-10' : 'pe-[72px]'}`}
              />
              <div className="absolute end-1 top-1/2 -translate-y-1/2 flex items-center">
                <HoverLabel label={showPassword ? t('loginForm.hidePassword') : t('loginForm.showPassword')} position="above">
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? t('loginForm.hidePassword') : t('loginForm.showPassword')}
                  className="rounded p-1 text-neutral-400 hover:text-accent transition"
                >
                  {showPassword ? (
                    <EyeSlash size={16} />
                  ) : (
                    <Eye size={16} />
                  )}
                </button>
                </HoverLabel>
                {!locked && (
                  <HoverLabel label={t('loginForm.generatePassword')} position="above">
                  <button
                    type="button"
                    onClick={() => setShowGenerator(true)}
                    aria-label={t('loginForm.generatePassword')}
                    className="rounded p-1 text-neutral-400 hover:text-accent transition"
                  >
                    <Password size={16} />
                  </button>
                  </HoverLabel>
                )}
              </div>
            </div>
            <CopyBtn
              onClick={() => copy(data.password, 'password')}
              active={copied === 'password'}
              title={t('loginForm.copyPassword')}
            />
          </div>
          {!locked && (
            <button
              type="button"
              onClick={() => setShowGenerator(true)}
              className="inline-flex items-center gap-1 mt-1 text-[11px] text-accent bg-accent/8 hover:bg-accent/15 px-2 py-0.5 rounded-full transition"
            >
              <Password size={11} />
              {t('loginForm.generatePassword')}
            </button>
          )}
          {showGenerator && (
            <PasswordGeneratorModal
              onGenerate={(pw) => {
                updateBody({ password: pw });
                setShowGenerator(false);
                setShowPassword(true);
              }}
              onClose={() => setShowGenerator(false)}
            />
          )}
        </div>

        {/* Authenticator key (TOTP) - the key itself is never masked or
            gated; only the generated code (below) is a Pro feature. */}
        <div>
          <label className={labelClass}>{t('loginForm.totpLabel')}</label>
          <div className="flex gap-1.5">
            <input
              type="text"
              value={data.totp}
              onChange={(e) => updateBody({ totp: e.target.value })}
              placeholder={t('loginForm.totpPlaceholder')}
              disabled={locked}
              autoComplete="off"
              spellCheck={false}
              className={`${fieldClass} font-mono`}
            />
            <CopyBtn
              onClick={() => copy(data.totp, 'totp')}
              active={copied === 'totp'}
              title={t('loginForm.copyTotp')}
            />
          </div>
          {data.totp.trim() && !totpParams && (
            <p className="mt-1 text-[11px] text-amber-600 dark:text-amber-400">{t('loginForm.totpInvalid')}</p>
          )}
          {totpParams && totpUnlocked && totpCode && totpSecondsLeft !== null && (
            <p className="mt-1 text-[11px] text-neutral-500 dark:text-neutral-400 flex items-center gap-1.5">
              <span dir="ltr" className="font-mono text-neutral-700 dark:text-neutral-300 tabular-nums" /* rtl-ok: generated digits, must not reorder */>
                {totpCode}
              </span>
              <span className="tabular-nums">· {t('loginForm.totpExpiresIn', { seconds: totpSecondsLeft })}</span>
            </p>
          )}
          {totpParams && !totpUnlocked && (
            <p className="mt-1 text-[11px] text-neutral-400 dark:text-neutral-500">{t('loginForm.totpProNote')}</p>
          )}
        </div>

        {/* Website / URL - after the credentials, the same order the view
            shows: the title names the site, so the address is a detail. */}
        <div>
          <label className={labelClass}>{t('loginForm.websiteLabel')}</label>
          <div className="flex gap-1.5">
            <input
              ref={urlRef}
              type="url"
              value={data.url}
              onChange={(e) => handleUrlChange(e.target.value)}
              onBlur={handleUrlBlur}
              placeholder="https://github.com"
              disabled={locked}
              autoComplete="off"
              className={fieldClass}
            />
            <CopyBtn
              onClick={() => copy(data.url, 'url')}
              active={copied === 'url'}
              title={t('loginForm.copyUrl')}
            />
          </div>
          {urlHint && (
            <p className="mt-1 text-[11px] text-amber-600 dark:text-amber-400">{urlHint}</p>
          )}
        </div>

        {/* Notes */}
        <div>
          <label className={labelClass}>{t('loginForm.notesLabel')}</label>
          <textarea
            value={data.notes}
            onChange={(e) => updateBody({ notes: e.target.value })}
            placeholder={t('loginForm.notesPlaceholder')}
            disabled={locked}
            rows={3}
            className={`${fieldClass} resize-y`}
          />
        </div>

        {/* PIN-protect toggle */}
        <label className={`flex items-center gap-2 pt-2 border-t border-divider ${!pinConfigured && !pinProtected ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}>
          <input
            type="checkbox"
            checked={pinProtected}
            onChange={(e) => onPinProtectedChange(noteId, e.target.checked)}
            // Read-only locks CONTENT, not protection: toggling the PIN gate
            // changes no data, so it stays available on a locked item.
            disabled={!pinConfigured && !pinProtected}
            className="rounded accent-accent"
          />
          <span className="text-sm text-neutral-600 dark:text-neutral-400">
            {t('loginForm.requirePin')}
          </span>
          <button
            type="button"
            onClick={(e) => { e.preventDefault(); setShowPinInfo(true); }}
            className="text-accent/60 hover:text-accent transition p-1 -m-1"
            aria-label={t('loginForm.whatDoesThisDo')}
          >
            <Info />
          </button>
        </label>

        {showPinInfo && <PinInfoModal onClose={() => setShowPinInfo(false)} />}
        {!pinConfigured && !pinProtected && (
          <p className="text-[11px] text-neutral-400 dark:text-neutral-500 -mt-2">
            {t('loginForm.setUpPinFirst')}
          </p>
        )}

        {/* Save / Cancel */}
        {saveError && (
          <p className="text-[11px] text-red-600 dark:text-red-400">{saveError}</p>
        )}
        {!locked && (
          <div className="flex gap-2 -mt-2">
            {!isNew && (
              <button
                type="button"
                onClick={onCancel}
                className="flex-1 inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-md text-sm font-medium border border-divider text-neutral-600 dark:text-neutral-400 hover:bg-neutral-100 dark:hover:bg-surface-1 transition"
              >
                {t('common:actions.cancel')}
              </button>
            )}
            <button
              type="button"
              onClick={onSave}
              className="flex-1 inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-md text-sm font-medium bg-accent text-white hover:bg-accent-hover transition"
            >
              <FloppyDisk />
              {t('common:actions.save')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
