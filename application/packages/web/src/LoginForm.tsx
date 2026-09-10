import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Check, Copy, Eye, EyeSlash, FloppyDisk, Globe, Info, Lock, NotePencil, Password, Shield, User } from './icons';
import { hasPin } from './pin';
import { PinInfoModal } from './PinInfoModal';
import { HoverLabel } from './HoverLabel';
import { useCopyToClipboard } from './clipboard';
import { parseTotpInput, generateTotpCode, totpSecondsRemaining } from '@notes/shared';
import { proUnlocked } from './demo';
import { PasswordField } from './PasswordText';
import { FIELD_BUTTON, FIELD_CLASS, FieldLabel } from './formFields';
import { PasswordGeneratorModal } from './PasswordGenerator';
import type { UpgradeTrigger } from './UpgradeModal';

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
  return (
    <HoverLabel label={title} position="start">
      <button type="button" onClick={onClick} aria-label={title} className={FIELD_BUTTON}>
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
   *  key itself is always visible and editable regardless of tier. Also
   *  gates the generator's passphrase mode. */
  isPro: boolean | null;
  onOpenUpgrade: (trigger: UpgradeTrigger) => void;
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
  onOpenUpgrade,
}: LoginFormProps) {
  const { t } = useTranslation('auth');
  const data = parseLoginBody(body);
  const { copy, copied } = useCopyToClipboard();
  // Never memoize this. Settings opens over a mounted form, so a PIN
  // can appear or vanish while the toggle below is on screen, and
  // localStorage fires nothing that would refresh a frozen value.
  const pinConfigured = hasPin();
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

  const fieldClass = FIELD_CLASS;

  return (
    /* Width comes from VAULT_COLUMN on the VaultItem wrapper. */
    <div className="flex-1 overflow-y-auto p-6">
      <div className="space-y-4">
        {/* Username */}
        <div>
          <FieldLabel icon={<User size={13} />}>{t('loginForm.usernameLabel')}</FieldLabel>
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
          <FieldLabel icon={<Lock size={13} />}>{t('loginForm.passwordLabel')}</FieldLabel>
          <div className="flex gap-1.5">
            <PasswordField
              value={data.password}
              onChange={(e) => updateBody({ password: e.target.value })}
              revealed={showPassword}
              disabled={locked}
              placeholder={t('loginForm.passwordPlaceholder')}
              fieldClass={fieldClass}
            />
            <HoverLabel label={showPassword ? t('loginForm.hidePassword') : t('loginForm.showPassword')} position="above">
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={showPassword ? t('loginForm.hidePassword') : t('loginForm.showPassword')}
                className={FIELD_BUTTON}
              >
                {showPassword ? <EyeSlash size={16} /> : <Eye size={16} />}
              </button>
            </HoverLabel>
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
              isPro={isPro}
              onOpenUpgrade={() => onOpenUpgrade('passphrase')}
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
          <FieldLabel icon={<Shield size={13} />}>{t('loginForm.totpLabel')}</FieldLabel>
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
          <FieldLabel icon={<Globe size={13} />}>{t('loginForm.websiteLabel')}</FieldLabel>
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
          <FieldLabel icon={<NotePencil size={13} />}>{t('loginForm.notesLabel')}</FieldLabel>
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
