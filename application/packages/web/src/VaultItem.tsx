import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import { LoginForm, parseLoginBody, domainFromUrl } from './LoginForm';
import { CardForm, parseCardBody, detectCardNetwork } from './CardForm';
import { SshKeyForm, parseSshKeyBody } from './SshKeyForm';
import { VAULT_EMPTY_BODIES } from './notesViewUtils';
import { faviconUrl, domainFromUrlString } from './favicon';
import { prefetchFavicon } from './faviconQueue';
import { HoverLabel } from './HoverLabel';
import { exemptOpts } from './i18nExempt';
import { Copy, Check, Eye, EyeSlash, ArrowSquareOut, PencilSimple, X, Key, CreditCard, Lock, Globe, User, Calendar, MapPin, Tag, Shield, RocketLaunch } from './icons';
import { useCopyToClipboard } from './clipboard';
import { useTheme } from './theme';
import { parseTotpInput, generateTotpCode, totpSecondsRemaining } from '@notes/shared';
import { proUnlocked } from './demo';

/**
 * The vault column. Every vault surface is a stack of label + value rows,
 * so at the editor column's full width the value sits stranded at the far
 * end with a lane of empty space between. The three view modes and the edit
 * wrapper below all wear this, and the three forms inherit it from that
 * wrapper - one number, one place.
 * Spec: ops/docs/ui-patterns.md (the vault column)
 */
const VAULT_COLUMN = 'w-full max-w-[520px]';

/* ────────────────────────────────────────────────────────────────
 * Icon helpers - thin wrappers around the shared Phosphor module
 * ──────────────────────────────────────────────────────────────── */
const IconCopy = ({ className = '' }: { className?: string }) => (
  <Copy className={className} />
);
const IconCheck = ({ className = '' }: { className?: string }) => (
  <Check className={className} />
);
const IconEye = () => <Eye />;
const IconEyeOff = () => <EyeSlash />;
const IconExternal = () => <ArrowSquareOut size={12} />;
const IconEdit = () => <PencilSimple />;
const IconX = () => <X />;
const IconSave = () => <Check />;

/* ────────────────────────────────────────────────────────────────
 * Copy button - view-mode field action
 * ──────────────────────────────────────────────────────────────── */
function CopyButton({ value, label, copied, onCopy }: {
  value: string;
  label: string;
  copied: string | null;
  onCopy: (text: string, label: string) => void;
}) {
  const { t } = useTranslation('shell');
  const isCopied = copied === label;
  const tip = isCopied ? t('vaultItem.copied') : t('vaultItem.copyField', { label });
  return (
    <HoverLabel label={tip} position="start">
      <button
        type="button"
        onClick={() => onCopy(value, label)}
        aria-label={tip}
        className="shrink-0 rounded-md p-1.5 text-neutral-400 hover:text-accent hover:bg-neutral-100 dark:hover:bg-surface-0 transition"
      >
        {isCopied ? <IconCheck className="text-emerald-500" /> : <IconCopy />}
      </button>
    </HoverLabel>
  );
}

/* ────────────────────────────────────────────────────────────────
 * Favicon image with concurrency-throttled loading + IndexedDB cache.
 *
 * Uses IntersectionObserver to detect visibility, then calls
 * prefetchFavicon which checks IndexedDB first (instant, offline-
 * capable), falls back to a queued network fetch (max 5 concurrent),
 * and stores the result in IndexedDB for future sessions.
 *
 * Spec: ops/docs/backlog.md (#69 - client concurrency cap + IDB cache)
 * ──────────────────────────────────────────────────────────────── */
function Favicon({ domain, size = 20 }: { domain: string; size?: number }) {
  const [src, setSrc] = useState('');
  const [failed, setFailed] = useState(false);
  const containerRef = useRef<HTMLSpanElement>(null);
  const { favicons } = useTheme();
  const url = domain && favicons ? faviconUrl(domain) : '';

  useEffect(() => {
    setSrc('');
    setFailed(false);
    if (!url) return;

    const el = containerRef.current;
    if (!el) return;

    let cancelled = false;

    const observer = new IntersectionObserver(
      (entries) => {
        const entry = entries[0];
        if (!entry?.isIntersecting || cancelled) return;
        observer.disconnect();
        prefetchFavicon(url).then(blobUrl => {
          if (cancelled) return;
          if (blobUrl) setSrc(blobUrl);
          else setFailed(true);
        });
      },
      { rootMargin: '200px' },
    );

    observer.observe(el);
    return () => { cancelled = true; observer.disconnect(); };
  }, [url]);

  // ONE box in every state - icon, still loading, globe fallback - and the
  // observed element is that box, so the ref NEVER detaches. The <img> used
  // to replace the ref'd span outright, which made React null the ref: after
  // that, a domain change (editing a bookmark's URL) found no element to
  // observe, started no fetch, and the surface kept the old icon until it
  // happened to remount. That is why switching pillars "fixed" it.
  return (
    <span
      ref={containerRef}
      className="inline-flex items-center justify-center rounded bg-[#f0efec] text-neutral-400 overflow-hidden"
      style={{ width: size, height: size }}
    >
      {src ? (
        <img
          src={src}
          alt=""
          width={size}
          height={size}
          style={{ width: size, height: size }}
          onError={() => setFailed(true)}
        />
      ) : !url || failed ? (
        <Globe size={size} />
      ) : null}
    </span>
  );
}

/* ────────────────────────────────────────────────────────────────
 * Type badge - small colored pill showing the vault item type
 * ──────────────────────────────────────────────────────────────── */
function TypeBadge({ type }: { type: 'login' | 'card' | 'ssh-key' }) {
  const { t } = useTranslation('shell');
  const cfg = {
    login: { label: t('vaultItem.badgeLogin'), bg: 'bg-blue-50 dark:bg-blue-950/50', text: 'text-blue-700 dark:text-blue-300', icon: (
      <Lock size={10} />
    )},
    card: { label: t('vaultItem.badgeCard'), bg: 'bg-amber-50 dark:bg-amber-950/50', text: 'text-amber-700 dark:text-amber-300', icon: (
      <CreditCard size={10} />
    )},
    'ssh-key': { label: t('vaultItem.badgeSshKey', exemptOpts('shell:vaultItem.badgeSshKey')), bg: 'bg-neutral-900 dark:bg-neutral-800', text: 'text-white', icon: (
      <Key size={10} />
    )},
  }[type];

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium ${cfg.bg} ${cfg.text}`}>
      {cfg.icon}
      {cfg.label}
    </span>
  );
}

/* ────────────────────────────────────────────────────────────────
 * View-mode field row
 * ──────────────────────────────────────────────────────────────── */
function ViewField({ label, icon, children }: {
  label: React.ReactNode;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-neutral-100 dark:border-neutral-800 last:border-b-0">
      <span className="text-xs text-neutral-500 dark:text-neutral-400 flex items-center gap-1.5 shrink-0 min-w-[70px]">
        {icon}
        {label}
      </span>
      <div className="flex items-center gap-1.5 min-w-0 justify-end">
        {children}
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * TOTP countdown ring - a thin SVG circle that drains over the
 * code's period, red in the last 5 seconds. Static (full, muted)
 * when there's no code to count down (the locked teaser state).
 * ──────────────────────────────────────────────────────────────── */
function TotpRing({ secondsLeft, period, danger, static: isStatic = false }: {
  secondsLeft: number;
  period: number;
  danger: boolean;
  static?: boolean;
}) {
  const r = 9;
  const circumference = 2 * Math.PI * r; // ~56.5
  const offset = isStatic ? 0 : circumference * (1 - secondsLeft / period);
  return (
    <svg width={20} height={20} viewBox="0 0 20 20" className="shrink-0" aria-hidden="true">
      <circle cx={10} cy={10} r={r} fill="none" strokeWidth={2} stroke="currentColor" className="text-neutral-200 dark:text-neutral-700" />
      <circle
        cx={10}
        cy={10}
        r={r}
        fill="none"
        strokeWidth={2}
        strokeLinecap="round"
        stroke="currentColor"
        className={isStatic ? 'text-neutral-300 dark:text-neutral-600' : danger ? 'text-red-500' : 'text-accent'}
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        transform="rotate(-90 10 10)"
        style={isStatic ? undefined : { transition: 'stroke-dashoffset 1s linear' }}
      />
    </svg>
  );
}

/** Split a code into two halves with a thin space between (6→3+3, 8→4+4, 7→4+3). */
function groupTotpCode(code: string): string {
  const mid = Math.ceil(code.length / 2);
  return `${code.slice(0, mid)} ${code.slice(mid)}`;
}

/* ────────────────────────────────────────────────────────────────
 * TOTP code row - shown under the password field for a login that
 * has an authenticator key set. The key is stored and synced for
 * every tier (LoginData.totp); only the generated code is gated.
 * ──────────────────────────────────────────────────────────────── */
// Spec: ops/docs/pro-features.md (TOTP code display Pro gate)
function TotpField({ raw, isPro, onOpenUpgrade, copy, copied }: {
  raw: string;
  isPro: boolean | null;
  onOpenUpgrade: () => void;
  copy: (text: string, label: string) => void;
  copied: string | null;
}) {
  const { t } = useTranslation('shell');
  const params = useMemo(() => parseTotpInput(raw), [raw]);
  const unlocked = proUnlocked(isPro);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!params || !unlocked) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [params, unlocked]);

  if (!params) {
    return (
      <ViewField label={t('vaultItem.fieldTotp')} icon={<Shield size={13} />}>
        <span className="text-sm text-neutral-400 dark:text-neutral-500 italic">{t('vaultItem.totpInvalid')}</span>
      </ViewField>
    );
  }

  const label = (
    <span className="flex items-center gap-1.5">
      {t('vaultItem.fieldTotp')}
      {!isPro && <RocketLaunch size={11} weight="fill" className="text-pro" />}
    </span>
  );

  if (!unlocked) {
    return (
      <div className="py-2.5 border-b border-neutral-100 dark:border-neutral-800 last:border-b-0">
        <ViewField label={label} icon={<Shield size={13} />}>
          <span dir="ltr" className="text-sm font-mono tracking-wider text-neutral-400 dark:text-neutral-600" /* rtl-ok: masked code placeholder, symbols only, must not reorder */>
            {'••• •••'}
          </span>
          <TotpRing secondsLeft={params.period} period={params.period} danger={false} static />
        </ViewField>
        <button
          type="button"
          onClick={onOpenUpgrade}
          className="mt-1 w-full py-1.5 rounded-md text-xs font-medium bg-accent/8 text-accent hover:bg-accent/15 transition"
        >
          {t('vaultItem.totpUnlockCta')}
        </button>
        <p className="mt-1 text-[11px] text-neutral-400 dark:text-neutral-500">{t('vaultItem.totpProNote')}</p>
      </div>
    );
  }

  const code = generateTotpCode(params, now);
  const secondsLeft = totpSecondsRemaining(params.period, now);
  const isCopied = copied === 'totpCode';

  return (
    <ViewField label={label} icon={<Shield size={13} />}>
      <span dir="ltr" className="text-sm font-mono tracking-wider tabular-nums text-neutral-800 dark:text-neutral-200" /* rtl-ok: generated digits, must not reorder */>
        {groupTotpCode(code)}
      </span>
      <TotpRing secondsLeft={secondsLeft} period={params.period} danger={secondsLeft <= 5} />
      <HoverLabel label={isCopied ? t('vaultItem.copied') : t('vaultItem.copyCode')} position="start">
        <button
          type="button"
          onClick={() => copy(code, 'totpCode')}
          aria-label={t('vaultItem.copyCode')}
          className="shrink-0 rounded-md p-1.5 text-neutral-400 hover:text-accent hover:bg-neutral-100 dark:hover:bg-surface-0 transition"
        >
          {isCopied ? <IconCheck className="text-emerald-500" /> : <IconCopy />}
        </button>
      </HoverLabel>
    </ViewField>
  );
}

/* ────────────────────────────────────────────────────────────────
 * Login view mode
 * ──────────────────────────────────────────────────────────────── */
function LoginViewMode({ note, onEdit, copy, copied, isPro, onOpenUpgrade }: {
  note: LocalNote;
  onEdit: () => void;
  copy: (text: string, label: string) => void;
  copied: string | null;
  isPro: boolean | null;
  onOpenUpgrade: () => void;
}) {
  const { t } = useTranslation('shell');
  const data = parseLoginBody(note.body);
  const [showPassword, setShowPassword] = useState(false);
  const domain = domainFromUrlString(data.url);
  const fullUrl = data.url.trim() && !/^https?:\/\//i.test(data.url.trim())
    ? 'https://' + data.url.trim()
    : data.url.trim();

  return (
    <div className={`flex-1 p-6 ${VAULT_COLUMN}`}>
      {/* Header: favicon + title + badge + edit */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3 min-w-0">
          <span className="shrink-0 w-10 h-10 rounded-md bg-[#f0efec] flex items-center justify-center overflow-hidden">
            <Favicon domain={domain} size={28} />
          </span>
          <div className="min-w-0">
            <div className="text-lg font-semibold truncate text-neutral-900 dark:text-white">
              {note.title || t('vaultItem.untitledLogin')}
            </div>
            <TypeBadge type="login" />
          </div>
        </div>
        <button
          type="button"
          onClick={onEdit}
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-surface-1 border border-divider text-neutral-700 dark:text-neutral-300 hover:bg-neutral-200 dark:hover:bg-surface-0 transition"
        >
          <IconEdit /> {t('common:actions.edit')}
        </button>
      </div>

      {/* Fields */}
      <div>
        {data.url && (
          <ViewField label={t('vaultItem.fieldUrl')} icon={<Globe size={13} />}>
            <a
              href={fullUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-accent hover:underline truncate"
            >
              {domain || data.url}
            </a>
            <CopyButton value={data.url} label="url" copied={copied} onCopy={copy} />
          </ViewField>
        )}

        {data.username && (
          <ViewField label={t('vaultItem.fieldUser')} icon={<User size={13} />}>
            <span className="text-sm text-neutral-800 dark:text-neutral-200 truncate">{data.username}</span>
            <CopyButton value={data.username} label="username" copied={copied} onCopy={copy} />
          </ViewField>
        )}

        {data.password && (
          <ViewField label={t('vaultItem.fieldPass')} icon={<Lock size={13} />}>
            <span className="min-w-0 break-all text-end text-sm font-mono text-neutral-800 dark:text-neutral-200 tracking-wider">
              {showPassword ? data.password : '•'.repeat(Math.min(data.password.length, 16))}
            </span>
            <HoverLabel label={showPassword ? t('vaultItem.hide') : t('vaultItem.reveal')} position="start">
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              aria-label={showPassword ? t('vaultItem.hide') : t('vaultItem.reveal')}
              className="shrink-0 p-1 text-neutral-400 hover:text-accent transition rounded"
            >
              {showPassword ? <IconEyeOff /> : <IconEye />}
            </button>
            </HoverLabel>
            <CopyButton value={data.password} label="password" copied={copied} onCopy={copy} />
          </ViewField>
        )}

        {data.totp.trim() && (
          <TotpField raw={data.totp} isPro={isPro} onOpenUpgrade={onOpenUpgrade} copy={copy} copied={copied} />
        )}
      </div>

      {/* Copy all button - only when there's something meaningful to copy */}
      {(data.url || data.username || data.password) && (
        <button
          type="button"
          onClick={() => {
            const lines: string[] = [];
            if (data.url) lines.push(data.url.trim());
            if (data.username) lines.push(data.username);
            if (data.password) lines.push(data.password);
            copy(lines.join('\n'), 'all');
          }}
          className="mt-3 w-full py-2 rounded-lg text-xs font-medium text-neutral-500 dark:text-neutral-400 border border-divider hover:bg-neutral-100 dark:hover:bg-surface-0 transition flex items-center justify-center gap-1.5"
        >
          {copied === 'all' ? <IconCheck className="text-emerald-500" /> : <IconCopy />}
          {copied === 'all' ? t('vaultItem.copied') : t('vaultItem.copyAll')}
        </button>
      )}

      {data.notes && (
        <div className="mt-3 pt-3 border-t border-neutral-100 dark:border-neutral-800 text-sm text-neutral-500 dark:text-neutral-400 italic whitespace-pre-wrap break-words">
          {data.notes}
        </div>
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * Card view mode
 * ──────────────────────────────────────────────────────────────── */
function CardViewMode({ note, onEdit, copy, copied }: {
  note: LocalNote;
  onEdit: () => void;
  copy: (text: string, label: string) => void;
  copied: string | null;
}) {
  const { t } = useTranslation('shell');
  const data = parseCardBody(note.body);
  const [showNumber, setShowNumber] = useState(false);
  const [showCvv, setShowCvv] = useState(false);
  const digits = data.cardNumber.replace(/\D/g, '');
  const last4 = digits.slice(-4);
  const network = detectCardNetwork(digits);
  const masked = digits.length > 4
    ? '•••• '.repeat(Math.floor((digits.length - 4) / 4)) + last4
    : digits;
  const formatted = digits.replace(/(.{4})/g, '$1 ').trim();

  return (
    <div className={`flex-1 overflow-y-auto p-6 ${VAULT_COLUMN}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="min-w-0">
          <div className="text-lg font-semibold truncate text-neutral-900 dark:text-white">
            {note.title || t('vaultItem.untitledCard')}
          </div>
          <TypeBadge type="card" />
        </div>
        <button
          type="button"
          onClick={onEdit}
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-surface-1 border border-divider text-neutral-700 dark:text-neutral-300 hover:bg-neutral-200 dark:hover:bg-surface-0 transition"
        >
          <IconEdit /> {t('common:actions.edit')}
        </button>
      </div>

      <div>
        {data.cardholderName && (
          <ViewField label={t('vaultItem.fieldName')} icon={<User size={13} />}>
            <span className="text-sm text-neutral-800 dark:text-neutral-200 truncate">{data.cardholderName}</span>
            <CopyButton value={data.cardholderName} label="name" copied={copied} onCopy={copy} />
          </ViewField>
        )}

        {digits && (
          <ViewField label={t('vaultItem.fieldNumber')} icon={<CreditCard size={13} />}>
            <span className="min-w-0 text-end text-sm font-mono text-neutral-800 dark:text-neutral-200 tracking-wider">
              {showNumber ? formatted : masked}
            </span>
            {network && <span className="text-[10px] text-neutral-400 shrink-0">{network}</span>}
            <HoverLabel label={showNumber ? t('vaultItem.hide') : t('vaultItem.reveal')} position="start">
            <button type="button" onClick={() => setShowNumber(!showNumber)} aria-label={showNumber ? t('vaultItem.hide') : t('vaultItem.reveal')} className="shrink-0 p-1 text-neutral-400 hover:text-accent transition rounded">
              {showNumber ? <IconEyeOff /> : <IconEye />}
            </button>
            </HoverLabel>
            <CopyButton value={digits} label="number" copied={copied} onCopy={copy} />
          </ViewField>
        )}

        {(data.expMonth || data.expYear) && (
          <ViewField label={t('vaultItem.fieldExpires')} icon={<Calendar size={13} />}>
            <span className="text-sm text-neutral-800 dark:text-neutral-200">
              {data.expMonth}/{data.expYear}
            </span>
            <CopyButton value={`${data.expMonth}/${data.expYear}`} label="exp" copied={copied} onCopy={copy} />
          </ViewField>
        )}

        {data.cvv && (
          <ViewField label={t('vaultItem.fieldCvv')} icon={<Lock size={13} />}>
            <span className="text-sm font-mono text-neutral-800 dark:text-neutral-200 tracking-wider">
              {showCvv ? data.cvv : '•'.repeat(data.cvv.length)}
            </span>
            <HoverLabel label={showCvv ? t('vaultItem.hide') : t('vaultItem.reveal')} position="start">
            <button type="button" onClick={() => setShowCvv(!showCvv)} aria-label={showCvv ? t('vaultItem.hide') : t('vaultItem.reveal')} className="shrink-0 p-1 text-neutral-400 hover:text-accent transition rounded">
              {showCvv ? <IconEyeOff /> : <IconEye />}
            </button>
            </HoverLabel>
            <CopyButton value={data.cvv} label="cvv" copied={copied} onCopy={copy} />
          </ViewField>
        )}

        {data.billingZip && (
          <ViewField label={t('vaultItem.fieldZip')} icon={<MapPin size={13} />}>
            <span className="min-w-0 break-all text-end text-sm text-neutral-800 dark:text-neutral-200">{data.billingZip}</span>
            <CopyButton value={data.billingZip} label="zip" copied={copied} onCopy={copy} />
          </ViewField>
        )}
      </div>

      {data.notes && (
        <div className="mt-3 pt-3 border-t border-neutral-100 dark:border-neutral-800 text-sm text-neutral-500 dark:text-neutral-400 italic whitespace-pre-wrap break-words">
          {data.notes}
        </div>
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * SSH Key view mode
 * ──────────────────────────────────────────────────────────────── */
function SshKeyViewMode({ note, onEdit, copy, copied }: {
  note: LocalNote;
  onEdit: () => void;
  copy: (text: string, label: string) => void;
  copied: string | null;
}) {
  const { t } = useTranslation('shell');
  const data = parseSshKeyBody(note.body);
  const [showPrivate, setShowPrivate] = useState(false);
  const [showPassphrase, setShowPassphrase] = useState(false);

  // Truncate public key for display.
  const pubShort = data.publicKey.length > 40
    ? data.publicKey.slice(0, 20) + '...' + data.publicKey.slice(-15)
    : data.publicKey;

  return (
    <div className={`flex-1 overflow-y-auto p-6 ${VAULT_COLUMN}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="min-w-0">
          <div className="text-lg font-semibold truncate text-neutral-900 dark:text-white">
            {note.title || t('vaultItem.untitledKey')}
          </div>
          <TypeBadge type="ssh-key" />
        </div>
        <button
          type="button"
          onClick={onEdit}
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-surface-1 border border-divider text-neutral-700 dark:text-neutral-300 hover:bg-neutral-200 dark:hover:bg-surface-0 transition"
        >
          <IconEdit /> {t('common:actions.edit')}
        </button>
      </div>

      <div>
        {data.label && (
          <ViewField label={t('vaultItem.fieldLabel')} icon={<Tag size={13} />}>
            <span className="text-sm text-neutral-800 dark:text-neutral-200 truncate">{data.label}</span>
          </ViewField>
        )}

        {data.publicKey && (
          <ViewField label={t('vaultItem.fieldPublic')} icon={<Key size={13} />}>
            <span className="text-xs font-mono text-neutral-600 dark:text-neutral-400 truncate max-w-[200px]">{pubShort}</span>
            <CopyButton value={data.publicKey} label="publicKey" copied={copied} onCopy={copy} />
          </ViewField>
        )}

        {data.privateKey && (
          <ViewField label={t('vaultItem.fieldPrivate')} icon={<Lock size={13} />}>
            <span className="min-w-0 break-all text-end text-sm font-mono text-neutral-800 dark:text-neutral-200 tracking-wider">
              {showPrivate ? data.privateKey.slice(0, 30) + '...' : '•'.repeat(16)}
            </span>
            <HoverLabel label={showPrivate ? t('vaultItem.hide') : t('vaultItem.reveal')} position="start">
            <button type="button" onClick={() => setShowPrivate(!showPrivate)} aria-label={showPrivate ? t('vaultItem.hide') : t('vaultItem.reveal')} className="shrink-0 p-1 text-neutral-400 hover:text-accent transition rounded">
              {showPrivate ? <IconEyeOff /> : <IconEye />}
            </button>
            </HoverLabel>
            <CopyButton value={data.privateKey} label="privateKey" copied={copied} onCopy={copy} />
          </ViewField>
        )}

        {data.passphrase && (
          <ViewField label={t('vaultItem.fieldPass')} icon={<Shield size={13} />}>
            <span className="min-w-0 break-all text-end text-sm font-mono text-neutral-800 dark:text-neutral-200 tracking-wider">
              {showPassphrase ? data.passphrase : '•'.repeat(Math.min(data.passphrase.length, 12))}
            </span>
            <HoverLabel label={showPassphrase ? t('vaultItem.hide') : t('vaultItem.reveal')} position="start">
            <button type="button" onClick={() => setShowPassphrase(!showPassphrase)} aria-label={showPassphrase ? t('vaultItem.hide') : t('vaultItem.reveal')} className="shrink-0 p-1 text-neutral-400 hover:text-accent transition rounded">
              {showPassphrase ? <IconEyeOff /> : <IconEye />}
            </button>
            </HoverLabel>
            <CopyButton value={data.passphrase} label="passphrase" copied={copied} onCopy={copy} />
          </ViewField>
        )}
      </div>

      {data.notes && (
        <div className="mt-3 pt-3 border-t border-neutral-100 dark:border-neutral-800 text-sm text-neutral-500 dark:text-neutral-400 italic whitespace-pre-wrap break-words">
          {data.notes}
        </div>
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * Detect whether a vault body is "empty" (freshly created).
 * ──────────────────────────────────────────────────────────────── */
function isEmptyVaultBody(body: string, type: string): boolean {
  const empty = VAULT_EMPTY_BODIES[type];
  if (!empty) return false;
  return body === empty;
}

/* ────────────────────────────────────────────────────────────────
 * VaultItem - wrapper that manages view/edit lifecycle.
 *
 * New items (empty body) start in edit mode. After Save, the item
 * locks into a read-only view with copy buttons and clickable URLs.
 * An Edit button unlocks the form again.
 *
 * During edit mode, changes are buffered locally and only committed
 * to the note store on Save. Cancel reverts to the last saved state.
 * ──────────────────────────────────────────────────────────────── */
export interface VaultItemProps {
  note: LocalNote;
  isTrash: boolean;
  onTitleChange: (id: string, title: string) => void;
  onBodyChange: (id: string, body: string) => void;
  onPinProtectedChange: (id: string, value: boolean) => void;
  /** Drives the TOTP code Pro gate (behavior only - the badge stays on
   *  plain !isPro so demo keeps advertising the feature it unlocks). */
  isPro: boolean | null;
  onOpenUpgrade: () => void;
}

export function VaultItem({
  note,
  isTrash,
  onTitleChange,
  onBodyChange,
  onPinProtectedChange,
  isPro,
  onOpenUpgrade,
}: VaultItemProps) {
  const { t } = useTranslation('shell');
  const isNew = isEmptyVaultBody(note.body, note.type);
  const [editing, setEditing] = useState(isNew);
  // Title is NOT buffered here: the note title bar (NotesView header) is the
  // canonical title input and writes note.title live, like every other note
  // type. Buffering a draftTitle here let a stale copy clobber the live title
  // on Save (bug #136). The form's auto-derive uses the live onTitleChange.
  const [draftBody, setDraftBody] = useState(note.body);
  // PIN-protect lives in draft state too - committing it immediately
  // (via the parent's setPinProtected) flips `isNoteLocked` to true,
  // which unmounts VaultItem and discards unsaved draftTitle/draftBody
  // when the user falls outside the PIN unlock window. See changelog
  // entry for 0.156.4.
  const [draftPinProtected, setDraftPinProtected] = useState(note.pinProtected === 1);
  const { copy, copied } = useCopyToClipboard();
  const [saveError, setSaveError] = useState('');

  // Sync draft when the note changes externally (e.g. sync from another device).
  useEffect(() => {
    if (!editing) {
      setDraftBody(note.body);
      setDraftPinProtected(note.pinProtected === 1);
    }
  }, [note.body, note.pinProtected, editing]);

  // When selecting a new note, reset editing state.
  useEffect(() => {
    const empty = isEmptyVaultBody(note.body, note.type);
    setEditing(empty);
    setDraftBody(note.body);
    setDraftPinProtected(note.pinProtected === 1);
    setSaveError('');
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [note.id]);

  /** Check that at least one meaningful field has content. */
  const isBodyEmpty = useMemo(() => {
    const empty = VAULT_EMPTY_BODIES[note.type];
    return empty ? draftBody === empty : false;
  }, [draftBody, note.type]);

  const handleSave = useCallback(() => {
    if (isBodyEmpty) {
      setSaveError(t('vaultItem.fillOneField'));
      return;
    }
    // Validate incomplete expiry: both month and year, or neither.
    if (note.type === 'card') {
      const cd = parseCardBody(draftBody);
      if ((cd.expMonth && !cd.expYear) || (!cd.expMonth && cd.expYear)) {
        setSaveError(t('vaultItem.expiryNeedsBoth'));
        return;
      }
    }
    setSaveError('');
    onBodyChange(note.id, draftBody);
    if (draftPinProtected !== (note.pinProtected === 1)) {
      onPinProtectedChange(note.id, draftPinProtected);
    }
    setEditing(false);
  }, [note.id, note.pinProtected, draftBody, draftPinProtected, onBodyChange, onPinProtectedChange, isBodyEmpty, t]);

  const handleCancel = useCallback(() => {
    setDraftBody(note.body);
    setDraftPinProtected(note.pinProtected === 1);
    setEditing(false);
  }, [note.body, note.pinProtected]);

  const handleEdit = useCallback(() => {
    setDraftBody(note.body);
    setDraftPinProtected(note.pinProtected === 1);
    setEditing(true);
  }, [note.body, note.pinProtected]);

  const locked = isTrash || note.locked === 1;

  // ── View mode ────────────────────────────────────────────────
  if (!editing && !isNew) {
    if (note.type === 'login') {
      return <LoginViewMode note={note} onEdit={handleEdit} copy={copy} copied={copied} isPro={isPro} onOpenUpgrade={onOpenUpgrade} />;
    }
    if (note.type === 'card') {
      return <CardViewMode note={note} onEdit={handleEdit} copy={copy} copied={copied} />;
    }
    return <SshKeyViewMode note={note} onEdit={handleEdit} copy={copy} copied={copied} />;
  }

  // ── Edit mode ────────────────────────────────────────────────
  const formProps = {
    noteId: note.id,
    title: note.title,
    body: draftBody,
    locked,
    pinProtected: draftPinProtected,
    onTitleChange,
    onBodyChange: (_id: string, b: string) => setDraftBody(b),
    onPinProtectedChange: (_id: string, v: boolean) => setDraftPinProtected(v),
    onSave: handleSave,
    onCancel: handleCancel,
    isNew,
    saveError,
  };
  const loginFormProps = { ...formProps, isPro };

  return (
    <div className={`flex-1 flex flex-col min-h-0 ${VAULT_COLUMN}`}>
      {note.type === 'login' ? (
        <LoginForm {...loginFormProps} />
      ) : note.type === 'card' ? (
        <CardForm {...formProps} />
      ) : (
        <SshKeyForm {...formProps} />
      )}
    </div>
  );
}

/* Re-export Favicon for use in NoteRow */
export { Favicon };
