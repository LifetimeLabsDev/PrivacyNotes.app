import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { hasPin } from './pin';
import { PinInfoModal } from './PinInfoModal';
import { HoverLabel } from './HoverLabel';
import { Check, Copy, Eye, EyeSlash, Info, FloppyDisk } from './icons';
import { useCopyToClipboard } from './clipboard';

/* ────────────────────────────────────────────────────────────────
 * CardData - the JSON blob stored in the note body for card-type
 * notes. The note's `title` field serves as the display name
 * (e.g. "Visa ending in 4242") and is auto-derived from the card
 * number when empty.
 * ──────────────────────────────────────────────────────────────── */
export interface CardData {
  cardholderName: string;
  cardNumber: string;
  expMonth: string;
  expYear: string;
  cvv: string;
  billingZip: string;
  notes: string;
}

export function parseCardBody(body: string): CardData {
  try {
    const p = JSON.parse(body);
    return {
      cardholderName: typeof p.cardholderName === 'string' ? p.cardholderName : '',
      cardNumber: typeof p.cardNumber === 'string' ? p.cardNumber : '',
      expMonth: typeof p.expMonth === 'string' ? p.expMonth : '',
      expYear: typeof p.expYear === 'string' ? p.expYear : '',
      cvv: typeof p.cvv === 'string' ? p.cvv : '',
      billingZip: typeof p.billingZip === 'string' ? p.billingZip : '',
      notes: typeof p.notes === 'string' ? p.notes : '',
    };
  } catch {
    return { cardholderName: '', cardNumber: '', expMonth: '', expYear: '', cvv: '', billingZip: '', notes: '' };
  }
}

export function serializeCardBody(data: CardData): string {
  return JSON.stringify(data);
}

/** Detect card network from the first digits (BIN). */
export function detectCardNetwork(num: string): string {
  const d = num.replace(/\D/g, '');
  if (!d) return '';
  const n2 = Number(d.slice(0, 2));
  const n4 = Number(d.slice(0, 4));
  const n6 = Number(d.slice(0, 6));
  if (d.startsWith('4')) return 'Visa';
  if ((n2 >= 51 && n2 <= 55) || (n6 >= 222100 && n6 <= 272099)) return 'Mastercard';
  if (n2 === 34 || n2 === 37) return 'Amex';
  if (n2 === 36 || (n2 >= 38 && n2 <= 39) || (n4 >= 3000 && n4 <= 3059) || (n4 >= 3095 && n4 <= 3095) || (n4 >= 3600 && n4 <= 3699)) return 'Diners';
  if (n4 >= 6011 || n2 === 65 || (n6 >= 644000 && n6 <= 649999)) return 'Discover';
  if (n4 >= 3528 && n4 <= 3589) return 'JCB';
  return '';
}

/** Max digit length by network: 15 for Amex, 16 for all others. */
function maxDigitsForNetwork(digits: string): number {
  const n2 = Number(digits.slice(0, 2));
  return (n2 === 34 || n2 === 37) ? 15 : 16;
}

/** Format card number with spaces every 4 digits. */
function formatCardNumber(raw: string): string {
  const d = raw.replace(/\D/g, '');
  return d.replace(/(.{4})/g, '$1 ').trim();
}

/** Derive a display title like "Visa ending in 4242". */
function deriveCardTitle(data: CardData): string {
  const digits = data.cardNumber.replace(/\D/g, '');
  if (digits.length < 4) return '';
  const last4 = digits.slice(-4);
  const network = detectCardNetwork(digits);
  return network ? `${network} ending in ${last4}` : `Card ending in ${last4}`;
}

/* ────────────────────────────────────────────────────────────────
 * Copy button (shared)
 * ──────────────────────────────────────────────────────────────── */
function CopyBtn({ onClick, active, title }: { onClick: () => void; active: boolean; title: string }) {
  return (
    <HoverLabel label={title} position="start">
      <button type="button" onClick={onClick} aria-label={title} className="shrink-0 rounded-md p-2 text-neutral-400 hover:text-accent hover:bg-neutral-100 dark:hover:bg-surface-0 transition">
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
 * CardForm - the editor replacement for card-type notes.
 * ──────────────────────────────────────────────────────────────── */
interface CardFormProps {
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
}

export function CardForm({
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
}: CardFormProps) {
  const { t } = useTranslation('common');
  const data = parseCardBody(body);
  const { copy, copied } = useCopyToClipboard();
  const pinConfigured = useMemo(() => hasPin(), []);
  const [showPinInfo, setShowPinInfo] = useState(false);
  const [showNumber, setShowNumber] = useState(false);
  const [numberFocused, setNumberFocused] = useState(false);
  const [showCvv, setShowCvv] = useState(false);

  const updateBody = useCallback(
    (patch: Partial<CardData>) => {
      const next = { ...data, ...patch };
      onBodyChange(noteId, serializeCardBody(next));
    },
    [noteId, data, onBodyChange]
  );

  /** Auto-derive title from card number on blur. */
  const handleNumberBlur = useCallback(() => {
    if (!title.trim()) {
      const derived = deriveCardTitle(data);
      if (derived) onTitleChange(noteId, derived);
    }
  }, [noteId, title, data, onTitleChange]);

  /** Soft expired-card hint - informational, not blocking. */
  const isExpired = (() => {
    if (!data.expMonth || !data.expYear) return false;
    const now = new Date();
    const expYearFull = 2000 + Number(data.expYear);
    const expMonth = Number(data.expMonth);
    // Card expires at end of its expiry month.
    if (expYearFull < now.getFullYear()) return true;
    if (expYearFull === now.getFullYear() && expMonth < now.getMonth() + 1) return true;
    return false;
  })();

  const fieldClass =
    'w-full rounded-md border border-divider bg-surface-1 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-60';
  const labelClass = 'block text-xs font-medium text-neutral-500 dark:text-neutral-400 mb-1';

  const maskedNumber = data.cardNumber.replace(/\D/g, '').length > 4
    ? '•••• '.repeat(Math.floor((data.cardNumber.replace(/\D/g, '').length - 4) / 4)) +
      (data.cardNumber.replace(/\D/g, '').length % 4 > 0 && data.cardNumber.replace(/\D/g, '').length > 4
        ? '•'.repeat((data.cardNumber.replace(/\D/g, '').length - 4) % 4) + ' '
        : '') +
      data.cardNumber.replace(/\D/g, '').slice(-4)
    : data.cardNumber;

  return (
    /* Width comes from VAULT_COLUMN on the VaultItem wrapper. */
    <div className="flex-1 overflow-y-auto p-6">
      <div className="space-y-4">
        {/* Cardholder Name */}
        <div>
          <label className={labelClass}>{t('cardForm.cardholderName')}</label>
          <input
            type="text"
            value={data.cardholderName}
            onChange={(e) => updateBody({ cardholderName: e.target.value.replace(/[0-9]/g, '') })}
            placeholder={t('cardForm.cardholderPlaceholder')}
            disabled={locked}
            autoComplete="off"
            className={fieldClass}
          />
        </div>

        {/* Card Number */}
        <div>
          <label className={labelClass}>{t('cardForm.cardNumber')}</label>
          <div className="flex gap-1.5">
            <div className="relative flex-1">
              <input
                type="text"
                value={showNumber || numberFocused ? formatCardNumber(data.cardNumber) : maskedNumber}
                onChange={(e) => {
                  const raw = e.target.value.replace(/\D/g, '');
                  const max = maxDigitsForNetwork(raw);
                  updateBody({ cardNumber: raw.slice(0, max) });
                }}
                onFocus={() => setNumberFocused(true)}
                onBlur={() => { setNumberFocused(false); handleNumberBlur(); }}
                placeholder={t('cardForm.cardNumberPlaceholder')}
                disabled={locked}
                autoComplete="off"
                inputMode="numeric"
                className={`${fieldClass} font-mono pe-10`}
              />
              <div className="absolute end-1 top-1/2 -translate-y-1/2">
              <HoverLabel label={showNumber ? t('cardForm.hideNumber') : t('cardForm.showNumber')} position="above">
              <button
                type="button"
                onClick={() => setShowNumber(!showNumber)}
                aria-label={showNumber ? t('cardForm.hideNumber') : t('cardForm.showNumber')}
                className="rounded p-1 text-neutral-400 hover:text-accent transition"
              >
                {showNumber ? (
                  <EyeSlash size={16} />
                ) : (
                  <Eye size={16} />
                )}
              </button>
              </HoverLabel>
              </div>
            </div>
            <CopyBtn
              onClick={() => copy(data.cardNumber, 'number')}
              active={copied === 'number'}
              title={t('cardForm.copyCardNumber')}
            />
          </div>
          {data.cardNumber && (() => {
            const digits = data.cardNumber.replace(/\D/g, '');
            const network = detectCardNetwork(data.cardNumber);
            const tooShort = digits.length > 0 && digits.length < 13;
            return (
              <>
                <div className="mt-1 text-xs text-neutral-400">
                  {network || t('cardForm.unknownNetwork')}
                </div>
                {tooShort && (
                  <div className="mt-0.5 text-[11px] text-amber-600 dark:text-amber-400">
                    {t('cardForm.numberTooShort', { count: digits.length, expected: maxDigitsForNetwork(digits) })}
                  </div>
                )}
              </>
            );
          })()}
        </div>

        {/* Expiry + CVV row */}
        <div className="flex gap-3">
          <div className="flex-1">
            <label className={labelClass}>{t('cardForm.expiry')}</label>
            <div className="flex gap-1.5">
              <select
                value={data.expMonth}
                onChange={(e) => updateBody({ expMonth: e.target.value })}
                disabled={locked}
                className={`${fieldClass} appearance-none`}
              >
                <option value="">{t('cardForm.monthPlaceholder')}</option>
                {Array.from({ length: 12 }, (_, i) => {
                  const m = String(i + 1).padStart(2, '0');
                  return <option key={m} value={m}>{m}</option>;
                })}
              </select>
              <select
                value={data.expYear}
                onChange={(e) => updateBody({ expYear: e.target.value })}
                disabled={locked}
                className={`${fieldClass} appearance-none`}
              >
                <option value="">{t('cardForm.yearPlaceholder')}</option>
                {Array.from({ length: 12 }, (_, i) => {
                  const y = String(new Date().getFullYear() + i).slice(-2);
                  return <option key={y} value={y}>{y}</option>;
                })}
              </select>
            </div>
          </div>
          <div className="w-28">
            <label className={labelClass}>{t('cardForm.cvv')}</label>
            <div className="flex gap-1.5">
              <input
                type={showCvv ? 'text' : 'password'}
                value={data.cvv}
                onChange={(e) => updateBody({ cvv: e.target.value.replace(/\D/g, '').slice(0, 4) })}
                placeholder={t('cardForm.cvvPlaceholder')}
                disabled={locked}
                autoComplete="off"
                inputMode="numeric"
                maxLength={4}
                className={`${fieldClass} font-mono`}
              />
              <HoverLabel label={showCvv ? t('cardForm.hideCvv') : t('cardForm.showCvv')} position="above">
              <button
                type="button"
                onClick={() => setShowCvv(!showCvv)}
                aria-label={showCvv ? t('cardForm.hideCvv') : t('cardForm.showCvv')}
                className="shrink-0 rounded-md p-2 text-neutral-400 hover:text-accent transition"
              >
                {showCvv ? (
                  <EyeSlash size={16} />
                ) : (
                  <Eye size={16} />
                )}
              </button>
              </HoverLabel>
            </div>
          </div>
        </div>

        {isExpired && (
          <p className="text-[11px] text-amber-600 dark:text-amber-400 -mt-2">{t('cardForm.expiredHint')}</p>
        )}

        {/* Billing Zip */}
        <div>
          <label className={labelClass}>{t('cardForm.billingZip')}</label>
          <input
            type="text"
            value={data.billingZip}
            onChange={(e) => updateBody({ billingZip: e.target.value })}
            placeholder={t('cardForm.billingZipPlaceholder')}
            disabled={locked}
            autoComplete="off"
            className={fieldClass}
          />
        </div>

        {/* Notes */}
        <div>
          <label className={labelClass}>{t('cardForm.notes')}</label>
          <textarea
            value={data.notes}
            onChange={(e) => updateBody({ notes: e.target.value })}
            placeholder={t('cardForm.notesPlaceholder')}
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
            {t('cardForm.requirePin')}
          </span>
          <button
            type="button"
            onClick={(e) => { e.preventDefault(); setShowPinInfo(true); }}
            className="text-accent/60 hover:text-accent transition p-1 -m-1"
            aria-label={t('cardForm.whatDoesThisDo')}
          >
            <Info />
          </button>
        </label>

        {showPinInfo && <PinInfoModal onClose={() => setShowPinInfo(false)} />}
        {!pinConfigured && !pinProtected && (
          <p className="text-[11px] text-neutral-400 dark:text-neutral-500 -mt-2">
            {t('cardForm.setUpPinFirst')}
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
                {t('actions.cancel')}
              </button>
            )}
            <button
              type="button"
              onClick={onSave}
              className="flex-1 inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-md text-sm font-medium bg-accent text-white hover:bg-accent-hover transition"
            >
              <FloppyDisk />
              {t('actions.save')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
