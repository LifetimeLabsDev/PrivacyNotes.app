import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Check, Copy, Eye, EyeSlash, FloppyDisk, Info } from './icons';
import { hasPin } from './pin';
import { PinInfoModal } from './PinInfoModal';
import { HoverLabel } from './HoverLabel';
import { useCopyToClipboard } from './clipboard';

/* ────────────────────────────────────────────────────────────────
 * SshKeyData - the JSON blob stored in the note body for ssh-key
 * type notes. The note's `title` field serves as the display name
 * (e.g. "user@host") and is auto-derived from the key comment.
 * ──────────────────────────────────────────────────────────────── */
export interface SshKeyData {
  label: string;
  privateKey: string;
  publicKey: string;
  passphrase: string;
  notes: string;
}

export function parseSshKeyBody(body: string): SshKeyData {
  try {
    const p = JSON.parse(body);
    return {
      label: typeof p.label === 'string' ? p.label : '',
      privateKey: typeof p.privateKey === 'string' ? p.privateKey : '',
      publicKey: typeof p.publicKey === 'string' ? p.publicKey : '',
      passphrase: typeof p.passphrase === 'string' ? p.passphrase : '',
      notes: typeof p.notes === 'string' ? p.notes : '',
    };
  } catch {
    return { label: '', privateKey: '', publicKey: '', passphrase: '', notes: '' };
  }
}

export function serializeSshKeyBody(data: SshKeyData): string {
  return JSON.stringify(data);
}

/** Extract comment from an SSH public key (the trailing part after the base64). */
function extractKeyComment(pubKey: string): string {
  const parts = pubKey.trim().split(/\s+/);
  return parts.length >= 3 ? parts.slice(2).join(' ') : '';
}

/* ────────────────────────────────────────────────────────────────
 * Ed25519 key pair generation via Web Crypto (or fallback message)
 *
 * Web Crypto doesn't support Ed25519 in all browsers. We attempt
 * it and show a message if it fails. The generated keys are in
 * OpenSSH format for copy-paste convenience.
 * ──────────────────────────────────────────────────────────────── */

async function generateEd25519Pair(): Promise<{ privateKey: string; publicKey: string } | null> {
  try {
    const kp = await crypto.subtle.generateKey(
      'Ed25519' as unknown as AlgorithmIdentifier, true, ['sign', 'verify']
    ) as CryptoKeyPair;
    const privRaw = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
    const pubRaw = await crypto.subtle.exportKey('raw', kp.publicKey);

    // OpenSSH public key format: ssh-ed25519 <base64(len+type + len+pubkey)> generated
    const pubBytes = new Uint8Array(pubRaw);
    const typeStr = 'ssh-ed25519';
    const typeBytes = new TextEncoder().encode(typeStr);
    // Build the wire format: uint32 len + bytes
    const buf = new ArrayBuffer(4 + typeBytes.length + 4 + pubBytes.length);
    const view = new DataView(buf);
    let offset = 0;
    view.setUint32(offset, typeBytes.length); offset += 4;
    new Uint8Array(buf, offset, typeBytes.length).set(typeBytes); offset += typeBytes.length;
    view.setUint32(offset, pubBytes.length); offset += 4;
    new Uint8Array(buf, offset, pubBytes.length).set(pubBytes);
    const pubB64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
    const publicKey = `ssh-ed25519 ${pubB64} generated`;

    // PEM private key (PKCS#8)
    const privB64 = btoa(String.fromCharCode(...new Uint8Array(privRaw)));
    const lines = privB64.match(/.{1,64}/g) ?? [];
    const privateKey = `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----`;

    return { privateKey, publicKey };
  } catch {
    return null;
  }
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
 * SshKeyForm - the editor replacement for ssh-key type notes.
 * ──────────────────────────────────────────────────────────────── */
interface SshKeyFormProps {
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

export function SshKeyForm({
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
}: SshKeyFormProps) {
  const { t } = useTranslation('common');
  const data = parseSshKeyBody(body);
  const { copy, copied } = useCopyToClipboard();
  const pinConfigured = useMemo(() => hasPin(), []);
  const [showPinInfo, setShowPinInfo] = useState(false);
  const [showPrivate, setShowPrivate] = useState(false);
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState('');

  const updateBody = useCallback(
    (patch: Partial<SshKeyData>) => {
      const next = { ...data, ...patch };
      onBodyChange(noteId, serializeSshKeyBody(next));
    },
    [noteId, data, onBodyChange]
  );

  /** Auto-derive title from label on blur. */
  const handleLabelBlur = useCallback(() => {
    if (!title.trim() && data.label.trim()) {
      onTitleChange(noteId, data.label.trim());
    }
  }, [noteId, title, data.label, onTitleChange]);

  /** Auto-derive title from public key comment on blur. */
  const handlePublicKeyBlur = useCallback(() => {
    if (!title.trim() && data.publicKey.trim()) {
      const comment = extractKeyComment(data.publicKey);
      if (comment) onTitleChange(noteId, comment);
    }
  }, [noteId, title, data.publicKey, onTitleChange]);

  const handleGenerate = useCallback(async () => {
    setGenerating(true);
    setGenError('');
    const result = await generateEd25519Pair();
    if (result) {
      updateBody({ privateKey: result.privateKey, publicKey: result.publicKey });
      if (!title.trim()) {
        const comment = extractKeyComment(result.publicKey);
        if (comment) onTitleChange(noteId, comment);
      }
    } else {
      setGenError('Ed25519 not supported in this browser. Paste your keys manually.');
    }
    setGenerating(false);
  }, [noteId, title, onTitleChange, updateBody]);

  const fieldClass =
    'w-full rounded-md border border-divider bg-surface-1 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-60';
  const labelClass = 'block text-xs font-medium text-neutral-500 dark:text-neutral-400 mb-1';

  return (
    /* Width comes from VAULT_COLUMN on the VaultItem wrapper. */
    <div className="flex-1 overflow-y-auto p-6">
      <div className="space-y-4">
        {/* Label */}
        <div>
          <label className={labelClass}>{t('sshKeyForm.label')}</label>
          <input
            type="text"
            value={data.label}
            onChange={(e) => updateBody({ label: e.target.value })}
            onBlur={handleLabelBlur}
            placeholder={t('sshKeyForm.labelPlaceholder')}
            disabled={locked}
            autoComplete="off"
            className={fieldClass}
          />
        </div>

        {/* Generate button */}
        {!locked && (
          <button
            type="button"
            onClick={() => void handleGenerate()}
            disabled={generating}
            className="text-xs px-3 py-1.5 rounded-md bg-accent/10 hover:bg-accent/20 text-accent font-medium transition disabled:opacity-50"
          >
            {generating ? 'Generating...' : 'Generate Ed25519 Key Pair'}
          </button>
        )}
        {genError && (
          <div className="text-xs text-amber-600 dark:text-amber-400">{genError}</div>
        )}

        {/* Public Key */}
        <div>
          <label className={labelClass}>Public Key</label>
          <div className="flex gap-1.5 items-start">
            <textarea
              value={data.publicKey}
              onChange={(e) => updateBody({ publicKey: e.target.value })}
              onBlur={handlePublicKeyBlur}
              placeholder="ssh-ed25519 AAAA..."
              disabled={locked}
              rows={3}
              className={`${fieldClass} font-mono text-xs resize-y`}
            />
            <CopyBtn
              onClick={() => copy(data.publicKey, 'publicKey')}
              active={copied === 'publicKey'}
              title={t('sshKeyForm.copyPublicKey')}
            />
          </div>
        </div>

        {/* Private Key */}
        <div>
          <label className={labelClass}>Private Key</label>
          <div className="flex gap-1.5 items-start">
            <div className="relative flex-1">
              {showPrivate ? (
                <textarea
                  value={data.privateKey}
                  onChange={(e) => updateBody({ privateKey: e.target.value })}
                  disabled={locked}
                  rows={6}
                  className={`${fieldClass} font-mono text-xs resize-y`}
                />
              ) : (
                <div
                  className={`${fieldClass} font-mono text-xs cursor-pointer min-h-[4rem] flex items-center justify-center text-neutral-400`}
                  onClick={() => setShowPrivate(true)}
                >
                  {data.privateKey ? 'Click to reveal private key' : 'No private key stored'}
                </div>
              )}
              {data.privateKey && (
                <div className="absolute end-2 top-2">
                <HoverLabel label={showPrivate ? 'Hide private key' : 'Show private key'} position="above">
                <button
                  type="button"
                  onClick={() => setShowPrivate(!showPrivate)}
                  aria-label={showPrivate ? 'Hide private key' : 'Show private key'}
                  className="rounded p-1 text-neutral-400 hover:text-accent transition"
                >
                  {showPrivate ? (
                    <EyeSlash size={16} />
                  ) : (
                    <Eye size={16} />
                  )}
                </button>
                </HoverLabel>
                </div>
              )}
            </div>
            <CopyBtn
              onClick={() => copy(data.privateKey, 'privateKey')}
              active={copied === 'privateKey'}
              title={t('sshKeyForm.copyPrivateKey')}
            />
          </div>
        </div>

        {/* Passphrase */}
        <div>
          <label className={labelClass}>{t('sshKeyForm.passphrase')}</label>
          <div className="flex gap-1.5">
            <div className="relative flex-1">
              <input
                type={showPassphrase ? 'text' : 'password'}
                value={data.passphrase}
                onChange={(e) => updateBody({ passphrase: e.target.value })}
                placeholder={t('sshKeyForm.passphrasePlaceholder')}
                disabled={locked}
                autoComplete="off"
                className={`${fieldClass} pe-10`}
              />
              <div className="absolute end-1 top-1/2 -translate-y-1/2">
              <HoverLabel label={showPassphrase ? t('sshKeyForm.hide') : t('sshKeyForm.show')} position="above">
              <button
                type="button"
                onClick={() => setShowPassphrase(!showPassphrase)}
                aria-label={showPassphrase ? t('sshKeyForm.hide') : t('sshKeyForm.show')}
                className="rounded p-1 text-neutral-400 hover:text-accent transition"
              >
                {showPassphrase ? (
                  <EyeSlash size={16} />
                ) : (
                  <Eye size={16} />
                )}
              </button>
              </HoverLabel>
              </div>
            </div>
            <CopyBtn
              onClick={() => copy(data.passphrase, 'passphrase')}
              active={copied === 'passphrase'}
              title={t('sshKeyForm.copyPassphrase')}
            />
          </div>
        </div>

        {/* Notes */}
        <div>
          <label className={labelClass}>{t('sshKeyForm.notes')}</label>
          <textarea
            value={data.notes}
            onChange={(e) => updateBody({ notes: e.target.value })}
            placeholder={t('sshKeyForm.notesPlaceholder')}
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
            {t('sshKeyForm.requirePin')}
          </span>
          <button
            type="button"
            onClick={(e) => { e.preventDefault(); setShowPinInfo(true); }}
            className="text-accent/60 hover:text-accent transition p-1 -m-1"
            aria-label={t('sshKeyForm.whatDoesThisDo')}
          >
            <Info />
          </button>
        </label>

        {showPinInfo && <PinInfoModal onClose={() => setShowPinInfo(false)} />}
        {!pinConfigured && !pinProtected && (
          <p className="text-[11px] text-neutral-400 dark:text-neutral-500 -mt-2">
            {t('sshKeyForm.setUpPinFirst')}
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
