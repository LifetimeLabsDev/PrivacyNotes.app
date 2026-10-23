import { VaultFieldAction } from './ui/VaultFieldAction';
import { Button } from './ui/Button';
import { VaultFormActions } from './ui/VaultFormActions';
import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Info, Key, Lock, NotePencil, Shield, Tag } from './icons';
import { hasPin } from './pin';
import { PinInfoModal } from './PinInfoModal';
import { useCopyToClipboard } from './clipboard';
import { PasswordField } from './PasswordText';
import { FIELD_CLASS, FieldLabel } from './formFields';
import { storedVaultKeys } from './vaultBody';

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

/** `previous` is the stored body; keys a newer version wrote in it are kept. */
export function serializeSshKeyBody(data: SshKeyData, previous = ''): string {
  return JSON.stringify({ ...storedVaultKeys(previous), ...data });
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
 * it and show a message if it fails. Both keys are written in the
 * OpenSSH formats, the only ones every `ssh` build reads.
 * ──────────────────────────────────────────────────────────────── */

/** The key comment runs to the end of the line, so the label is folded onto one line. An
 *  empty label writes no comment, which is still a valid public key. */
export async function generateEd25519Pair(label: string): Promise<{ privateKey: string; publicKey: string } | null> {
  try {
    const kp = await crypto.subtle.generateKey(
      'Ed25519' as unknown as AlgorithmIdentifier, true, ['sign', 'verify']
    ) as CryptoKeyPair;
    const privRaw = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
    const pubRaw = await crypto.subtle.exportKey('raw', kp.publicKey);

    // OpenSSH public key format: ssh-ed25519 <base64(len+type + len+pubkey)> [comment]
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
    const comment = label.trim().replace(/\s+/g, ' ');
    const publicKey = comment ? `ssh-ed25519 ${pubB64} ${comment}` : `ssh-ed25519 ${pubB64}`;

    // Loaded on use: vaultFields pulls this file onto the boot path.
    const { ed25519SeedFromPkcs8, openSshEd25519PrivateKey } = await import('./sshKeyFile');
    const seed = ed25519SeedFromPkcs8(new Uint8Array(privRaw));
    if (!seed) return null;
    const privateKey = openSshEd25519PrivateKey(seed, pubBytes, comment).trimEnd();

    return { privateKey, publicKey };
  } catch {
    return null;
  }
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
  // Never memoize this. Settings opens over a mounted form, so a PIN
  // can appear or vanish while the toggle below is on screen, and
  // localStorage fires nothing that would refresh a frozen value.
  const pinConfigured = hasPin();
  const [showPinInfo, setShowPinInfo] = useState(false);
  const [showPrivate, setShowPrivate] = useState(false);
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState('');
  const [downloadError, setDownloadError] = useState(false);

  const updateBody = useCallback(
    (patch: Partial<SshKeyData>) => {
      const next = { ...data, ...patch };
      onBodyChange(noteId, serializeSshKeyBody(next, body));
    },
    [noteId, data, body, onBodyChange]
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
    const result = await generateEd25519Pair(data.label);
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
  }, [noteId, title, data.label, onTitleChange, updateBody]);

  const downloadKey = useCallback(async (which: 'private' | 'public') => {
    setDownloadError(false);
    const { downloadSshKey } = await import('./sshKeyFile');
    const saved = await downloadSshKey(which, data);
    if (!saved.ok && saved.reason === 'failed') setDownloadError(true);
  }, [data.privateKey, data.publicKey]);

  const fieldClass = FIELD_CLASS;

  return (
    /* Width comes from VAULT_COLUMN on the VaultItem wrapper. */
    <div className="flex-1 overflow-y-auto p-6">
      <div className="space-y-4">
        {/* Label */}
        <div>
          <FieldLabel icon={<Tag size={13} />}>{t('sshKeyForm.label')}</FieldLabel>
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
          <Button action="generate" onClick={() => void handleGenerate()} disabled={generating}>
            {generating ? 'Generating...' : 'Generate Ed25519 Key Pair'}
          </Button>
        )}
        {genError && (
          <div className="text-xs text-warning">{genError}</div>
        )}

        {/* Public Key */}
        <div>
          <FieldLabel icon={<Key size={13} />}>{t('sshKeyForm.publicKey')}</FieldLabel>
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
            <VaultFieldAction kind="copy"
              onClick={() => copy(data.publicKey, 'publicKey')}
              active={copied === 'publicKey'}
              title={t('sshKeyForm.copyPublicKey')}
            />
            {data.publicKey.trim() && (
              <VaultFieldAction kind="download" onClick={() => void downloadKey('public')} title={t('sshKeyForm.downloadPublicKey')} />
            )}
          </div>
        </div>

        {/* Private Key */}
        <div>
          <FieldLabel icon={<Lock size={13} />}>{t('sshKeyForm.privateKey')}</FieldLabel>
          <div className="flex gap-1.5 items-start">
            <div className="flex-1 min-w-0">
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
                  className={`${fieldClass} font-mono text-xs cursor-pointer min-h-[4rem] flex items-center justify-center text-pn-muted`}
                  onClick={() => setShowPrivate(true)}
                >
                  {data.privateKey ? 'Click to reveal private key' : 'No private key stored'}
                </div>
              )}
            </div>
            {data.privateKey && (
              <VaultFieldAction kind="reveal" active={showPrivate} title={showPrivate ? 'Hide private key' : 'Show private key'} onClick={() => setShowPrivate(!showPrivate)} />
            )}
            <VaultFieldAction kind="copy"
              onClick={() => copy(data.privateKey, 'privateKey')}
              active={copied === 'privateKey'}
              title={t('sshKeyForm.copyPrivateKey')}
            />
            {data.privateKey.trim() && (
              <VaultFieldAction kind="download" onClick={() => void downloadKey('private')} title={t('sshKeyForm.downloadPrivateKey')} />
            )}
          </div>
          {data.privateKey.trim() && (
            <p className="text-[11px] text-pn-muted mt-1.5">{t('sshKeyForm.downloadHint')}</p>
          )}
          {downloadError && (
            <p className="text-[11px] text-danger mt-1.5">{t('sshKeyForm.downloadFailed')}</p>
          )}
        </div>

        {/* Passphrase */}
        <div>
          <FieldLabel icon={<Shield size={13} />}>{t('sshKeyForm.passphrase')}</FieldLabel>
          <div className="flex gap-1.5">
            <PasswordField
              value={data.passphrase}
              onChange={(e) => updateBody({ passphrase: e.target.value })}
              revealed={showPassphrase}
              disabled={locked}
              placeholder={t('sshKeyForm.passphrasePlaceholder')}
              fieldClass={fieldClass}
            />
            <VaultFieldAction kind="reveal" active={showPassphrase} title={showPassphrase ? t('sshKeyForm.hide') : t('sshKeyForm.show')} onClick={() => setShowPassphrase(!showPassphrase)} />
            <VaultFieldAction kind="copy"
              onClick={() => copy(data.passphrase, 'passphrase')}
              active={copied === 'passphrase'}
              title={t('sshKeyForm.copyPassphrase')}
            />
          </div>
        </div>

        {/* Notes */}
        <div>
          <FieldLabel icon={<NotePencil size={13} />}>{t('sshKeyForm.notes')}</FieldLabel>
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
          <span className="text-sm text-pn-muted">
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
          <p className="text-[11px] text-pn-muted -mt-2">
            {t('sshKeyForm.setUpPinFirst')}
          </p>
        )}

        <VaultFormActions locked={locked} isNew={isNew} saveError={saveError} onSave={onSave} onCancel={onCancel} />
      </div>
    </div>
  );
}
