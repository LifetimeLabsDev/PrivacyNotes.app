import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { NoteType } from '@notes/shared';
import { Eye, EyeSlash } from './icons';
import type { NoteVersion } from './noteVersions';
import { vaultContent, type VaultField } from './vaultFields';
import { DetailAction, DetailCopyAction, DetailRow } from './detailPane';
import { useCopyToClipboard } from './clipboard';

/** A vault version as rows. Keyed by version, so a reveal never carries
 *  over to another version. */
export function VaultVersionPreview({ version, type }: { version: NoteVersion; type: NoteType }) {
  const { t } = useTranslation('billing');
  const content = vaultContent({
    type,
    body: version.body,
    trackers: version.login ? { login: version.login } : undefined,
  });
  const rows: VaultField[] = content ? [...content.fields] : [];
  if (content?.notes) rows.push({ label: content.notesLabel, value: content.notes, secret: true });
  return (
    <div>
      {rows.length === 0 ? (
        <div className="text-neutral-400 italic">{t('history.emptyBody')}</div>
      ) : (
        rows.map((row, i) => <VaultVersionRow key={i} row={row} id={`row-${i}`} />)
      )}
      {type === 'login' && version.login === undefined && (
        <p className="mt-3 text-[12px] text-neutral-500">{t('history.loginExtrasNotRecorded')}</p>
      )}
    </div>
  );
}

function VaultVersionRow({ row, id }: { row: VaultField; id: string }) {
  const { t } = useTranslation('shell');
  const { copy, copied } = useCopyToClipboard();
  const [shown, setShown] = useState(false);
  const masked = row.secret && !shown;
  return (
    <DetailRow
      label={row.label}
      multiline
      actions={
        <>
          {row.secret && (
            <DetailAction label={shown ? t('vaultItem.hide') : t('vaultItem.reveal')} onClick={() => setShown(!shown)}>
              {shown ? <EyeSlash size={15} /> : <Eye size={15} />}
            </DetailAction>
          )}
          <DetailCopyAction
            value={row.value}
            id={id}
            copied={copied}
            onCopy={copy}
            label={copied === id ? t('vaultItem.copied') : t('vaultItem.copyField', { label: row.label })}
          />
        </>
      }
    >
      {masked ? (
        <span dir="ltr" className="font-mono tracking-wider" /* rtl-ok: a mask, symbols only */>••••••••</span>
      ) : (
        <span dir={row.mono ? 'ltr' : 'auto'} className={`whitespace-pre-wrap break-all ${row.mono ? 'font-mono text-xs' : ''}`} /* rtl-ok: a key keeps its character order */>
          {row.value}
        </span>
      )}
    </DetailRow>
  );
}
