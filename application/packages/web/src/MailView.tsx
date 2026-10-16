/**
 * A saved email (.eml) as text: in the shared viewer, and as the card of a
 * Files note that holds one. The mail is parsed on the device from its stored
 * bytes and drawn as React text, so nothing in it runs and nothing loads: a
 * remote image or a tracking pixel never reaches the network.
 * Spec: ops/issues/0522.md
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { File } from './icons';
import { loadAttachmentData } from './EncryptedAttachment';
import { parseEml, type ParsedMail } from './mailParse';
import { formatInstant } from './intlFormat';
import { formatBytes } from './formatBytes';

/** One parse per stored file for the session, shared by the card and the viewer. */
const parsed = new Map<string, Promise<ParsedMail | null>>();

function loadMail(uuid: string): Promise<ParsedMail | null> {
  let p = parsed.get(uuid);
  if (!p) {
    p = loadAttachmentData(uuid).then((att) => (att ? parseEml(new Uint8Array(att.data)) : null)).catch(() => null);
    parsed.set(uuid, p);
    // A failure is not kept, so the next open tries again.
    void p.then((m) => { if (!m) parsed.delete(uuid); });
  }
  return p;
}

function useMail(uuid: string): ParsedMail | null | 'loading' {
  const [mail, setMail] = useState<ParsedMail | null | 'loading'>('loading');
  useEffect(() => {
    let alive = true;
    setMail('loading');
    void loadMail(uuid).then((m) => { if (alive) setMail(m); });
    return () => { alive = false; };
  }, [uuid]);
  return mail;
}

/** The mail in the viewer: the header lines, the text, the attachment names. */
export function MailView({ uuid }: { uuid: string }) {
  const { t } = useTranslation('media');
  const mail = useMail(uuid);
  if (mail === 'loading' || !mail) {
    return (
      <div data-backdrop="" className="h-full flex items-center justify-center px-6 text-sm text-white/70 text-center">
        {mail === 'loading' ? t('mail.loading') : t('mail.failed')}
      </div>
    );
  }
  const rows: [string, string][] = [
    [t('mail.from'), mail.from],
    [t('mail.to'), mail.to],
    [t('mail.cc'), mail.cc],
    [t('mail.date'), mail.date ? formatInstant(mail.date, 'dateTime') : ''],
  ];
  return (
    <div data-backdrop="" className="h-full overflow-y-auto px-3 sm:px-0">
      <article className="mx-auto max-w-3xl my-2 rounded-lg bg-surface-2 text-pn border border-divider p-5 sm:p-6 select-text">
        <h2 className="text-lg font-semibold break-words" dir="auto">{mail.subject || t('mail.noSubject')}</h2>
        <dl className="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-[13px]">
          {rows.filter(([, v]) => v).map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-pn-muted">{k}</dt>
              <dd className="break-words" dir="auto">{v}</dd>
            </div>
          ))}
        </dl>
        <div className="mt-4 pt-4 border-t border-divider text-sm leading-relaxed whitespace-pre-wrap break-words" dir="auto">
          {mail.text || <span className="text-pn-muted">{t('mail.empty')}</span>}
        </div>
        {mail.attachments.length > 0 && (
          <div className="mt-4 pt-3 border-t border-divider">
            <div className="text-xs text-pn-muted mb-1.5">{t('mail.attachments')}</div>
            <ul className="space-y-1">
              {mail.attachments.map((a, i) => (
                <li key={i} className="flex items-center gap-2 text-[13px]">
                  <File size={14} className="shrink-0 text-pn-muted" aria-hidden="true" />
                  <span className="min-w-0 truncate" dir="auto">{a.name}</span>
                  <span className="shrink-0 text-pn-muted text-[12px]">{formatBytes(a.size)}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </article>
    </div>
  );
}

/** The card of a Files note that holds one mail: who, what, when, and the
 *  first lines. Spans throughout, because this is the content of a button. */
export function MailCover({ uuid }: { uuid: string }) {
  const { t } = useTranslation('media');
  const mail = useMail(uuid);
  if (mail === 'loading' || !mail) {
    return (
      <span className="block px-4 py-10 text-sm text-center text-pn-muted">
        {mail === 'loading' ? t('mail.loading') : t('mail.failed')}
      </span>
    );
  }
  return (
    <span className="block p-4 text-start">
      <span className="block text-sm font-semibold text-pn truncate" dir="auto">{mail.subject || t('mail.noSubject')}</span>
      <span className="flex items-baseline gap-2 mt-0.5 text-[12px] text-pn-muted">
        <span className="min-w-0 truncate" dir="auto">{mail.from}</span>
        {mail.date && <span className="shrink-0 ms-auto">{formatInstant(mail.date, 'row')}</span>}
      </span>
      {mail.text && (
        <span className="block mt-2 text-[13px] text-pn-soft leading-snug line-clamp-4 whitespace-pre-line break-words" dir="auto">
          {mail.text.slice(0, 600)}
        </span>
      )}
    </span>
  );
}
