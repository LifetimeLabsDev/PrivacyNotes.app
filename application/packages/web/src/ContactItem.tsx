import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import {
  buildContactBody,
  contactDisplayName,
  contactFullName,
  contactInitialsFor,
  formatAddressLines,
  formatContactDate,
  parseContactBody,
  smsHref,
  telHref,
  type Contact,
  type ContactLabelled,
  BIRTHDAY_LABEL,
} from './contactBody';
import { ContactForm, withTrailingBlank } from './ContactForm';
import { ContactChip } from './NoteRow';
import { useCopyToClipboard } from './clipboard';
import { openExternal } from './openExternal';
import { activeLocale } from './languages';
import { HoverLabel } from './HoverLabel';
import { ArrowSquareOut, At, Cake, Calendar, CaretDown, ChatCircle, EnvelopeSimple, Globe, MapPin, Phone, User, Users, X } from './icons';
import { DETAIL_COLUMN, DETAIL_TILE_PX, DetailAction, DetailCopyAction, DetailGroup, DetailHero, DetailLink, DetailNotes, DetailRow } from './detailPane';
import { loadEncryptedImageUrl } from './EncryptedImage';
import { useEscapeToClose } from './useEscapeToClose';


/** A stored contact with nothing in it: the New state. */
function isContactEmpty(c: Contact): boolean {
  return (
    !contactFullName(c) &&
    !c.nickname.trim() &&
    !c.org.trim() &&
    !c.jobTitle.trim() &&
    c.phones.length === 0 &&
    c.emails.length === 0 &&
    c.addresses.length === 0 &&
    c.urls.length === 0 &&
    c.profiles.length === 0 &&
    c.dates.length === 0 &&
    c.related.length === 0 &&
    !c.notes.trim() &&
    c.extras.length === 0
  );
}

/** The form's draft: the stored contact plus the blank row each repeating group keeps. */
function toDraft(c: Contact): Contact {
  return {
    ...c,
    phones: withTrailingBlank(c.phones, 'mobile'),
    emails: withTrailingBlank(c.emails, 'home'),
    urls: c.urls.length ? withTrailingBlank(c.urls, 'homepage') : [],
    profiles: c.profiles.length ? withTrailingBlank(c.profiles, '') : [],
    dates: c.dates.length ? withTrailingBlank(c.dates, 'other') : [],
    related: c.related.length ? withTrailingBlank(c.related, 'other') : [],
  };
}

/**
 * The contact body, seated under the STANDARD note header exactly like
 * VaultItem: the header owns title, pin, share, trash and the options
 * menu, the shared tag line owns folder and tags, and this component owns
 * what a contact is. One pane, two states: in view a phone number is a
 * call button, and editing is a mode entered from the Edit button, which
 * is what stops a mistyped tap from opening the editor instead of the
 * dialer. New is edit with everything empty.
 *
 * Edits are buffered in a draft and written on Done, the vault's contract;
 * Cancel drops them. The title is not buffered: the header's title field is
 * the display name and writes live, and Done fills it in from the name
 * fields only while it is empty or still equal to the last derived name.
 *
 * Spec: ops/docs/plans/contacts-pillar.md (section 6)
 */
export function ContactItem({
  note,
  isTrash,
  onDraftName,
  onTitleChange,
  onBodyChange,
  onPinProtectedChange,
}: {
  note: LocalNote;
  isTrash: boolean;
  /** The name the draft spells, reported on every keystroke so the header can
   *  show it while it is typed. '' whenever the form is not open. */
  onDraftName: (name: string) => void;
  onTitleChange: (id: string, title: string) => void;
  onBodyChange: (id: string, body: string) => void;
  onPinProtectedChange: (id: string, value: boolean) => void;
}) {
  const { t } = useTranslation('shell');
  const saved = useMemo(() => parseContactBody(note.body), [note.body]);
  const isNew = isContactEmpty(saved);
  const [editing, setEditing] = useState(isNew);
  const [draft, setDraft] = useState<Contact>(() => toDraft(saved));
  const [draftPinProtected, setDraftPinProtected] = useState(note.pinProtected === 1);
  const [saveError, setSaveError] = useState('');

  // A remote edit lands in the draft only while nobody is typing into it.
  useEffect(() => {
    if (!editing) {
      setDraft(toDraft(saved));
      setDraftPinProtected(note.pinProtected === 1);
    }
  }, [saved, note.pinProtected, editing]);

  // Hand the header the name being typed, so it appears at the top as the name
  // fields are filled in. A REPORT, never a write: the draft is buffered and
  // Cancel drops it, so a title stored from a keystroke would outlive the edit
  // that spelled it. The header shows it in grey, and Done makes it the title.
  useEffect(() => {
    onDraftName(editing ? contactDisplayName('', draft) : '');
  }, [draft, editing, onDraftName]);

  // Leaving the contact takes the reported name with it, so the next note in
  // the pane cannot inherit a name that was typed into this one.
  useEffect(() => () => onDraftName(''), [onDraftName]);

  // A note switch resets everything: the component is keyed by note id in
  // NoteEditorPane, so this covers a same-id refresh too.
  useEffect(() => {
    const c = parseContactBody(note.body);
    setEditing(isContactEmpty(c));
    setDraft(toDraft(c));
    setDraftPinProtected(note.pinProtected === 1);
    setSaveError('');
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [note.id]);

  const locked = isTrash || note.locked === 1;

  const handleSave = useCallback(() => {
    const body = buildContactBody(draft);
    const next = parseContactBody(body);
    if (isContactEmpty(next)) {
      setSaveError(t('contacts.fillOne'));
      return;
    }
    setSaveError('');
    onBodyChange(note.id, body);
    // The display name follows the name fields until the user names the
    // contact by hand in the header.
    const derivedBefore = contactDisplayName('', saved);
    if (!note.title.trim() || note.title.trim() === derivedBefore) {
      const derived = contactDisplayName('', next);
      if (derived && derived !== note.title) onTitleChange(note.id, derived);
    }
    if (draftPinProtected !== (note.pinProtected === 1)) {
      onPinProtectedChange(note.id, draftPinProtected);
    }
    setEditing(false);
  }, [draft, draftPinProtected, note.id, note.title, note.pinProtected, saved, onBodyChange, onTitleChange, onPinProtectedChange, t]);

  const handleCancel = useCallback(() => {
    setDraft(toDraft(saved));
    setDraftPinProtected(note.pinProtected === 1);
    setSaveError('');
    setEditing(false);
  }, [saved, note.pinProtected]);

  const handleEdit = useCallback(() => {
    setDraft(toDraft(saved));
    setDraftPinProtected(note.pinProtected === 1);
    setEditing(true);
  }, [saved, note.pinProtected]);

  if (!editing && !isNew) {
    return (
      <div className={`flex-1 overflow-y-auto p-6 ${DETAIL_COLUMN}`}>
        <ContactView note={note} contact={saved} locked={locked} onEdit={handleEdit} />
      </div>
    );
  }

  return (
    <div className={`flex-1 flex flex-col min-h-0 ${DETAIL_COLUMN}`}>
      <ContactForm
        noteId={note.id}
        title={contactDisplayName(note.title, draft)}
        draft={draft}
        onDraftChange={setDraft}
        locked={locked}
        pinProtected={draftPinProtected}
        onPinProtectedChange={setDraftPinProtected}
        onSave={handleSave}
        onCancel={handleCancel}
        isNew={isNew}
        saveError={saveError}
      />
    </div>
  );
}

/** The address a website or profile value opens, or null when it is not a web address. */
function webHref(value: string): string | null {
  const v = value.trim();
  if (/^https?:\/\//i.test(v)) return v;
  if (/^www\./i.test(v)) return `https://${v}`;
  return null;
}

/**
 * The photo at its stored size, in the panel every dialog shares: the header
 * row carries the name and the standard close button, and the picture sits
 * flush under it with no frame. The picture is never scaled up: a small
 * photo shows small, centred with some room around it.
 */
function ContactPhotoLightbox({ photo, name, onClose }: { photo: string; name: string; onClose: () => void }) {
  const { t } = useTranslation('common');
  useEscapeToClose(onClose);
  // Same two shapes the chip reads: a stored blob, or the static path the
  // seeded contact carries.
  const staticSrc = photo.startsWith('/') ? photo : '';
  const uuid = photo.startsWith('pn:img/') ? photo.slice('pn:img/'.length) : '';
  const [url, setUrl] = useState<string | null>(null);
  const [small, setSmall] = useState(false);
  useEffect(() => {
    if (!uuid) { setUrl(null); return; }
    let alive = true;
    void loadEncryptedImageUrl(uuid).then((u) => { if (alive) setUrl(u); });
    return () => { alive = false; };
  }, [uuid]);
  return (
    <div
      className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 sm:p-6 z-50"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label={name}
    >
      <div
        className="bg-surface-2 border border-divider text-pn rounded-lg overflow-hidden min-w-[14rem] max-w-[calc(100vw-2rem)]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-divider">
          <h2 className="text-sm font-semibold truncate" dir="auto">{name}</h2>
          <button
            type="button"
            onClick={onClose}
            className="shrink-0 text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1"
            aria-label={t('actions.close')}
          >
            <X size={18} />
          </button>
        </div>
        <div className={`flex justify-center ${small ? 'p-6' : ''}`}>
          {staticSrc || url ? (
            <img
              src={staticSrc || url!}
              alt={name}
              onLoad={(e) => setSmall(e.currentTarget.naturalWidth < 200)}
              className="block max-w-full max-h-[75vh]"
              draggable={false}
            />
          ) : (
            <div className="w-56 h-56 bg-surface-1" />
          )}
        </div>
      </div>
    </div>
  );
}

function ContactView({ note, contact, locked, onEdit }: {
  note: LocalNote;
  contact: Contact;
  locked: boolean;
  onEdit: () => void;
}) {
  const { t } = useTranslation('shell');
  const { copy, copied } = useCopyToClipboard();
  const [extrasOpen, setExtrasOpen] = useState(false);
  const [photoOpen, setPhotoOpen] = useState(false);
  const locale = activeLocale();
  const name = contactDisplayName(note.title, contact) || t('contacts.unnamed');
  const subtitle = [contact.jobTitle.trim(), contact.org.trim()].filter(Boolean).join(', ');
  const labelText = (label: string) => (label ? t(`contacts.labels.${label}`, { defaultValue: label }) : '');

  const copyAction = (value: string, key: string) => (
    <DetailCopyAction value={value} id={key} copied={copied} onCopy={copy} label={t('common:actions.copy')} />
  );

  const group = (heading: string, rows: React.ReactNode) => <DetailGroup heading={heading}>{rows}</DetailGroup>;

  const textRows = (rows: ContactLabelled[], keyPrefix: string, icon: React.ReactNode) =>
    rows.map((r, i) => (
      <DetailRow key={`${keyPrefix}${i}`} icon={icon} label={labelText(r.label)} actions={copyAction(r.value, `${keyPrefix}${i}`)}>
        {r.value}
      </DetailRow>
    ));

  const nameRows: React.ReactNode[] = [];
  if (contact.nickname.trim()) nameRows.push(<DetailRow key="nick" icon={<User size={13} />} label={t('contacts.nickname')}>{contact.nickname}</DetailRow>);
  const phonetic = [contact.phonetic.first, contact.phonetic.middle, contact.phonetic.last].map((s) => s.trim()).filter(Boolean).join(' ');
  if (phonetic) nameRows.push(<DetailRow key="phon" icon={<User size={13} />} label={t('contacts.itemPhonetic')}>{phonetic}</DetailRow>);
  const full = contactFullName(contact);
  if (full && full !== name) nameRows.push(<DetailRow key="full" icon={<User size={13} />} label={t('contacts.groupName')}>{full}</DetailRow>);
  if (contact.department.trim()) nameRows.push(<DetailRow key="dept" icon={<User size={13} />} label={t('contacts.department')}>{contact.department}</DetailRow>);

  return (
    <div>
      {/* Hero: the chip the row draws, the name, the job and the company. */}
      <DetailHero
        tile={contact.photo ? (
          <HoverLabel label={t('contacts.showPhoto')} position="end">
            <button
              type="button"
              onClick={() => setPhotoOpen(true)}
              aria-label={t('contacts.showPhoto')}
              className="shrink-0 rounded-full hover:opacity-90 focus-visible:outline-2 focus-visible:outline-accent transition"
            >
              <ContactChip name={name} initials={contactInitialsFor(note.title, contact)} photo={contact.photo} size={DETAIL_TILE_PX} />
            </button>
          </HoverLabel>
        ) : (
          <ContactChip name={name} initials={contactInitialsFor(note.title, contact)} photo={contact.photo} size={DETAIL_TILE_PX} />
        )}
        title={name}
        subtitle={subtitle ? <div className="text-sm text-neutral-500 dark:text-neutral-400 truncate" dir="auto">{subtitle}</div> : undefined}
        onEdit={locked ? undefined : onEdit}
        editLabel={t('common:actions.edit')}
      />
      {photoOpen && contact.photo && (
        <ContactPhotoLightbox photo={contact.photo} name={name} onClose={() => setPhotoOpen(false)} />
      )}

      {contact.phones.length > 0 && group(t('contacts.groupPhone'), contact.phones.map((p, i) => (
        <DetailRow
          key={`ph${i}`}
          icon={<Phone size={13} />}
          label={labelText(p.label)}
          actions={
            <>
              <DetailAction label={t('contacts.call')} href={telHref(p.value)}><Phone size={15} /></DetailAction>
              <DetailAction label={t('contacts.message')} href={smsHref(p.value)}><ChatCircle size={15} /></DetailAction>
              {copyAction(p.value, `ph${i}`)}
            </>
          }
        >
          {/* The number itself dials: tapping it must call, never edit. */}
          <a href={telHref(p.value)} className="text-accent hover:underline" dir="ltr">{p.value}</a>
        </DetailRow>
      )))}

      {contact.emails.length > 0 && group(t('contacts.groupEmail'), contact.emails.map((e, i) => (
        <DetailRow
          key={`em${i}`}
          icon={<EnvelopeSimple size={13} />}
          label={labelText(e.label)}
          actions={
            <>
              <DetailAction label={t('contacts.sendEmail')} href={`mailto:${e.value}`}><EnvelopeSimple size={15} /></DetailAction>
              {copyAction(e.value, `em${i}`)}
            </>
          }
        >
          <a href={`mailto:${e.value}`} className="text-accent hover:underline break-all" dir="ltr">{e.value}</a>
        </DetailRow>
      )))}

      {contact.addresses.length > 0 && group(t('contacts.groupAddress'), contact.addresses.map((a, i) => {
        const lines = formatAddressLines(a);
        return (
          <DetailRow key={`ad${i}`} icon={<MapPin size={13} />} label={labelText(a.label)} multiline actions={copyAction(lines.join('\n'), `ad${i}`)}>
            <span className="whitespace-pre-line">{lines.join('\n')}</span>
          </DetailRow>
        );
      }))}

      {contact.urls.length > 0 && group(t('contacts.groupWebsite'), contact.urls.map((u, i) => {
        const href = webHref(u.value) ?? `https://${u.value.trim()}`;
        return (
          <DetailRow
            key={`url${i}`}
            icon={<Globe size={13} />}
            label={labelText(u.label)}
            actions={
              <>
                <DetailAction label={t('contacts.open')} onClick={() => openExternal(href)}><ArrowSquareOut size={15} /></DetailAction>
                {copyAction(u.value, `url${i}`)}
              </>
            }
          >
            <DetailLink href={href}>{u.value}</DetailLink>
          </DetailRow>
        );
      }))}

      {contact.profiles.length > 0 && group(t('contacts.groupProfile'), contact.profiles.map((p, i) => {
        const href = webHref(p.value);
        return (
          <DetailRow
            key={`pr${i}`}
            icon={<At size={13} />}
            label={labelText(p.label)}
            actions={
              <>
                {href && <DetailAction label={t('contacts.open')} onClick={() => openExternal(href)}><ArrowSquareOut size={15} /></DetailAction>}
                {copyAction(p.value, `pr${i}`)}
              </>
            }
          >
            {href ? <DetailLink href={href}>{p.value}</DetailLink> : <span className="break-all" dir="ltr">{p.value}</span>}
          </DetailRow>
        );
      }))}

      {contact.dates.length > 0 && group(t('contacts.groupDates'), contact.dates.map((d, i) => (
        <DetailRow key={`dt${i}`} icon={d.label === BIRTHDAY_LABEL ? <Cake size={13} /> : <Calendar size={13} />} label={labelText(d.label)}>{formatContactDate(d.value, locale)}</DetailRow>
      )))}

      {contact.related.length > 0 && group(t('contacts.groupRelated'), textRows(contact.related, 'rel', <Users size={13} />))}

      {nameRows.length > 0 && group(t('contacts.groupName'), nameRows)}

      {contact.notes.trim() && <DetailNotes heading={t('contacts.groupNote')}>{contact.notes}</DetailNotes>}

      {contact.extras.length > 0 && (
        <div className="mt-5 rounded-md border border-divider">
          <button
            type="button"
            onClick={() => setExtrasOpen((v) => !v)}
            aria-expanded={extrasOpen}
            className="w-full flex items-center gap-2 px-3 py-2 text-[13px] text-neutral-600 dark:text-neutral-300"
          >
            <CaretDown size={12} className={`shrink-0 transition-transform ${extrasOpen ? '' : '-rotate-90'}`} aria-hidden="true" />
            {t('contacts.alsoInFile')}
            <span className="ms-auto text-xs text-neutral-400">{t('contacts.extrasCount', { count: contact.extras.length })}</span>
          </button>
          {extrasOpen && (
            <div className="px-3 pb-3 flex flex-col gap-1">
              {contact.extras.map((x, i) => (
                <div key={i} className="flex gap-3 text-xs">
                  <span className="shrink-0 w-36 truncate font-mono text-neutral-500 dark:text-neutral-400" dir="ltr">{x.name}</span>
                  <span className="min-w-0 break-all text-neutral-700 dark:text-neutral-300" dir="auto">{x.value}</span>
                </div>
              ))}
              <p className="mt-1 text-[11px] text-neutral-400 dark:text-neutral-500">{t('contacts.extrasNote')}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
