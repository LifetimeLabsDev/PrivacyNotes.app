import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Callout, Modal, ModalFooter, ROW_TITLE, SETTINGS_BTN_PRIMARY, SETTINGS_HELP, Switch, TextField } from './ui';
import { Image as ImageIcon, NEW_GLYPHS } from './icons';
import { normalizeUrl } from './linkBody';
import { isImeComposing } from './imeComposing';
import { renderMarkdownSafe } from './markdownRender';
import { formatBytes } from './formatBytes';
import { DEMO_APP_URL } from './demo';
import { withSource } from './campaignSource';
import type { ClipErrorReason } from './clipDownload';
import type { ClipDraft, ClipSource, SavedClip } from './clipPage';
import type { LocalNote } from './db';
import { formatInstant } from './intlFormat';
import { clipLabels, noticeFor, readClipPictures, writeClipPictures, type ClipNotice } from './clipMessages';

/** How many characters of the note the preview renders. */
const PREVIEW_CHARS = 900;

/**
 * Clip page, from the + menu: an address, a preview of the note once the
 * page is downloaded, whether to keep its pictures, and Save. The clip is the
 * page's main text; a bookmark is only the fallback when the page cannot be
 * clipped, and the window saves it then and says so. The preview renders the
 * clip's Markdown through the app's sanitizing renderer with its pictures
 * left out, never the page's own HTML.
 * Spec: ops/docs/archive/web-clipper-stage1.md (section 5.2, D11)
 */
export default function ClipPageModal({
  token,
  onSave,
  onKeepBookmark,
  existingClip,
  onOpenNote,
  onOpenImageSettings,
  initialUrl = '',
  onClose,
}: {
  token: () => Promise<string | null>;
  /** Save the clip and its bookmark. */
  onSave: (url: string, saved: SavedClip) => Promise<void>;
  /** The page could not be clipped: keep it as a bookmark. */
  onKeepBookmark: (url: string) => Promise<void>;
  /** The note this address was clipped into already, if any. */
  existingClip: (url: string) => LocalNote | undefined;
  onOpenNote: (note: LocalNote) => void;
  /** Settings > Storage > Images, linked after the pictures hint. */
  onOpenImageSettings: () => void;
  /** The address to start with, from the quick add. */
  initialUrl?: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(['shell', 'settings']);
  const [address, setAddress] = useState(initialUrl);
  const [invalid, setInvalid] = useState(false);
  const [pictures, setPictures] = useState(readClipPictures);
  const [notice, setNotice] = useState<ClipNotice | null>(null);
  /** The clip failed and the bookmark was kept: only Close is left. */
  const [ended, setEnded] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [source, setSource] = useState<{ url: string; page: ClipSource } | null>(null);
  /** The prepared clip, with or without its pictures. */
  const [draft, setDraft] = useState<{ url: string; pictures: boolean; draft: ClipDraft } | null>(null);
  const [preview, setPreview] = useState('');
  /** The clip has very little text: likely a sign-in, cookie or check page. */
  const [short, setShort] = useState(false);
  /** The address the person committed (Enter, a paste, Save). The window
   *  downloads that one only, never a half-typed address. */
  const [committed, setCommitted] = useState<string | null>(null);
  const run = useRef(0);

  const url = normalizeUrl(address);
  /** A page clipped before is opened, not clipped a second time. */
  const existing = committed && committed === url ? existingClip(committed) : undefined;
  const ready = draft && draft.url === url && draft.pictures === pictures ? draft.draft : null;

  /** The clip cannot be made: say why, and keep the bookmark when asked. */
  async function fallBack(target: string, text: string, keep: boolean) {
    setNotice({ text });
    if (!keep) return;
    await onKeepBookmark(target);
    setEnded(true);
  }

  /** Download the page for the address, once per address. */
  async function load(target: string): Promise<ClipSource | null> {
    if (source?.url === target) return source.page;
    const id = ++run.current;
    setBusy(t('clipper.downloading'));
    setNotice(null);
    setDraft(null);
    try {
      const clip = await import('./clipPage');
      const page = await clip.downloadPage(target, token);
      if (id !== run.current) return null;
      setSource({ url: target, page });
      return page;
    } catch (err) {
      if (id !== run.current) return null;
      const reason = (err as { reason?: ClipErrorReason }).reason ?? 'failed';
      const n = noticeFor(reason);
      if (n.signUp) setNotice(n);
      else await fallBack(target, n.text, reason !== 'limit' && reason !== 'refused');
      return null;
    } finally {
      if (id === run.current) setBusy(null);
    }
  }

  /** The clip of `page`, with its pictures downloaded when they are on. */
  async function prepare(target: string, page: ClipSource, withPictures: boolean): Promise<ClipDraft | null> {
    if (draft && draft.url === target && draft.pictures === withPictures) return draft.draft;
    const id = run.current;
    const clip = await import('./clipPage');
    const found = await clip.clipOf(page, 'main');
    if (id !== run.current) return null;
    if (!found || !(await clip.clipFitsNote(found))) {
      await fallBack(target, t(found ? 'clipper.tooLong' : 'clipper.noMainText'), true);
      return null;
    }
    if (withPictures && found.images.length > 0) {
      setBusy(t('clipper.downloadingPictures', { done: 0, total: Math.min(found.images.length, 20) }));
    }
    const made = await clip.downloadPictures(found, page, token, (done, total) => {
      if (id === run.current) setBusy(t('clipper.downloadingPictures', { done, total }));
    }, withPictures);
    if (id !== run.current) return null;
    setBusy(null);
    setDraft({ url: target, pictures: withPictures, draft: made });
    return made;
  }

  // Download and prepare once an address is committed, and again when the
  // pictures are switched on or off.
  useEffect(() => {
    if (!committed || ended || existingClip(committed)) return;
    let live = true;
    void (async () => {
      const page = await load(committed);
      if (page && live) await prepare(committed, page, pictures);
    })();
    return () => {
      live = false;
    };
    // load and prepare read state they also set; the effect runs on the inputs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [committed, pictures, ended]);

  // The preview: the note as it will start, pictures left out.
  useEffect(() => {
    if (!ready) {
      setPreview('');
      setShort(false);
      return;
    }
    let live = true;
    void import('@notes/clipper').then(({ clipNoteBody, isShortText, placePictures, previewOf }) => {
      if (!live) return;
      setShort(isShortText(ready.clip.markdown));
      const labels = clipLabels();
      const markdown = placePictures(ready.clip.markdown, ready.clip.images, ready.clip.images.map(() => ({ failure: 'skipped' as const })), '');
      const body = previewOf(clipNoteBody({ ...ready.clip, markdown }, ready.source.url, { sourceLabel: labels.source, formatDate: labels.formatDate }), PREVIEW_CHARS);
      setPreview(renderMarkdownSafe(body));
    });
    return () => {
      live = false;
    };
  }, [ready]);

  async function save() {
    if (!url) {
      setInvalid(true);
      return;
    }
    // An address typed but not committed is downloaded first, and the
    // preview shows before anything is saved.
    if (committed !== url) {
      setCommitted(url);
      return;
    }
    if (existing) return;
    const page = await load(url);
    if (!page) return;
    const made = await prepare(url, page, pictures);
    if (!made) return;
    const clip = await import('./clipPage');
    setSaving(true);
    setBusy(t('clipper.saving'));
    try {
      const saved = await clip.finishClip(made, clipLabels(), (done, total) => setBusy(t('clipper.stepPictures', { done, total })));
      await onSave(url, saved);
      onClose();
    } catch {
      setSaving(false);
      setBusy(null);
      await fallBack(url, t('clipper.failed'), true);
    }
  }

  /** The person takes the suggestion: the bookmark, and no note. */
  async function keepBookmark() {
    if (!url) return;
    setSaving(true);
    await onKeepBookmark(url);
    onClose();
  }

  const stored = ready ? ready.held.filter((h) => 'bytes' in h).length : 0;

  return (
    <Modal onClose={saving ? undefined : onClose} title={t('clipper.windowTitle')} className="max-w-md p-6 space-y-4">
      <TextField
        label={t('clipper.addressLabel')}
        value={address}
        autoFocus
        dir="ltr"
        inputMode="url"
        enterKeyHint="go"
        placeholder={t('clipper.addressPlaceholder')}
        disabled={saving}
        error={invalid ? t('bookmarks.urlInvalid') : undefined}
        onChange={(e) => {
          const value = e.target.value;
          setAddress(value);
          setInvalid(false);
          // A new address starts over: the last message and a failed clip
          // belong to the old one. A paste commits at once, over old text too.
          setNotice(null);
          setEnded(false);
          const pasted = (e.nativeEvent as InputEvent).inputType === 'insertFromPaste' ? normalizeUrl(value) : null;
          setCommitted(pasted);
        }}
        onKeyDown={(e) => {
          if (e.key !== 'Enter' || isImeComposing(e)) return;
          e.preventDefault();
          if (url) setCommitted(url);
          else setInvalid(address.trim() !== '');
        }}
        onBlur={() => setInvalid(address.trim() !== '' && !url)}
      />
      {ready && (
        <div className="max-h-56 overflow-y-auto rounded-md border border-dashed border-divider bg-surface-1 px-3 py-2">
          <p className="text-sm font-semibold text-pn">{ready.clip.title || url}</p>
          <div
            className="prose prose-pn prose-sm max-w-none text-[13px] [&_a]:pointer-events-none"
            // Rendered from the clip's Markdown by the app's sanitizing
            // renderer, pictures removed; never the downloaded HTML.
            dangerouslySetInnerHTML={{ __html: preview }}
          />
        </div>
      )}
      {ready && short && !saving && (
        <Callout
          tone="warning"
          action={(
            <Button icon={<NEW_GLYPHS.bookmark size={15} aria-hidden="true" />} onClick={() => void keepBookmark()}>
              {t('clipper.keepBookmark')}
            </Button>
          )}
        >
          {t('clipper.shortText')}
        </Callout>
      )}
      <Switch
        label={t('clipper.savePictures')}
        description={ready && pictures && stored > 0
          ? t('clipper.picturesLine', { count: stored, size: formatBytes(ready.pictureBytes) })
          : (
            <>
              {t('clipper.savePicturesHint')}{' '}
              {/* A button inside the switch's label does not flip the switch. */}
              <button type="button" onClick={onOpenImageSettings} className="text-accent hover:underline">
                {t('settings:storage.imageSettingsLink')}
              </button>
            </>
          )}
        icon={<ImageIcon size={14} className="text-accent" />}
        labelClassName={ROW_TITLE}
        checked={pictures}
        disabled={ended || saving}
        onChange={(on) => {
          setPictures(on);
          writeClipPictures(on);
        }}
      />
      {busy && <p className={SETTINGS_HELP} role="status">{busy}</p>}
      {existing && (
        <p className="text-sm text-pn-soft" role="status">
          {t('clipper.alreadySaved', { date: formatInstant(existing.createdAt, 'date') })}
        </p>
      )}
      {notice && (
        <div className="space-y-2" role="alert">
          <p className="text-sm text-warning">{notice.text}</p>
          {notice.signUp && (
            <a href={withSource(DEMO_APP_URL)} className={`${SETTINGS_BTN_PRIMARY} inline-flex`}>
              {t('demoBanner.cta')}
            </a>
          )}
        </div>
      )}
      {/* A clip that ended in a bookmark leaves nothing to do: the X closes. */}
      {!ended && (
        <ModalFooter>
          <Button action="cancel" onClick={onClose} disabled={saving} />
          {existing ? (
            <Button action="open" variant="primary" onClick={() => onOpenNote(existing)}>{t('clipper.openNote')}</Button>
          ) : (
            <Button action="save" onClick={() => void save()} disabled={saving || !url || busy !== null}>
              {ready && short ? t('clipper.saveAnyway') : undefined}
            </Button>
          )}
        </ModalFooter>
      )}
    </Modal>
  );
}
