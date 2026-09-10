// Some UI strings are rendered in English even when the app is in another
// locale, because their translation overflows tight chrome (the footer gear
// label, the sync status pill, the half-width sidebar buttons). Render an exempt
// string with t(key, exemptOpts('<ns>:<key>')).
//
// The forcing is per-key, not blanket, because overflow depends on the script:
// Romance and Germanic translations run ~30% longer than English, whereas
// Japanese, Korean and Traditional Chinese words are far SHORTER. "Settings" is
// 8 characters; 設定 /
// 설정 is two. So most of these keys can safely show their real translation in
// CJK even though they cannot in German or French. Each key names the locales
// where its translation is verified to fit; everywhere else it falls back to
// English. Catalan runs long like Spanish and is excluded from exactly the
// slots where the Spanish form overflows.
//
// Shape: keys are namespace-qualified ('notes:footer.settings') so two
// namespaces can't collide. A call site passes the qualified key to exemptOpts
// and the short key to t(): t('footer.settings', exemptOpts('notes:footer.settings')).
//
// THIS FILE is the single source of truth for which UI strings render in
// English regardless of the active locale, and in which locales. If an
// "exempt" string ever looks unexpectedly translated (or unexpectedly
// English), the answer is in the RENDER_TRANSLATED map below - nothing else
// decides it. Human-readable explanation of the per-locale model, and how to
// change a key: ops/docs/i18n-spec.md section 10b.
// Design rationale + the CJK unlock: ops/docs/i18n-cjk-plan.md section 3.
import { activeLocale } from './i18n';

export const FORCE_EN = { lng: 'en' } as const;

const CJK = ['ja', 'ko', 'zh-TW'] as const;
// The Latin target locales (en is the source and always shows its own text).
const LATIN = ['de', 'fr', 'it', 'es', 'nl', 'pl', 'pt-PT', 'pt-BR', 'ca', 'cs', 'tr', 'sv'] as const;
// Every translated locale EXCEPT the few whose translation overflows a given
// slot. CJK forms are short and always fit, so they are always included.
const allBut = (...tooWide: string[]): readonly string[] => [
  ...LATIN.filter((l) => !tooWide.includes(l)),
  ...CJK,
];

// Per-key allow list: the locales that render the REAL translation. A key that
// is ABSENT from this map is not exempt at all - it is translated everywhere. A
// key present is forced to English in every locale NOT in its list. An empty
// array means English in every locale (a deliberate do-not-translate).
//
// The per-locale lists were measured in-browser on 2026-07-21 by injecting each
// translation into the real slot and checking for truncation and wrap, INCLUDING
// the Tags|Folders toggle. `upload` translates everywhere; `import` everywhere
// but Dutch. The three footer/rail slots below (Settings, sync pill, Import &
// Export) are English in all Latin because their slots are too tight to measure
// reliably. Spec: ops/docs/i18n-spec.md section 10b.
const RENDER_TRANSLATED: Record<string, readonly string[]> = {
  // The Brave "enable the flag" card, whole. Listed here so the review
  // dashboard marks every cell dead; the runtime forcing is done by
  // ENGLISH_EVERYWHERE below, which unlike `[]` also covers Arabic.
  'shell:markdown.braveTitle': [],
  'shell:markdown.braveSteps': [],
  'shell:markdown.braveCopy': [],
  'shell:markdown.braveCopied': [],
  'shell:markdown.braveAppAlternative': [],

  // The two SSH key-material labels, whole. Listed here so the review dashboard
  // marks every cell dead; the runtime forcing is done by ENGLISH_EVERYWHERE
  // below, which unlike `[]` also covers Arabic.
  'common:sshKeyForm.publicKey': [],
  'common:sshKeyForm.privateKey': [],

  // Product terms and dev-facing jargon: English in every locale, CJK included.
  'notes:vaultNew.sshKey': [], // "SSH Key" in the vault New menu
  'shell:vaultItem.badgeSshKey': [], // "SSH Key" vault row badge
  'notes:settings.accountLabel': [], // "ID & Sync" - product term
  'settings:syncStatus.notSynced': [], // footer pill word; the slot is narrow and ID & Sync carries the translation
  'notes:vaultFilter.keys': [], // Vault "Keys" filter chip, pairs with the SSH badge
  'shell:tagsRail.viewAuto': [], // "Auto" view mode
  'settings:appearance.viewAuto': [], // "Auto" view mode
  'settings:appearance.modeAuto': [], // "Auto" light/dark mode

  // Tags|Folders toggle: both labels share the narrow rail (content-width since
  // v0.253.1). fr/es/ca overflow (Etiquettes+Dossiers, Etiquetas+Carpetas,
  // Etiquetes+Carpetes); de/it/nl/pl/pt fit (Tag+Cartelle, Etiquetas+Pastas).
  // tr joins the overflow set: Etiketler + Klasörler is 9+9 glyphs, wider than
  // the es/ca pairs already excluded here (9+8) and level with fr (10+8). sv
  // stays translated at Taggar + Mappar (6+6), between de (10) and cs (12).
  'shell:browseToggle.tags': allBut('fr', 'es', 'ca', 'tr'),
  'shell:browseToggle.folders': allBut('fr', 'es', 'ca', 'tr'),

  // Sidebar footer pair (Feedback / Import). feedback: es "Comentarios", ca
  // "Comentaris" and cs "Zpetna vazba" (12ch, two words) truncate. import: nl
  // "Importeren" (10ch) truncates; the other Latin forms (Importer/Importar,
  // <=8ch, and cs "Import") fit. Everywhere else both translate.
  // tr "Geri bildirim" is 13 glyphs over two words, the same shape that got cs
  // excluded. sv takes the loanword "Feedback" (8), as de/it/nl/pt-PT already do.
  'shell:tagsRail.feedback': allBut('es', 'ca', 'cs', 'tr'),
  // tr "İçe aktar" is two words in a slot where nl's single 10-glyph
  // "Importeren" already overflows; sv "Importera" (9) sits just under it.
  'shell:tagsRail.import': allBut('nl', 'tr'),

  // Sidebar footer icon-row hover pill (the label that expands beside the
  // hovered icon; touch shows icons only, so this is the only label slot).
  // One label renders at a time but the w-60 rail still caps it at ~80px:
  // fr "Téléchargements" and pt-PT "Transferências" exceed that and render
  // English. tagsRail.help and tagsRail.rate are absent from this map
  // because every translation fits the pill. Estimated by glyph count;
  // re-measure in-browser (2026-07-21 method) if the row layout changes.
  // sv "Nedladdningar" (13) lands in the fr/pt-PT class here; tr "İndirmeler"
  // (10) matches cs "Ke stažení" (10), which already fits this pill.
  'shell:tagsRail.downloads': allBut('fr', 'pt-PT', 'sv'),

  // The footer Settings label, the sync-status pill beside it, and the settings
  // rail "Import & Export" label are English in EVERY Latin locale (translated
  // in CJK only). The footer row is too tight to translate reliably per-locale -
  // long words wrap or crowd the sync icon at narrower window widths, so a
  // measured allow list is fragile - and "Importeren & exporteren" wraps in nl.
  // Keeping all three English in Latin is the robust, consistent call. Decided
  // 2026-07-21; per-locale measurement was abandoned for these three slots.
  'notes:footer.settings': CJK,
  'notes:settings.importLabel': CJK,
  'settings:syncStatus.synced': CJK,
  'settings:syncStatus.notSaved': CJK,
  'settings:syncStatus.offline': CJK,
  'settings:syncStatus.syncing': CJK,
  'settings:syncStatus.uploading': CJK,
  // "Storage full" pill state (backlog #143): same slot, same call. The CJK
  // forms (容量不足 / 저장 공간 부족 / 儲存空間已滿) are shorter than the
  // already-approved uploading forms; Latin ones (Almacenamiento lleno,
  // Armazenamento cheio) are exactly the overflow class this map exists for.
  'settings:syncStatus.storageFull': CJK,
};

function fits(allow: readonly string[]): boolean {
  const loc = activeLocale();
  // Arabic is never forced to English, for any key - including the
  // deliberate-English-everywhere product-jargon keys (empty allow arrays).
  // Its UI terms run compact, like CJK, and the ar catalog carries its own
  // translation for every one of those jargon keys, so there is no slot this
  // needs to protect. Unconditional, ahead of the allow-list check below.
  if (loc === 'ar' || loc.startsWith('ar-')) return true;
  return allow.some((l) => loc === l || loc.startsWith(`${l}-`));
}

/**
 * English in EVERY locale, Arabic included - the one thing `[]` cannot express.
 *
 * `[]` means "no locale renders the translation", but `fits()` waves Arabic
 * through ahead of the allow list, so an `[]` key still shows its Arabic form.
 * That is deliberate for the product-jargon keys above (Arabic has real
 * translations for them and its terms are compact), and wrong for a string that
 * is English for a reason unrelated to width.
 *
 * The Brave card is that case: it walks the reader through a browser flags page
 * whose own labels Chromium ships in English in every language, so a translated
 * card would describe a screen that does not exist in that language. We hold the
 * whole card in English rather than mix languages inside it (decided
 * 2026-08-14); the flag name itself is separately pinned as a constant.
 *
 * "Public Key" and "Private Key" are the second case. They name the two halves
 * of an SSH keypair, and every tool the reader holds them next to says exactly
 * that: ssh-keygen, the GitHub and GitLab settings screens, ~/.ssh, the header
 * inside the file. A translated label makes the person carrying the key match
 * a word they will not meet again anywhere. The surrounding fields (Label,
 * Passphrase, Notes) are ordinary words and stay translated.
 *
 * Keys here MUST also appear in RENDER_TRANSLATED with `[]`, which is what the
 * review dashboard parses to grey their cells out.
 */
const ENGLISH_EVERYWHERE = new Set([
  'common:sshKeyForm.publicKey',
  'common:sshKeyForm.privateKey',
  'shell:markdown.braveTitle',
  'shell:markdown.braveSteps',
  'shell:markdown.braveCopy',
  'shell:markdown.braveCopied',
  'shell:markdown.braveAppAlternative',
]);

/**
 * Options for t() on an overflow-prone key: FORCE_EN when the active locale
 * would overflow this slot, otherwise undefined (render the real translation).
 */
export function exemptOpts(qualifiedKey: string): typeof FORCE_EN | undefined {
  // Ahead of everything, including the Arabic pass-through inside `fits()`.
  if (ENGLISH_EVERYWHERE.has(qualifiedKey)) return FORCE_EN;
  const allow = RENDER_TRANSLATED[qualifiedKey];
  // A key not in the map is not exempt at all: render its real translation.
  // (Only keys listed above are ever forced to English.)
  return allow === undefined || fits(allow) ? undefined : FORCE_EN;
}

// The "New" action button (notes:header.new + shell:tasksList.new). German "Neu"
// and Czech "Nova"/"Novy" (4ch) fit where every other Latin locale's translation
// overflows; the CJK forms (新規 / 추가 / 新增) fit too. Kept as its own helper
// because it is the one key whose Latin allow list is non-empty.
// sv "Ny" (2) is shorter than German "Neu"; tr "Yeni" (4) matches Czech "Nový".
const NEW_BUTTON_FITS = ['de', 'cs', 'tr', 'sv', ...CJK] as const;

export function newButtonOpts(): typeof FORCE_EN | undefined {
  return fits(NEW_BUTTON_FITS) ? undefined : FORCE_EN;
}
