/**
 * Vault item -> labelled field rows.
 *
 * A vault note keeps its fields as a JSON blob in the note body, so every
 * surface that shows a note body without the vault forms behind it printed
 * that raw JSON: the HTML/PDF export did until it grew its own table, and
 * the Burn-After-Reading page still did. Both build their presentation from
 * the rows below, so one shared login reads the same in the PDF, in the
 * .html file and on the burn page.
 *
 * Labels are the ones the vault forms use, so a printed field carries the
 * same name as the field the user typed it into.
 */
import i18n from './i18n';
import type { LocalNote } from './db';
import { parseLoginBody } from './LoginForm';
import { parseCardBody, detectCardNetwork } from './CardForm';
import { parseSshKeyBody } from './SshKeyForm';
import { formatAddressLines, formatContactDate, parseContactBody } from './contactBody';
import { activeLocale } from './languages';

export interface VaultField {
  label: string;
  value: string;
  /** Keys and other opaque strings read better in a monospace face. */
  mono?: boolean;
}

export interface VaultContent {
  fields: VaultField[];
  /** The item's freeform notes - body text under the table, not a row. */
  notes: string;
  notesLabel: string;
}

/**
 * Break a vault note into display rows, or null when the note is not a
 * vault item (a plain note, journal entry or task list renders as markdown).
 */
export function vaultContent(note: LocalNote): VaultContent | null {
  if (note.type === 'login') {
    const l = parseLoginBody(note.body);
    // Credentials first, the address last: the same order the form and the
    // view use, so a printed login reads like the one on screen.
    const fields: VaultField[] = [];
    if (l.username) fields.push({ label: i18n.t('auth:loginForm.usernameLabel'), value: l.username });
    if (l.password) fields.push({ label: i18n.t('auth:loginForm.passwordLabel'), value: l.password });
    if (l.totp) fields.push({ label: i18n.t('auth:loginForm.totpLabel'), value: l.totp, mono: true });
    if (l.url) fields.push({ label: i18n.t('auth:loginForm.websiteLabel'), value: l.url });
    return { fields, notes: l.notes, notesLabel: i18n.t('auth:loginForm.notesLabel') };
  }

  if (note.type === 'card') {
    const c = parseCardBody(note.body);
    const digits = c.cardNumber.replace(/\D/g, '');
    const grouped = digits.replace(/(.{4})/g, '$1 ').trim();
    const network = detectCardNetwork(c.cardNumber);
    const fields: VaultField[] = [];
    if (c.cardholderName) fields.push({ label: i18n.t('common:cardForm.cardholderName'), value: c.cardholderName });
    if (grouped) fields.push({ label: i18n.t('common:cardForm.cardNumber'), value: grouped });
    if (network) fields.push({ label: i18n.t('common:cardForm.network'), value: network });
    if (c.expMonth || c.expYear) fields.push({ label: i18n.t('common:cardForm.expiry'), value: `${c.expMonth}/${c.expYear}` });
    if (c.cvv) fields.push({ label: i18n.t('common:cardForm.cvv'), value: c.cvv });
    if (c.billingZip) fields.push({ label: i18n.t('common:cardForm.billingZip'), value: c.billingZip });
    return { fields, notes: c.notes, notesLabel: i18n.t('common:cardForm.notes') };
  }

  if (note.type === 'ssh-key') {
    const s = parseSshKeyBody(note.body);
    const fields: VaultField[] = [];
    if (s.label) fields.push({ label: i18n.t('common:sshKeyForm.label'), value: s.label, mono: true });
    if (s.publicKey) fields.push({ label: i18n.t('common:sshKeyForm.publicKey'), value: s.publicKey, mono: true });
    if (s.privateKey) fields.push({ label: i18n.t('common:sshKeyForm.privateKey'), value: s.privateKey, mono: true });
    if (s.passphrase) fields.push({ label: i18n.t('common:sshKeyForm.passphrase'), value: s.passphrase, mono: true });
    return { fields, notes: s.notes, notesLabel: i18n.t('common:sshKeyForm.notes') };
  }

  if (note.type === 'contact') {
    const c = parseContactBody(note.body);
    const label = (group: string, raw: string) =>
      raw ? `${group} (${i18n.t(`shell:contacts.labels.${raw}`, { defaultValue: raw })})` : group;
    const fields: VaultField[] = [];
    for (const p of c.phones) fields.push({ label: label(i18n.t('shell:contacts.groupPhone'), p.label), value: p.value });
    for (const e of c.emails) fields.push({ label: label(i18n.t('shell:contacts.groupEmail'), e.label), value: e.value });
    if (c.org) fields.push({ label: i18n.t('shell:contacts.company'), value: c.org });
    if (c.department) fields.push({ label: i18n.t('shell:contacts.department'), value: c.department });
    if (c.jobTitle) fields.push({ label: i18n.t('shell:contacts.jobTitle'), value: c.jobTitle });
    for (const a of c.addresses) fields.push({ label: label(i18n.t('shell:contacts.groupAddress'), a.label), value: formatAddressLines(a).join('\n') });
    for (const u of c.urls) fields.push({ label: label(i18n.t('shell:contacts.groupWebsite'), u.label), value: u.value });
    for (const p of c.profiles) fields.push({ label: label(i18n.t('shell:contacts.groupProfile'), p.label), value: p.value });
    for (const d of c.dates) fields.push({ label: label(i18n.t('shell:contacts.groupDates'), d.label), value: formatContactDate(d.value, activeLocale()) });
    for (const r of c.related) fields.push({ label: label(i18n.t('shell:contacts.groupRelated'), r.label), value: r.value });
    if (c.nickname) fields.push({ label: i18n.t('shell:contacts.nickname'), value: c.nickname });
    return { fields, notes: c.notes, notesLabel: i18n.t('shell:contacts.groupNote') };
  }

  return null;
}

/**
 * One field as a markdown block: `**Label:** \`value\``, or a label over a
 * fenced block when the value spans lines, which in practice means a private
 * key. The fence is always longer than the longest backtick run in the value,
 * because a password is arbitrary bytes and an unfenced one renders its
 * asterisks as emphasis.
 */
function fieldBlock(label: string, value: string): string {
  const ticks = (value.match(/`+/g) ?? []).reduce((n, run) => Math.max(n, run.length), 0);
  if (value.includes('\n')) {
    const fence = '`'.repeat(Math.max(3, ticks + 1));
    return `**${label}:**\n\n${fence}\n${value}\n${fence}`;
  }
  const fence = '`'.repeat(ticks + 1);
  // CommonMark strips one leading and trailing space from a code span, which
  // is what keeps a value that starts or ends with a backtick readable.
  const pad = value.startsWith('`') || value.endsWith('`') ? ' ' : '';
  return `**${label}:** ${fence}${pad}${value}${pad}${fence}`;
}

/**
 * Render a vault item as readable markdown, for the SINGLE-NOTE .md export.
 *
 * Never for the full backup zip. That one writes the stored JSON body, which
 * is what `import/privacynotes.ts` reads back - together with the `type:` line
 * in its front matter - to rebuild the item. A single .md carries no type and
 * no importer reads one, so there the blob restores nothing and only hides the
 * fields from the person who asked for the file.
 */
export function vaultToMarkdown(vault: VaultContent): string {
  const blocks = vault.fields.map((f) => fieldBlock(f.label, f.value));
  if (vault.notes) blocks.push(`**${vault.notesLabel}:**\n\n${vault.notes}`);
  return blocks.join('\n\n');
}
