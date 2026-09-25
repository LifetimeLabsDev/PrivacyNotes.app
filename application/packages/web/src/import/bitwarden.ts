import { normalizeTag } from '../notesRepo';
import { serializeLoginBody } from '../LoginForm';
import { serializeCardBody } from '../CardForm';
import { serializeSshKeyBody } from '../SshKeyForm';
import { BW_EXPORTED_BY, BW_OWN_FIELDS } from '../export';
import { buildFolderTree } from './folderImport';
import { linkifyMarkdown } from './linkify';
import type { Importer, ImportedNote, ParsedImport } from './types';

/**
 * Bitwarden import adapter.
 *
 * Reads the unencrypted .json export from Bitwarden's vault export
 * (Tools > Export vault > File format: .json).
 *
 * Supported item types:
 *   1 = Login  -> PN 'login' vault item
 *   2 = Secure Note -> PN 'note'
 *   3 = Card   -> PN 'card' vault item
 *   4 = Identity -> PN 'note' (structured as readable text)
 *   5 = SSH Key -> PN 'ssh-key' vault item
 *
 * Folders map to tags, except in a file our own vault export wrote, where
 * they come back as folders. Favorites map to starred. Reprompt (1) maps to
 * pinProtected. TOTP authenticator keys are kept as-is on the login item.
 * The custom fields our vault export writes for what Bitwarden has no slot
 * for go back into their places; every other custom field is appended to the
 * notes field so nothing is lost.
 */

// Bitwarden export schema - intentionally loose, only the fields we use.
interface BwUri {
  match?: number | null;
  uri?: string;
}
interface BwLogin {
  uris?: BwUri[] | null;
  username?: string | null;
  password?: string | null;
  totp?: string | null;
}
interface BwCard {
  cardholderName?: string | null;
  brand?: string | null;
  number?: string | null;
  expMonth?: string | null;
  expYear?: string | null;
  code?: string | null;
}
interface BwIdentity {
  title?: string | null;
  firstName?: string | null;
  middleName?: string | null;
  lastName?: string | null;
  address1?: string | null;
  address2?: string | null;
  address3?: string | null;
  city?: string | null;
  state?: string | null;
  postalCode?: string | null;
  country?: string | null;
  company?: string | null;
  email?: string | null;
  phone?: string | null;
  ssn?: string | null;
  username?: string | null;
  passportNumber?: string | null;
  licenseNumber?: string | null;
}
interface BwSshKey {
  privateKey?: string | null;
  publicKey?: string | null;
  keyFingerprint?: string | null;
}
interface BwField {
  name?: string | null;
  value?: string | null;
  type?: number; // 0=Text, 1=Hidden, 2=Boolean, 3=Linked
}
interface BwItem {
  id?: string;
  organizationId?: string | null;
  folderId?: string | null;
  type: number;
  name?: string;
  notes?: string | null;
  favorite?: boolean;
  login?: BwLogin | null;
  card?: BwCard | null;
  identity?: BwIdentity | null;
  sshKey?: BwSshKey | null;
  fields?: BwField[] | null;
  reprompt?: number;
  creationDate?: string;
  revisionDate?: string;
}
interface BwFolder {
  id: string;
  name: string;
}
interface BwExport {
  encrypted?: boolean;
  exportedBy?: string;
  folders?: BwFolder[];
  items?: BwItem[];
}

// Bitwarden item type constants.
const BW_TYPE_LOGIN = 1;
const BW_TYPE_SECURE_NOTE = 2;
const BW_TYPE_CARD = 3;
const BW_TYPE_IDENTITY = 4;
const BW_TYPE_SSH_KEY = 5;

export const bitwardenImporter: Importer = {
  id: 'bitwarden',
  label: 'Bitwarden',
  description:
    'Unencrypted .json vault export from Bitwarden (Tools > Export vault > .json).',
  accept: '.json,application/json',
  enabled: true,
  sourceTag: 'bitwarden',

  async parse(file, onProgress) {
    onProgress?.('Reading file…');
    const text = await file.text();

    onProgress?.('Parsing JSON…');
    let data: BwExport;
    try {
      data = JSON.parse(text) as BwExport;
    } catch {
      throw new Error(
        'That file is not valid JSON. Make sure you exported as ".json" (not encrypted).'
      );
    }

    if (data.encrypted === true) {
      throw new Error(
        'This is an encrypted Bitwarden export. Please re-export using the plain ".json" format (not ".json (Encrypted)").'
      );
    }

    if (!data.items || !Array.isArray(data.items)) {
      throw new Error(
        'This file is missing the expected "items" array. Not a Bitwarden vault export.'
      );
    }

    const ownExport = data.exportedBy === BW_EXPORTED_BY;

    // Build folder ID -> name map: tags for a Bitwarden file, folders for
    // our own.
    const folderMap = new Map<string, string>();
    if (Array.isArray(data.folders)) {
      for (const f of data.folders) {
        if (f.id && f.name) folderMap.set(f.id, f.name);
      }
    }

    onProgress?.('Converting items…');
    const notes: ImportedNote[] = [];
    const warnings: string[] = [];
    const transforms: string[] = [];

    let loginCount = 0;
    let cardCount = 0;
    let secureNoteCount = 0;
    let identityCount = 0;
    let sshKeyCount = 0;
    let totpCount = 0;
    let starredCount = 0;
    let pinProtectedCount = 0;
    let linkifiedCount = 0;
    let customFieldCount = 0;
    let skippedOrg = 0;

    for (const item of data.items) {
      // Skip organization vault items - user exported an individual vault
      // but BW sometimes includes org items in the JSON anyway.
      if (item.organizationId) {
        skippedOrg++;
        continue;
      }

      const tags: string[] = [];
      // Bitwarden uses "/" for nested folders. Split into individual tags,
      // or keep the path to rebuild the folder when the file is our own.
      const folderPath = (item.folderId ? folderMap.get(item.folderId) ?? '' : '')
        .split('/').map((part) => part.trim()).filter(Boolean);
      if (!ownExport) {
        for (const part of folderPath) {
          const t = normalizeTag(part);
          if (t) tags.push(t);
        }
      }
      const { own, rest } = takeOwnFields(item.fields, item.type);
      // A set for the duplicate check: a crafted file can carry tens of
      // thousands of tags in one field, and a list scan per tag is quadratic.
      const seen = new Set(tags);
      for (const part of (own.tags ?? '').split(',')) {
        const t = normalizeTag(part);
        if (t && !seen.has(t)) {
          seen.add(t);
          tags.push(t);
        }
      }

      const starred = item.favorite === true;
      if (starred) starredCount++;

      const pinProtected = item.reprompt === 1;
      if (pinProtected) pinProtectedCount++;

      const createdAt = isoOrNow(item.creationDate);
      const updatedAt = isoOrNow(item.revisionDate ?? item.creationDate);

      const pushedAt = notes.length;
      switch (item.type) {
        case BW_TYPE_LOGIN: {
          loginCount++;
          const login = item.login ?? {};
          const uri = login.uris?.[0]?.uri ?? '';
          const itemNotes = appendCustomFields(item.notes ?? '', rest);
          customFieldCount += rest.length;

          if (login.totp) totpCount++;

          notes.push({
            title: item.name ?? '',
            body: serializeLoginBody({
              url: uri,
              username: login.username ?? '',
              password: login.password ?? '',
              notes: itemNotes,
              totp: login.totp ?? '',
            }),
            tags,
            createdAt,
            updatedAt,
            starred,
            pinProtected,
            type: 'login',
          });
          break;
        }

        case BW_TYPE_CARD: {
          cardCount++;
          const card = item.card ?? {};
          const itemNotes = appendCustomFields(item.notes ?? '', rest);
          customFieldCount += rest.length;

          notes.push({
            title: item.name ?? '',
            body: serializeCardBody({
              cardholderName: card.cardholderName ?? '',
              cardNumber: card.number ?? '',
              expMonth: card.expMonth ?? '',
              expYear: card.expYear ?? '',
              cvv: card.code ?? '',
              billingZip: own.billingZip ?? '',
              notes: itemNotes,
            }),
            tags,
            createdAt,
            updatedAt,
            starred,
            pinProtected,
            type: 'card',
          });
          break;
        }

        case BW_TYPE_SECURE_NOTE: {
          secureNoteCount++;
          let body = appendCustomFields(item.notes ?? '', rest);
          customFieldCount += rest.length;
          const original = body;
          body = linkifyMarkdown(body);
          if (body !== original) linkifiedCount++;

          notes.push({
            title: item.name ?? '',
            body,
            tags,
            createdAt,
            updatedAt,
            starred,
            pinProtected,
            type: 'note',
          });
          break;
        }

        case BW_TYPE_IDENTITY: {
          identityCount++;
          const identityNotes = appendCustomFields(item.notes ?? '', rest);
          customFieldCount += rest.length;
          // Identity is bitwarden's SECOND markdown body producer and the only
          // one that is not a structured vault type: formatIdentity returns
          // plain `Label: value` lines pushed as type 'note', carrying both the
          // item's Email field and the user's free-text notes. It went
          // unlinkified until the v0.300.0 call-site audit - the same shape as
          // the standardNotes checklist gap, and missed the same way, because
          // the exemption list named login / card / sshKey and simply never
          // mentioned this branch.
          const rawIdentity = formatIdentity(item.identity ?? {}, identityNotes);
          const body = linkifyMarkdown(rawIdentity);
          if (body !== rawIdentity) linkifiedCount++;

          notes.push({
            title: item.name ?? '',
            body,
            tags,
            createdAt,
            updatedAt,
            starred,
            pinProtected,
            type: 'note',
          });
          break;
        }

        case BW_TYPE_SSH_KEY: {
          sshKeyCount++;
          const ssh = item.sshKey ?? {};
          const itemNotes = appendCustomFields(item.notes ?? '', rest);
          customFieldCount += rest.length;

          notes.push({
            title: item.name ?? '',
            body: serializeSshKeyBody({
              label: own.label ?? ssh.keyFingerprint ?? '',
              privateKey: ssh.privateKey ?? '',
              publicKey: ssh.publicKey ?? '',
              passphrase: own.passphrase ?? '',
              notes: itemNotes,
            }),
            tags,
            createdAt,
            updatedAt,
            starred,
            pinProtected,
            type: 'ssh-key',
          });
          break;
        }

        default:
          warnings.push(
            `Skipped item "${item.name ?? '(unnamed)'}" with unknown type ${item.type}.`
          );
      }
      if (ownExport && folderPath.length > 0 && notes.length > pushedAt) {
        notes[pushedAt]!.folderPath = folderPath;
      }
    }

    // Our own export's folders, rebuilt once across all paths so siblings
    // share their ancestors. The apply step reuses a folder the account
    // already has under the same path instead of making a second one.
    const rebuilt = ownExport
      ? buildFolderTree(notes.map((n) => (n.folderPath ?? []).join('/')).filter(Boolean))
      : null;
    if (rebuilt) {
      for (const n of notes) {
        const key = (n.folderPath ?? []).join('/');
        if (key) n.folderId = rebuilt.dirToFolderId.get(key) ?? null;
      }
    }

    // Build transform messages.
    if (loginCount > 0) {
      transforms.push(`Imported ${loginCount} login${loginCount === 1 ? '' : 's'} as vault items.`);
    }
    if (cardCount > 0) {
      transforms.push(`Imported ${cardCount} card${cardCount === 1 ? '' : 's'} as vault items.`);
    }
    if (secureNoteCount > 0) {
      transforms.push(`Imported ${secureNoteCount} secure note${secureNoteCount === 1 ? '' : 's'}.`);
    }
    if (sshKeyCount > 0) {
      transforms.push(`Imported ${sshKeyCount} SSH key${sshKeyCount === 1 ? '' : 's'} as vault items.`);
    }
    if (identityCount > 0) {
      transforms.push(
        `Converted ${identityCount} identit${identityCount === 1 ? 'y' : 'ies'} to notes (no identity type in PrivacyNotes).`
      );
    }
    if (customFieldCount > 0) {
      transforms.push(
        `Preserved ${customFieldCount} custom field${customFieldCount === 1 ? '' : 's'} in the notes section.`
      );
    }
    if (starredCount > 0) {
      transforms.push(`Kept ${starredCount} favorite${starredCount === 1 ? '' : 's'} as starred.`);
    }
    if (pinProtectedCount > 0) {
      transforms.push(
        `Marked ${pinProtectedCount} re-prompt item${pinProtectedCount === 1 ? '' : 's'} as PIN-protected.`
      );
    }
    if (linkifiedCount > 0) {
      transforms.push(`Made URLs clickable in ${linkifiedCount} note${linkifiedCount === 1 ? '' : 's'}.`);
    }
    if (totpCount > 0) {
      transforms.push(`Kept the 2FA authenticator key for ${totpCount} login${totpCount === 1 ? '' : 's'}.`);
    }

    // Warnings.
    if (skippedOrg > 0) {
      warnings.push(
        `Skipped ${skippedOrg} organization vault item${skippedOrg === 1 ? '' : 's'} (only personal vault items are imported).`
      );
    }

    const uniqueTags = new Set<string>();
    for (const n of notes) for (const t of n.tags) uniqueTags.add(t);

    const emptyNotes = notes.filter((n) => !n.body.trim()).length;
    const untaggedNotes = notes.filter((n) => n.tags.length === 0).length;

    return {
      notes,
      warnings,
      transforms,
      stats: {
        totalNotes: notes.length,
        emptyNotes,
        untaggedNotes,
        uniqueTags: uniqueTags.size,
      },
      source: 'bitwarden',
      ...(rebuilt ? { folders: rebuilt.folders } : {}),
    } satisfies ParsedImport;
  },
};

/**
 * Split an item's custom fields into the ones our vault export writes for
 * what Bitwarden has no slot for, and the rest. A named field is taken only on
 * an item type that has its place, and only once; anything else stays with
 * the rest, which goes into the notes.
 */
function takeOwnFields(
  fields: BwField[] | null | undefined,
  type: number
): { own: Partial<Record<keyof typeof BW_OWN_FIELDS, string>>; rest: BwField[] } {
  const keys: (keyof typeof BW_OWN_FIELDS)[] =
    type === BW_TYPE_SSH_KEY ? ['tags', 'label', 'passphrase']
      : type === BW_TYPE_CARD ? ['tags', 'billingZip']
        : ['tags'];
  const own: Partial<Record<keyof typeof BW_OWN_FIELDS, string>> = {};
  const rest: BwField[] = [];
  for (const f of fields ?? []) {
    // Only a text value has a place to go back to; a hand-made file that
    // puts a number or a boolean under one of the names keeps it as a
    // custom field in the notes, the way every other field is kept.
    const key =
      typeof f.value === 'string'
        ? keys.find((k) => f.name === BW_OWN_FIELDS[k] && own[k] === undefined)
        : undefined;
    if (key) own[key] = f.value as string;
    else rest.push(f);
  }
  return { own, rest };
}

/**
 * Append Bitwarden custom fields to a notes string. Custom fields are
 * stored as name/value pairs and have no PN equivalent, so we render
 * them as "Name: Value" lines at the end of the notes.
 */
function appendCustomFields(
  notes: string,
  fields: BwField[] | null | undefined
): string {
  if (!fields || fields.length === 0) return notes;
  const lines: string[] = [];
  for (const f of fields) {
    // Skip linked fields (type 3) - they're Bitwarden autofill metadata
    // with no actual value, just a pointer to another field on the item.
    if (f.type === 3) continue;
    const name = f.name ?? '';
    const value = f.value ?? '';
    lines.push(`${name}: ${value}`);
  }
  const suffix = lines.join('\n');
  if (!notes.trim()) return suffix;
  return notes + '\n\n' + suffix;
}

/**
 * Format a Bitwarden identity into readable plain text. Identities have
 * no PN equivalent, so we render them as a structured note the user can
 * reference or copy fields from.
 */
function formatIdentity(id: BwIdentity, itemNotes: string): string {
  const lines: string[] = [];

  // Personal details (matches Bitwarden's grouping order)
  const nameParts = [id.title, id.firstName, id.middleName, id.lastName]
    .filter(Boolean)
    .join(' ');
  if (nameParts) lines.push(`Name: ${nameParts}`);
  if (id.username) lines.push(`Username: ${id.username}`);
  if (id.company) lines.push(`Company: ${id.company}`);

  // Identification
  if (id.ssn) lines.push(`SSN: ${id.ssn}`);
  if (id.passportNumber) lines.push(`Passport: ${id.passportNumber}`);
  if (id.licenseNumber) lines.push(`License: ${id.licenseNumber}`);

  // Contact information
  if (id.email) lines.push(`Email: ${id.email}`);
  if (id.phone) lines.push(`Phone: ${id.phone}`);
  const addrParts = [id.address1, id.address2, id.address3].filter(Boolean);
  if (addrParts.length > 0) lines.push(`Address: ${addrParts.join(', ')}`);
  const locParts = [id.city, id.state, id.postalCode, id.country].filter(Boolean);
  if (locParts.length > 0) lines.push(`Location: ${locParts.join(', ')}`);

  if (itemNotes) {
    if (lines.length > 0) lines.push('');
    lines.push(itemNotes);
  }

  return lines.join('\n');
}

function isoOrNow(s: string | undefined | null): string {
  if (!s) return new Date().toISOString();
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return new Date().toISOString();
  return d.toISOString();
}
