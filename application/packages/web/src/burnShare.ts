/**
 * Burn-After-Reading share - encrypts a note's content with a one-time
 * random key, stores the ciphertext server-side in `burn_notes`, and
 * returns a URL with the row ID + decryption key in the fragment.
 *
 * URL format: /burn#id=<uuid>&k=<hex>
 *
 * The key never leaves the client (fragments aren't sent over HTTP).
 * The server only ever sees opaque ciphertext. On reveal, the viewer
 * calls `consume_burn_note(id)` which returns the ciphertext and
 * deletes the row atomically - one read, then it's gone.
 */

import { encryptJson, bytesToHex, bytesToBase64, createSupabaseClient } from '@notes/shared';
import type { LocalNote } from './db';
import { vaultContent, type VaultField } from './vaultFields';
import { linkExportMarkdown } from './linkBody';
import { hasMedia, stripMediaReferences } from './imageProcessing';
import i18n from './i18n';
import { detectPlatform } from './devices';
import { isDemoMode } from './demo';

// Lightweight anon client - burn shares don't require auth.
// persistSession: false avoids creating a duplicate GoTrueClient
// instance that shares the same storage key as the main auth client.
const supabase = createSupabaseClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY,
  { persistSession: false, storageKey: 'sb-burn-share-auth' },
);

/** Max plaintext bytes before encryption. ~32KB keeps payloads sane. */
const MAX_PAYLOAD_BYTES = 32_768;

export type BurnResult =
  | { ok: true; url: string }
  | { ok: false; error: string };

/**
 * Encrypt the given note content and store the ciphertext on the server.
 * Returns a /burn URL with the row ID and decryption key in the fragment.
 *
 * `fields` carries a vault item's labelled rows. The viewer has no vault code
 * in it - a burn page is what a stranger opens, so it stays small - and a
 * vault body is a JSON blob, which is what the page used to print. The labels
 * therefore travel inside the ciphertext, in the sender's language. A link
 * made before this existed simply arrives without them and renders as before.
 */
export async function createBurnLink(
  title: string,
  body: string,
  fields?: VaultField[],
): Promise<BurnResult> {
  // Demo mode makes zero server calls. A burn link is a real row in
  // burn_notes, so the sandbox has to decline rather than write one.
  if (isDemoMode()) {
    return {
      ok: false,
      error: i18n.t('notesChrome:burnShare.demo'),
    };
  }
  // Burn links require a server round-trip - bail early with a friendly
  // message instead of letting the supabase-js call surface a raw
  // "TypeError: Failed to fetch". See gap #30.
  if (typeof navigator !== 'undefined' && navigator.onLine === false) {
    return {
      ok: false,
      error: i18n.t('notesChrome:burnShare.offline'),
    };
  }

  const content = fields?.length ? { title, body, fields } : { title, body };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(content));

  if (payloadBytes.length > MAX_PAYLOAD_BYTES) {
    return {
      ok: false,
      error: i18n.t('notesChrome:burnShare.tooLarge', {
        size: Math.round(payloadBytes.length / 1000),
        max: Math.round(MAX_PAYLOAD_BYTES / 1000),
      }),
    };
  }

  // Generate a one-time random 32-byte key via Web Crypto.
  const key = crypto.getRandomValues(new Uint8Array(32));

  // encryptJson produces { ciphertext, nonce } using xchacha20poly1305.
  const { ciphertext, nonce } = encryptJson(content, key);

  // Prepend nonce to ciphertext for self-contained decryption.
  const combined = new Uint8Array(nonce.length + ciphertext.length);
  combined.set(nonce, 0);
  combined.set(ciphertext, nonce.length);

  // Store as base64 on the server.
  const ciphertextB64 = bytesToBase64(combined);

  // Generate UUID client-side so we don't need .select('id') after insert.
  // PostgREST requires a SELECT RLS policy to return rows, but burn_notes
  // intentionally has no SELECT policy (prevents enumerating all ciphertexts).
  const id = crypto.randomUUID();

  const { error } = await supabase
    .from('burn_notes')
    .insert({ id, ciphertext: ciphertextB64 });

  if (error) {
    return {
      ok: false,
      error: error.message ?? i18n.t('notesChrome:burnShare.storeFailed'),
    };
  }

  const keyHex = bytesToHex(key);
  // Burn links open in the recipient's browser, so the URL must be a public
  // https origin. On native platforms window.location.origin is tauri://localhost
  // (broken once shared), so use the canonical web origin; on web keep the live
  // origin (for local dev) but strip www to avoid a redirect hop.
  // Spec: ops/docs/gotchas.md (canonical domain privacynotes.app, no www)
  const origin =
    detectPlatform() === 'web'
      ? window.location.origin.replace('://www.', '://')
      : 'https://privacynotes.app';
  const url = `${origin}/burn#id=${id}&k=${keyHex}`;

  return { ok: true, url };
}

/**
 * What a note contributes to a burn link: the body the reader sees, plus
 * a vault item's labelled rows. Returns null when the note is media only -
 * images and files never travel, so stripping them leaves nothing to send.
 *
 * Both the burn action and the menu button that offers it read this, so the
 * button can go dim on exactly the notes the action would refuse.
 */
export function prepareBurnPayload(
  note: LocalNote,
): { body: string; stripped: boolean; fields?: VaultField[] } | null {
  // A vault item's body is the JSON blob its form reads, so send the
  // labelled rows instead and let the item's own notes be the body.
  const vault = vaultContent(note);
  // Bookmarks burn as the bare clickable link, never a fields table.
  let body = linkExportMarkdown(note) ?? (vault ? vault.notes : note.body);
  let stripped = false;
  if (hasMedia(body)) {
    body = stripMediaReferences(body);
    if (!body && !vault) return null;
    stripped = true;
  }
  return { body, stripped, fields: vault?.fields };
}
