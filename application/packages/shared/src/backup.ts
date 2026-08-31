/**
 * The .pnbackup on-disk format, extracted from the web client so it can be
 * exercised headlessly.
 *
 * Binary layout: [24-byte nonce][xchacha20poly1305 ciphertext]. The plaintext
 * is JSON: { version: 3, exportedAt, notes: [...], folders?: [...] }, the same
 * payload structure the plaintext JSON backup uses. This module is
 * deliberately pure (no DOM, no i18n, no download glue) so
 * tools/backup-kat.mjs can test the REAL encode/decode path in CI instead of
 * a re-implementation of it; the browser-facing wrapping (file download,
 * translated error messages) stays in packages/web/src/export.ts.
 *
 * If you change anything here, the golden-file test in tools/backup-kat.mjs
 * is the contract: a .pnbackup written in the past must keep decrypting, or
 * users lose their last line of defence. Read that file before editing this
 * one. A changed golden expectation is never a test to update; it is a
 * broken promise to every existing backup on someone's disk.
 *
 * Spec: ops/docs/dependency-migration.md (section 3, what verifies what)
 */

import { encryptBlob, decryptBlob } from './blob.js';
import { encryptJson, decryptJson } from './crypto.js';
import type { NoteType } from './types.js';

/** Format version written by buildBackupPayload. Restore-side handling of
 *  unknown versions belongs to the caller, which can show UI. */
export const BACKUP_VERSION = 3;

/** Stable error code thrown by decodeBackup for inputs too short to hold a
 *  nonce plus any ciphertext. A code, not prose, so UI layers can translate. */
export const BACKUP_TOO_SMALL = 'BACKUP_TOO_SMALL';

/** The note fields a backup carries. Structurally satisfied by the web
 *  client's LocalNote, so callers pass their rows straight in. */
export interface BackupNote {
  id: string;
  title: string;
  body: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  starred?: number;
  /** Written SPARSELY - present only when 1. Untrashed notes encode
   *  byte-identically to pre-field backups, which keeps the pinned
   *  backup KATs green, and a restore resurrecting the trash as live
   *  rows is the bug this field exists to close. */
  trashed?: number;
  type?: NoteType;
  locked?: number;
  pinProtected?: number;
  trackers?: Record<string, unknown>;
  folderId?: string | null;
}

export interface BackupPayload {
  version: number;
  exportedAt: string;
  notes: BackupNote[];
  /** v3+: folder definitions. The restore flow validates these with
   *  validateFolders() before merging; this module treats them as opaque. */
  folders?: unknown;
}

/**
 * Assemble the version-3 backup payload from note rows.
 *
 * Field mapping notes, preserved from the original export code: `type`
 * defaults to 'note' for rows predating note types, `folderId` and `trackers`
 * are omitted rather than written empty, and `folders` is omitted entirely
 * when there are none, so old and new payloads stay byte-compatible.
 * `exportedAt` is injectable so tests can build deterministic payloads.
 */
export function buildBackupPayload(
  notes: BackupNote[],
  folders: unknown[] = [],
  exportedAt: string = new Date().toISOString(),
): BackupPayload {
  return {
    version: BACKUP_VERSION,
    exportedAt,
    notes: notes.map((n) => ({
      id: n.id,
      title: n.title,
      body: n.body,
      tags: n.tags,
      createdAt: n.createdAt,
      updatedAt: n.updatedAt,
      starred: n.starred,
      ...(n.trashed ? { trashed: 1 } : {}),
      type: n.type || 'note',
      locked: n.locked,
      pinProtected: n.pinProtected,
      ...(n.folderId ? { folderId: n.folderId } : {}),
      ...(n.trackers && Object.keys(n.trackers).length > 0 ? { trackers: n.trackers } : {}),
    })),
    ...(folders.length > 0 ? { folders } : {}),
  };
}

/**
 * The .pnbackupz format: a full-backup ZIP's bytes sealed as one blob
 * under the same sync encryption key - [24-byte nonce][ciphertext],
 * the layout every sealed byte in this codebase uses. The zip inside is
 * byte-identical to the plain full backup, so a restore decrypts and
 * hands the bytes to the normal zip importer. Deliberately NOT a change
 * to .pnbackup: that format is pinned by the backup KATs and must keep
 * opening with the phrase alone, forever.
 */
export function encodeZipBackup(zipBytes: Uint8Array, key: Uint8Array): Uint8Array {
  return encryptBlob(zipBytes, key);
}

/** Throws BACKUP_TOO_SMALL for a truncated file; an authentication
 *  failure (wrong account key or damaged file - indistinguishable by
 *  design) propagates for the UI layer to translate, exactly like
 *  decodeBackup. */
export function decodeZipBackup(bytes: Uint8Array, key: Uint8Array): Uint8Array {
  if (bytes.length < 41) {
    const err = new Error(BACKUP_TOO_SMALL);
    err.name = BACKUP_TOO_SMALL;
    throw err;
  }
  return decryptBlob(bytes, key);
}

/** Encrypt a payload into .pnbackup bytes: [24-byte nonce][ciphertext]. */
export function encodeBackup(
  payload: BackupPayload,
  encryptionKey: Uint8Array,
): Uint8Array {
  const { ciphertext, nonce } = encryptJson(payload, encryptionKey);
  const out = new Uint8Array(nonce.length + ciphertext.length);
  out.set(nonce, 0);
  out.set(ciphertext, nonce.length);
  return out;
}

/**
 * Decrypt .pnbackup bytes with the user's encryption key.
 * Throws Error(BACKUP_TOO_SMALL) on truncated input; wrong keys and tampered
 * ciphertexts throw from the Poly1305 authentication check in decryptJson.
 */
export function decodeBackup(
  data: Uint8Array,
  encryptionKey: Uint8Array,
): BackupPayload {
  if (data.length < 25) {
    throw new Error(BACKUP_TOO_SMALL);
  }
  const nonce = data.slice(0, 24);
  const ciphertext = data.slice(24);
  return decryptJson<BackupPayload>(ciphertext, nonce, encryptionKey);
}
