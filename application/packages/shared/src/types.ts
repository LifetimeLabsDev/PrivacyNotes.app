/**
 * Stored shape - what lives in Supabase.
 * Everything sensitive is inside `ciphertext`, opaque to the server.
 * ciphertext and nonce are base64-encoded strings.
 */
export interface StoredNote {
  id: string;
  user_pubkey: string;
  ciphertext: string; // base64
  nonce: string;      // base64
  created_at: string;
  updated_at: string;
}

/**
 * Runtime shape - what the UI works with after decryption.
 * Never persisted in plaintext.
 *
 * `trashed`, `starred`, `locked`, `pinProtected` live inside the
 * encrypted payload (not plaintext columns on the server) so even
 * note metadata stays private.
 *
 * `locked` and `pinProtected` are optional for backward compatibility:
 * older encrypted blobs predate the fields and must decrypt cleanly.
 * Treat `undefined` as `false` at the call site.
 */
/**
 * Note type discriminator. Determines which UI the note renders in
 * and what shape its body takes.
 *   - 'note'    - standard markdown note (TipTap editor)
 *   - 'task'    - checklist note, listed under Tasks (TipTap editor)
 *   - 'journal' - journal entry (TipTap editor + tracker pills)
 *   - 'file'    - uploaded file; body references its encrypted attachments
 *   - 'login'   - structured login/password entry (LoginForm)
 *   - 'card'    - credit/debit card (CardForm)
 *   - 'ssh-key' - SSH key pair (SshKeyForm)
 *   - 'link'    - bookmark; body is a small JSON document holding the URL
 *
 * Stored inside the encrypted payload so the server never learns what
 * kind of data the user is storing.
 */
export type NoteType = 'note' | 'task' | 'journal' | 'file' | 'login' | 'card' | 'ssh-key' | 'link';

export interface DecryptedNote {
  id: string;
  title: string;
  body: string;
  tags: string[];
  trashed: boolean;
  starred: boolean;
  createdAt: string;
  updatedAt: string;
  /** Pro: prevent accidental edits. Editor is read-only when true. */
  locked?: boolean;
  /** Pro: gate this note behind the user's PIN. */
  pinProtected?: boolean;
  /**
   * Note type. Defaults to 'note' for backward compatibility -
   * ciphertexts written before this field existed decrypt without it.
   */
  type?: NoteType;
  /**
   * Mood & wellness tracker data for journal entries. Optional -
   * only present on notes with type='journal' that have tracker
   * data logged. Older ciphertexts won't have this field.
   */
  trackers?: Record<string, unknown>;
  /**
   * Pro: id of the folder this note lives in, or null when unfiled.
   * Folder definitions live in the encrypted user settings blob; the
   * note only carries the membership pointer. Optional for backward
   * compatibility - older ciphertexts won't have this field.
   */
  folderId?: string | null;
}
