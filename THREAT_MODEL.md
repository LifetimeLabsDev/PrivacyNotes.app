# Threat Model

Last updated: 2026-09-15 (v0.517.1, three clarifications from the second-family audit: what a server with write access can do to a ciphertext, the BIP-39 salt and entropy, and a program under your own user account as device compromise; previous 2026-08-31, v0.488.3, local storage at rest)

This document describes the security assumptions, trust boundaries, and known limitations of PrivacyNotes, for auditors, contributors, and users who want to know exactly what the system protects against and what it does not.

## System overview

PrivacyNotes is an end-to-end encrypted personal workspace (notes, tasks, journal). A 12-word BIP-39 mnemonic phrase, generated client-side, is the sole root of trust. Two keys are derived from it via HKDF-SHA256 with domain-separated info strings:

1. **Ed25519 signing keypair** - the public key is the user's identity (pubkey); signatures authenticate sensitive API calls.
2. **XChaCha20-Poly1305 symmetric key** - encrypts all note content, attachments, user settings, and note version history before anything leaves the device.

Under self-custody, which is the default, the phrase, private signing key, and encryption key never leave the client. The server stores ciphertext, nonces, and operational metadata: the pubkey, device rows with peppered fingerprint hashes (see "Devices and fingerprint hashes"), quota counters, and subscription records. The full user-facing accounting of that metadata, including the identifier-free import counters and the website-icon lookups, is SECURITY.md's "What we measure" section; this document does not repeat it. The server never stores plaintext content.

**One exception, chosen by the user at OAuth signup.** In custodial mode the phrase is stored server-side, encrypted under a server-held key, which makes the server capable of decrypting that user's data. Everything below describes self-custody unless stated otherwise; the custodial deviations are specified in "OAuth users" and are the single largest trust boundary in the system.

## Trust boundaries

### Fully trusted

- **The user's device.** An attacker with full device access (OS-level keylogger, memory inspection, storage read) can extract the phrase. Out of scope.
- **The user's browser/WebView.** We rely on Web Crypto API, IndexedDB, and localStorage behaving correctly.
- **The cryptographic primitives.** `@noble/ciphers`, `@noble/hashes`, `@noble/ed25519`, `@scure/bip39` - audited, widely deployed libraries by Paul Miller.

### Partially trusted

- **Supabase (server + database).** Sees pubkeys, ciphertext, nonces, timestamps, and the metadata listed above. Cannot read content. A compromised server can delete data, serve stale data, and observe access patterns (which pubkey syncs when, note count, ciphertext sizes). It cannot decrypt notes, and it cannot forge one from nothing. With database write access it can move one of your existing ciphertexts onto another of your rows, because the wire format carries no row binding yet (see "Known limitation: no AAD" below).
- **Cloudflare (CDN + Workers).** Serves the frontend bundle. A compromised deployment could serve malicious JS that exfiltrates the phrase - the standard supply-chain risk for any web app. Desktop (Tauri) builds bundle the frontend locally, which mitigates this.
- **Paddle (payment processor).** Receives transaction metadata, no note content. Webhooks verified via HMAC-SHA256.

### Untrusted

- **The network.** TLS everywhere; content is encrypted before transmission regardless.
- **Other users.** RLS policies enforce strict pubkey isolation.

## Cryptographic design

### Key derivation

```
BIP-39 phrase (128 bits entropy)
  → mnemonicToSeedSync (PBKDF2-HMAC-SHA512, 2048 iterations, salt "mnemonic", passphrase empty)
  → 64-byte seed (a stretch of the 128 bits above, not new entropy)
  → HKDF-SHA256(seed, salt=none, info="privacynotes-signing-v1")       → 32-byte Ed25519 private key
  → HKDF-SHA256(seed, salt=none, info="privacynotes-encryption-v1")    → 32-byte symmetric key
  → HKDF-SHA256(seed, salt=none, info="privacynotes-auth-password-v1") → 32-byte session credential
```

**HKDF salt is omitted.** Per RFC 5869, an absent salt is a zero-filled string. Acceptable here: the input keying material is the 64-byte seed above, which carries the phrase's 128 bits of entropy, and domain separation comes from the info strings. An explicit salt could be added in a future derivation version but would not meaningfully improve security.

**The session credential is a login secret, not a key.** Returning devices re-mint their Supabase session by password grant against the account's existing auth user, using the auth-password HKDF branch (hex-encoded) as the password and the deterministic identifier `<pubkey>@phrase.privacynotes.app` as the login email. That address is an identifier in email shape: the domain receives no mail, and the server derives it from the signature-verified pubkey, never from client input. The server stores only a bcrypt hash of the credential; recovering the seed from it is not possible, and holding the credential grants exactly what holding a session grants - access to ciphertext the phrase holder could already fetch. Anonymous sign-in is used only for an account's first session.

### Encryption

- **Algorithm:** XChaCha20-Poly1305 (256-bit key, 192-bit nonce, 128-bit tag).
- **Nonce:** 24 bytes from `crypto.getRandomValues()` per encryption. The 192-bit nonce space makes random collisions negligible (~2^96 birthday bound).
- **Payload:** the note's JSON fields - title, body, tags, note type, metadata flags, and journal mood-tracker entries - are encrypted as a single blob. Health-adjacent data (mood tracking) sits inside the E2E envelope like everything else. The server stores base64 ciphertext and nonce.

**Known limitation: no AAD.** The note `id` and `user_pubkey` are not bound to the ciphertext, so an attacker with database write access could swap ciphertexts between rows of the same user undetected (cross-user swaps fail; the key differs). Adding AAD requires a ciphertext format migration. Tracked for a future version.

### Encrypted attachments

Images and file attachments use the same primitive via `encryptBlob` (`shared/src/blob.ts`): raw bytes encrypted under the user's symmetric key, 24-byte nonce prepended to the ciphertext. The original filename, MIME type, and size are encrypted inside the blob. The server sees an opaque object at path `<pubkey>/<uuid>` in a private storage bucket; RLS restricts each user to their own path prefix.

### Burn notes (one-time shares)

A burn note is encrypted client-side with a fresh random key that exists only in the share URL's fragment (`/burn#id=<uuid>&k=<hex>`). Fragments are never sent over HTTP, so the server holds ciphertext it can never decrypt, with no link to any account (creation is anonymous). Opening the link calls a consume-once RPC that deletes the row and returns the ciphertext in one statement; the table has no SELECT policy, so rows cannot be listed or re-read. Unopened notes are purged after 24 hours.

### QR sign-in and phrase handoff

Adding a device via QR encodes the full phrase in a URL fragment (`#phrase=...`) displayed as a QR code on the trusted device. The fragment never traverses the network; the new device consumes it on load and immediately removes it from the URL and history via `history.replaceState`. The QR itself is equivalent to the phrase while displayed - treat it as a secret.

### Challenge-response authentication

Device registration, pubkey linking, custody changes, and account deletion use Ed25519 signatures over structured challenges (e.g. `link:<authUid>`, `register-device:<authUid>:<deviceId>`). The `authUid` binding prevents replay across sessions.

## Local storage at rest

**Note content is sealed at rest on the device.** Rows in the `notes` store carry a version marker and one XChaCha20-Poly1305 ciphertext holding title, body, tags and tracker data; the sealing key is a dedicated HKDF branch off the phrase (`privacynotes-local-at-rest-v1`), derived on unlock and never stored. The AAD binds each ciphertext to its table and row id, so a blob moved between rows or tables fails authentication - a binding the server-side format does not have yet. The same seal covers the parsed-document cache and, in raw-bytes form, the decrypted image and attachment caches (the attachment's filename metadata seals beside its bytes); the in-flight edit stash in localStorage seals under the same key. Sealing is enforced in one place - a middleware under the local database layer - and a CI gate inspects raw storage after driving every write path, so a future writer that bypasses it fails the build instead of leaking silently.

What this protects, honestly: a copied browser profile, a storage dump or backup, and file-grabbing malware carry ciphertext instead of readable notes. What the chain bottoms out at depends on the mode. Without the app lock, the stored phrase is an AES-GCM envelope under a non-extractable WebCrypto key - "non-extractable" is a script-API property, not hardware, so a forensic parser over a complete profile copy can still recover the key material; in that mode the seal defends against script-level access and casual dumps. With the PIN app lock, the plain envelope is removed and the chain genuinely ends at the PIN wrap, bounded by the offline brute-force cost of a short PIN (see "PIN protection"). Fields the indexes and sync need stay readable on the row: id, timestamps, `dirty`, `deleted`, `trashed`, `starred`, `locked`, `pinProtected`, `type`, `folderId`, and the push-echo nonce - which is to say an attacker with the files still learns which rows exist, when they changed, and which are vault items, without reading any of them. Server-side these fields travel inside the wire ciphertext; locally the indexes need them.

Known residuals, deliberate and accepted: existing rows seal on the device's first unlock after the update that introduced sealing (no key exists before unlock, so the backlog waits); browser storage engines keep superseded values in free pages until compaction, so stale plaintext fragments can outlive the sweep for a while; the deduplication indexes store content hashes (an equality check against a known file, not content); the favicon cache keys on the domains in links and vault logins; the local settings cache stays readable for now - favorite tags, folder names, and custom tracker and medication names - until a planned split moves the sensitive part under the seal; the account panel cache holds user-entered device names and quota figures; an old sealed blob of the same row re-authenticates forever, so a disk-level rollback of one row to an earlier sealed version is undetectable (the format carries no freshness counter); the Markdown folder pillar edits the user's own files on their own disk, outside the seal by design; and the throwaway demo database stays plaintext because its keys derive from a public constant. Process memory is out of scope while the app runs - an app that shows notes holds notes. The real boundary for a lost or stolen machine remains OS full-disk encryption and screen lock, which the app cannot implement and should not imply.

**The phrase itself is the one exception, and it is wrapped.** The stored recovery phrase is an AES-GCM-256 envelope in trust-aware storage, encrypted under a NON-EXTRACTABLE WebCrypto key that lives in IndexedDB as a key object (`phraseAtRest.ts`). The browser never exposes that key's bytes to script, so a copied localStorage file, a serialized backup of the storage databases, or a synced browser profile no longer carries twelve readable words. This narrows the exposure of the root secret; it does not move the trust boundary above: an attacker who can RUN CODE in the app's origin on the user's machine can call the key and unwrap the phrase, and an attacker with the live browser profile on the same machine boots the app signed in. The wrap is best-effort by design: on a browser without working IndexedDB or WebCrypto, the app falls back to the old plaintext write rather than locking the user out, and leaves a breadcrumb in the auth log. Installs that predate the wrap migrate on their next boot.

The consequence, restated for the avoidance of marketing: **an attacker who can RUN CODE on the device - malware, a malicious extension with the right permissions, anyone at the unlocked machine - reads notes through the same door the app does.** That is out of scope (see "Out-of-scope threats"), and no feature in the product changes it. What changed with the at-rest seal is the file-access class only: storage copies and dumps no longer carry content.

The per-note lock and PIN-protect flags remain organizational gates at the client's trust level, not per-note cryptography (see "Lock / PIN-protect notes"). The biometric unlock remains a presence gate: its wrap key sits in storage beside the blob it wraps, so it adds no cryptographic strength until it is bound to the platform authenticator - a planned hardening, not a current property.

Sign-out clears the local database (`clearLocalDatabase`), including the parsed-document cache and the separate favicon cache, with an option to retain notes that have not yet synced so they are not lost; that wipe deletes by key on the sealed tables, because it runs after the seal key is zeroed. Account deletion (`deleteEntireLocalDatabase`) drops everything.

## PIN protection

The 4-digit PIN began as a **UI convenience gate**, and its offline bound has not changed: 10,000 values, brute-forced in minutes to hours by anyone holding the stored material, regardless of iteration count. What changed with the at-rest seal is its CONSEQUENCE: with the app lock armed, the phrase exists only PIN-wrapped and note content at rest is sealed under a phrase-derived key, so the PIN now stands at the end of a real cryptographic chain for file-access attackers - within exactly that brute-force bound. Users needing more than a short PIN can resist should rely on OS-level device encryption and screen lock.

### Implementation

- **Hash:** PBKDF2-SHA256, 600,000 iterations, 16-byte random salt, constant-time comparison.
- **Legacy hashes:** PINs set before the iteration bump used 100,000 iterations. They verify transparently and are rehashed to 600,000 on the next successful entry; until that entry, the weaker hash persists in storage.
- **Storage:** hash and salt in `UserSettings` (encrypted, synced) plus a localStorage cache; per-tab session unlock with a configurable timeout.
- **UI lockout:** 5 consecutive failures lock PIN entry for 30 seconds, doubling on each further failure. The counter lives in localStorage (survives tab close) and is shared across all PIN surfaces, so attempts cannot be split across views. This blocks casual in-browser guessing only; it does not slow the offline attack above.

### Lock / PIN-protect notes

The `locked` and `pinProtected` flags live inside the ciphertext and are enforced client-side only; any client holding the phrase decrypts everything regardless. Deliberate: a second, PIN-derived key would make those notes unrecoverable on a forgotten PIN. These are organizational privacy features, not cryptographic access control.

### Local phrase-at-rest: biometric and PIN wrapping

On a trusted device the phrase is stored locally (as the wrapped envelope described in "Local storage at rest") so the user can unlock without retyping it. Two optional features REPLACE that stored envelope with a user-secret wrap - enabling app lock removes the device-key envelope, and the post-unlock sign-in deliberately never writes it back while the lock is armed, so the PIN or biometric really is the only door (pre-launch audit 2026-08-28, finding 8). Both are convenience gates at the device's trust level:

- **Biometric unlock** (WebAuthn platform authenticator). A random AES-GCM-256 key wraps the phrase, and both the wrapped phrase and the raw wrap key sit in localStorage. The assertion is a user-presence check gating the UI flow; it does not derive or release the key, so storage access bypasses the biometric entirely. A future version could bind the key to the authenticator via the WebAuthn PRF extension.
- **PIN-wrapped phrase.** With app lock enabled, the phrase is wrapped with a PIN-derived AES key (same PBKDF2 parameters as above) and stored in synced `UserSettings` plus localStorage. Offline brute-force of the wrapped blob recovers the **master phrase** - the root key for the whole account - which is sharper than the per-note gate and accepted for the same reason: it requires storage access to a trusted device, which is out of scope. (The device-key envelope above is different on exactly this point: its key is non-extractable, so there is no blob-plus-key pair to carry away and grind offline.)

User-facing copy describes both as gates, not encryption.

## Sync, conflicts, and deletion

- **Model:** pull-then-push per device, ordered by `updated_at`.
- **Conflicts:** concurrent edits are detected via conditional updates. Metadata-only changes auto-merge; body-vs-body conflicts surface a resolution UI with both versions preserved. Nothing is silently overwritten.
- **Deletion and retention:** deleting a note writes a tombstone (`deleted_at`) that syncs to other devices. A scheduled job permanently deletes tombstoned rows (and their version history, via cascade) after 30 days; until then the note is restorable and its ciphertext remains on the server.

## Deletion metadata

- Deleting an attachment queues its opaque blob id in a server-side pending set (`pending_blob_gc`), so the server learns "a blob was deleted around time T" at delete time rather than at the deferred sweep. Owner-scoped by RLS; blob contents stay encrypted throughout.

## Devices and fingerprint hashes

Each registered device has a server-side row: user-visible name, platform, last-seen timestamp, and four fingerprint hashes used to group multiple browsers on one physical machine into a single device entry. The signals - platform, GPU renderer string, CPU core count, browser language - are hashed client-side with HMAC-SHA256 under a per-user pepper derived from the BIP-39 seed. Raw signal values never leave the device, and the server cannot brute-force the low-entropy signals because it never holds the pepper. Hashes are incomparable across users.

## OAuth users

OAuth (Google, Apple, GitHub) is an identity-only sign-in path. At first OAuth sign-in the user chooses a key custody model.

### Account identity and cross-provider linking

Account resolution is decided by Supabase GoTrue by **confirmed email**, not the provider's `sub`: a second provider reporting the same verified email merges into the same `auth.users` row, hence the same pubkey and notes. This is the load-bearing feature that lets a Google signup later sign in with Apple.

**Safety condition:** this is safe only because every enabled provider proves email ownership. Merging into a victim's account requires controlling the victim's email address, at which point most of their accounts are already lost - the standard property of email-based OAuth linking.

**Invariant (do not break):** never enable an auth method that can present an unverified email as confirmed (e.g. email/password without verification, a misconfigured magic-link path). Such a method would let an attacker merge into a custodial victim's account and call `get-custodial-phrase` to retrieve the plaintext phrase. Self-custody users would be unaffected; custodial users would be fully compromised.

**How the session credential complies:** the email provider is enabled (password grant for the re-mint credential above) with confirmation required, so a self-serve signup can never yield a signed-in, confirmed identity. The only path that confirms an email without verification is the pubkey link itself, and it confirms exclusively `<pubkey>@phrase.privacynotes.app` - composed server-side from a pubkey proven by ed25519 signature, on a domain the project controls and no identity provider can assert. No attacker-chosen address can reach a confirmed state through it.

**Known UX failure mode (data-loss-shaped, not a security issue):** if the second provider returns a different email (Apple's "Hide My Email" relay, or simply a different address), no merge occurs and the user silently lands in a fresh, empty account. Custodial users are hit hardest, as they are least likely to have saved their phrase. Onboarding surfaces phrase / QR recovery prominently for this reason.

### Self-custody (maximum privacy)

The phrase is generated client-side and never transmitted. The server stores only the pubkey under `app_metadata.pubkey`; OAuth proves identity and grants no access to key material. A new device requires the phrase or a QR sign-in from an existing device.

### Custodial (keep it simple)

The user explicitly opts to store their phrase server-side, encrypted with AES-256-GCM under a dedicated server secret (`CUSTODIAL_PHRASE_KEY`), enabling 1-click sign-in on new devices.

**Trust implications** (the user-facing statement is SECURITY.md's custodial section; these are the mechanics):

- The server operator, or anyone holding both database access and the secret, can decrypt the user's phrase and therefore all their data. A valid legal order could compel this. Database-only breaches stay unreadable.
- Custody is reversible from Settings > Security > Your Phrase: leaving deletes the `custodial_phrases` row, returning re-inserts it. Both directions require a live OAuth session AND an Ed25519 signature over a challenge, so a stolen session token alone cannot change custody mode. Cost of reversibility: the plaintext phrase can reach `store-custodial-phrase` from any signed-in device at any time; the signature bounds who, not when or where.

**Known limitations (flagged for audit):**

- `get-custodial-phrase` requires only a valid JWT - no signature challenge. A stolen session token suffices to exfiltrate the phrase for the JWT's lifetime. A signature challenge is not straightforward here: the user may not yet hold a signing key (the phrase is needed to derive it).
- `store-custodial-phrase` validates word count but not BIP-39 wordlist membership. Low risk: the call is signed, so callers can only store a phrase they already hold, corrupting only their own account.
- Neither custodial endpoint has rate limiting beyond platform defaults, notable given what `get-custodial-phrase` returns.
- The decrypted phrase transits isolate memory during `get-custodial-phrase` responses with no explicit zeroing; inherent to the runtime.

**Historical note:** before v0.152.0, an edge function derived OAuth users' phrases server-side from a secret pepper, silently. It was removed in v0.173.4 after all affected users migrated; the explicit custodial opt-in replaced it.

## Out-of-scope threats

- **Device compromise:** OS-level malware, keyloggers, memory or storage inspection. A hostile program running under your own user account counts as device compromise: it has the same access to the app's storage and keys as the app itself.
- **Supply-chain attacks on the web bundle:** a compromised CDN could serve malicious JS. Mitigated for desktop (bundled frontend); SRI / reproducible builds not yet implemented for web.
- **Denial of service** against Cloudflare or Supabase.
- **Clipboard exposure:** once a secret is copied, the OS clipboard is outside our control. We deliberately make no clipboard-wipe claims; a timed wipe from a background tab is unreliable and would be security theater.
- **Social engineering** that extracts the phrase from the user.
- **Quantum computing:** XChaCha20 at 256 bits is quantum-resistant; Ed25519 is vulnerable to Shor's algorithm, not a near-term practical concern.
