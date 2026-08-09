# Threat Model

Last updated: 2026-08-01 (v0.283.1)

This document describes the security assumptions, trust boundaries, and known limitations of PrivacyNotes, for auditors, contributors, and users who want to know exactly what the system protects against and what it does not.

## System overview

PrivacyNotes is an end-to-end encrypted personal workspace (notes, tasks, journal). A 12-word BIP-39 mnemonic phrase, generated client-side, is the sole root of trust. Two keys are derived from it via HKDF-SHA256 with domain-separated info strings:

1. **Ed25519 signing keypair** - the public key is the user's identity (pubkey); signatures authenticate sensitive API calls.
2. **XChaCha20-Poly1305 symmetric key** - encrypts all note content, attachments, user settings, and note version history before anything leaves the device.

Under self-custody, which is the default, the phrase, private signing key, and encryption key never leave the client. The server stores ciphertext, nonces, and operational metadata: the pubkey, device rows (name, platform, last-seen time, and peppered fingerprint hashes - see "Devices and fingerprint hashes"), quota counters, and Pro/storage subscription records. It never stores plaintext content.

**One exception, chosen by the user at OAuth signup.** In custodial mode the phrase is stored server-side, encrypted under a server-held key, which makes the server capable of decrypting that user's data. Everything below describes self-custody unless stated otherwise; the custodial deviations are specified in "OAuth users" and are the single largest trust boundary in the system.

## Trust boundaries

### Fully trusted

- **The user's device.** An attacker with full device access (OS-level keylogger, memory inspection, storage read) can extract the phrase. Out of scope.
- **The user's browser/WebView.** We rely on Web Crypto API, IndexedDB, and localStorage behaving correctly.
- **The cryptographic primitives.** `@noble/ciphers`, `@noble/hashes`, `@noble/ed25519`, `@scure/bip39` - audited, widely deployed libraries by Paul Miller.

### Partially trusted

- **Supabase (server + database).** Sees pubkeys, ciphertext, nonces, timestamps, and the metadata listed above. Cannot read content. A compromised server can delete data, serve stale data, and observe access patterns (which pubkey syncs when, note count, ciphertext sizes); it cannot forge or decrypt notes.
- **Cloudflare (CDN + Workers).** Serves the frontend bundle. A compromised deployment could serve malicious JS that exfiltrates the phrase - the standard supply-chain risk for any web app. Desktop (Tauri) builds bundle the frontend locally, which mitigates this.
- **Paddle (payment processor).** Receives transaction metadata, no note content. Webhooks verified via HMAC-SHA256.

### Untrusted

- **The network.** TLS everywhere; content is encrypted before transmission regardless.
- **Other users.** RLS policies enforce strict pubkey isolation.

## Cryptographic design

### Key derivation

```
BIP-39 phrase (128 bits entropy)
  → mnemonicToSeedSync (PBKDF2-HMAC-SHA512, 2048 iterations, passphrase="mnemonic")
  → 64-byte seed
  → HKDF-SHA256(seed, salt=none, info="privacynotes-signing-v1")       → 32-byte Ed25519 private key
  → HKDF-SHA256(seed, salt=none, info="privacynotes-encryption-v1")    → 32-byte symmetric key
  → HKDF-SHA256(seed, salt=none, info="privacynotes-auth-password-v1") → 32-byte session credential
```

**HKDF salt is omitted.** Per RFC 5869, an absent salt is a zero-filled string. Acceptable here: the input keying material is a 512-bit seed, and domain separation comes from the info strings. An explicit salt could be added in a future derivation version but would not meaningfully improve security.

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

## PIN protection

The 4-digit PIN is a **UI convenience gate**, not a security boundary. It protects against shoulder-surfing and a borrowed, unlocked device - not against an attacker with filesystem access, the phrase, or offline compute. A 4-digit PIN has 10,000 values; an attacker holding the stored hash can brute-force it offline in minutes to hours regardless of iteration count. Users needing more should rely on OS-level device encryption and screen lock.

### Implementation

- **Hash:** PBKDF2-SHA256, 600,000 iterations, 16-byte random salt, constant-time comparison.
- **Legacy hashes:** PINs set before the iteration bump used 100,000 iterations. They verify transparently and are rehashed to 600,000 on the next successful entry; until that entry, the weaker hash persists in storage.
- **Storage:** hash and salt in `UserSettings` (encrypted, synced) plus a localStorage cache; per-tab session unlock with a configurable timeout.
- **UI lockout:** 5 consecutive failures lock PIN entry for 30 seconds, doubling on each further failure. The counter lives in localStorage (survives tab close) and is shared across all PIN surfaces, so attempts cannot be split across views. This blocks casual in-browser guessing only; it does not slow the offline attack above.

### Lock / PIN-protect notes

The `locked` and `pinProtected` flags live inside the ciphertext and are enforced client-side only; any client holding the phrase decrypts everything regardless. Deliberate: a second, PIN-derived key would make those notes unrecoverable on a forgotten PIN. These are organizational privacy features, not cryptographic access control.

### Local phrase-at-rest: biometric and PIN wrapping

On a trusted device the phrase is stored locally so the user can unlock without retyping it. Two optional features gate that stored phrase; **both are convenience gates at the same trust level as plaintext storage**:

- **Biometric unlock** (WebAuthn platform authenticator). A random AES-GCM-256 key wraps the phrase, and both the wrapped phrase and the raw wrap key sit in localStorage. The assertion is a user-presence check gating the UI flow; it does not derive or release the key, so storage access bypasses the biometric entirely. A future version could bind the key to the authenticator via the WebAuthn PRF extension.
- **PIN-wrapped phrase.** With app lock enabled, the phrase is wrapped with a PIN-derived AES key (same PBKDF2 parameters as above) and stored in synced `UserSettings` plus localStorage. Offline brute-force of the wrapped blob recovers the **master phrase** - the root key for the whole account - which is sharper than the per-note gate and accepted for the same reason: it requires storage access to a trusted device, which is out of scope.

User-facing copy describes both honestly as gates, not encryption.

## Sync, conflicts, and deletion

- **Model:** pull-then-push per device, ordered by `updated_at`.
- **Conflicts:** concurrent edits are detected via conditional updates. Metadata-only changes auto-merge; body-vs-body conflicts surface a resolution UI with both versions preserved. Nothing is silently overwritten.
- **Deletion and retention:** deleting a note writes a tombstone (`deleted_at`) that syncs to other devices. A scheduled job permanently deletes tombstoned rows (and their version history, via cascade) after 30 days; until then the note is restorable and its ciphertext remains on the server.

## Quota and limits

- **Per-account:** 10,000 notes; combined storage (notes + attachments) of 50 MB free / 500 MB Pro, extendable with optional 1/2/5 GB Pro storage add-ons. Enforced server-side by Postgres triggers.
- **Per-row:** 1 MB ciphertext cap (64 KB for burn notes).
- **Over-quota lifecycle:** exceeding the cap (e.g. after a storage add-on is cancelled) starts a 90-day grace period during which sync continues. Past 90 days, new writes are rejected ("Sync frozen") until usage drops or capacity is re-added; deletes remain allowed so recovery is always possible, and local data is never touched.
- **Abuse defenses:** signup is rate-limited and may additionally be gated by an interactive challenge, and abusive write patterns are bounded by further server-side limits. Exact mechanisms and thresholds are deliberately not documented here. Anonymous signups that never complete setup are deleted after 7 days; accounts with a linked pubkey are never purged.

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

**Trust implications:**

- The server operator (or anyone holding both database access and the secret) can decrypt the user's phrase and therefore all their data. A valid legal order could compel this.
- Custodial users retain TLS in transit, AES-256-GCM at rest, and protection against database-only breaches.
- Custody is reversible from Settings > Security > Your Phrase: leaving deletes the `custodial_phrases` row, returning re-inserts it. Both directions require a live OAuth session AND an Ed25519 signature over a challenge, so a stolen session token alone cannot change custody mode.
- **Cost of reversibility:** the plaintext phrase can reach `store-custodial-phrase` from any signed-in device at any time, not only at signup. The signature bounds who (the key holder), not when or where.

**Known limitations (flagged for audit):**

- `get-custodial-phrase` requires only a valid JWT - no signature challenge. A stolen session token suffices to exfiltrate the phrase for the JWT's lifetime. A signature challenge is not straightforward here: the user may not yet hold a signing key (the phrase is needed to derive it).
- `store-custodial-phrase` validates word count but not BIP-39 wordlist membership. Low risk: the call is signed, so callers can only store a phrase they already hold, corrupting only their own account.
- Neither custodial endpoint has rate limiting beyond platform defaults, notable given what `get-custodial-phrase` returns.
- The decrypted phrase transits isolate memory during `get-custodial-phrase` responses with no explicit zeroing; inherent to the runtime.

**Design rationale:** the choice is presented at first OAuth sign-in with an explicit tradeoff explanation. Most apps store keys server-side silently; we ask.

**Historical note:** before v0.152.0, an edge function derived OAuth users' phrases server-side from a secret pepper, silently. It was removed in v0.173.4 after all affected users migrated; the explicit custodial opt-in replaced it.

## Out-of-scope threats

- **Device compromise:** OS-level malware, keyloggers, memory or storage inspection.
- **Supply-chain attacks on the web bundle:** a compromised CDN could serve malicious JS. Mitigated for desktop (bundled frontend); SRI / reproducible builds not yet implemented for web.
- **Denial of service** against Cloudflare or Supabase.
- **Clipboard exposure:** once a secret is copied, the OS clipboard is outside our control. We deliberately make no clipboard-wipe claims; a timed wipe from a background tab is unreliable and would be security theater.
- **Social engineering** that extracts the phrase from the user.
- **Quantum computing:** XChaCha20 at 256 bits is quantum-resistant; Ed25519 is vulnerable to Shor's algorithm, not a near-term practical concern.
