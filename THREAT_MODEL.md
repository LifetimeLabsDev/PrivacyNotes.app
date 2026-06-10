# Threat Model

Last updated: 2026-06-10 (v0.195.6)

This document describes the security assumptions, trust boundaries, and known limitations of PrivacyNotes. It is intended for security auditors, contributors, and users who want to understand exactly what the system protects against and what it does not.

## System overview

PrivacyNotes is an end-to-end encrypted personal workspace (notes, tasks, journal). A 12-word BIP-39 mnemonic phrase, generated client-side, is the sole root of trust. From this phrase, two keys are deterministically derived via HKDF-SHA256 with domain-separated info strings:

1. **Ed25519 signing keypair** - the public key serves as the user's identity (pubkey). Used to authenticate API calls via challenge-response signatures.
2. **XChaCha20-Poly1305 symmetric key** - encrypts all note content, user settings, and note version history before any data leaves the device.

The phrase, private signing key, and encryption key never leave the client. The server stores only the pubkey (identity), ciphertext, and nonce.

## Trust boundaries

### Fully trusted

- **The user's device.** We assume the device is not compromised. An attacker with full device access (OS-level keylogger, memory inspection) can extract the phrase. This is explicitly out of scope.
- **The user's browser/WebView.** We rely on Web Crypto API, IndexedDB, and localStorage behaving correctly. A compromised browser breaks all guarantees.
- **The cryptographic primitives.** We use `@noble/ciphers` (XChaCha20-Poly1305), `@noble/hashes` (HKDF-SHA256, SHA-256), `@noble/ed25519`, and `@scure/bip39`. These are audited, widely deployed libraries by Paul Miller. We trust them to be correctly implemented.

### Partially trusted

- **Supabase (server + database).** The server can see pubkeys, ciphertext, nonces, and timestamps. It cannot read note contents. A compromised server can: delete data, serve stale data, observe access patterns (which pubkey syncs when, note count, ciphertext sizes). It cannot forge or decrypt notes without the user's key.
- **Cloudflare (CDN + Workers).** Serves the static frontend bundle. A compromised Cloudflare deployment could serve malicious JavaScript that exfiltrates the phrase. This is the standard supply-chain risk for any web application. Desktop (Tauri) builds mitigate this by bundling the frontend locally.
- **Paddle (payment processor).** Processes Pro purchases. Receives transaction metadata but no note content. Webhook integrity is verified via HMAC-SHA256 signature.

### Untrusted

- **The network.** All client-server communication is over TLS. Note content is encrypted before transmission regardless.
- **Other users.** RLS policies enforce strict pubkey isolation. One user cannot read, modify, or delete another user's data.

## Cryptographic design

### Key derivation

```
BIP-39 phrase (128 bits entropy)
  → mnemonicToSeedSync (PBKDF2-HMAC-SHA512, 2048 iterations, passphrase="mnemonic")
  → 64-byte seed
  → HKDF-SHA256(seed, salt=none, info="privacynotes-signing-v1")    → 32-byte Ed25519 private key
  → HKDF-SHA256(seed, salt=none, info="privacynotes-encryption-v1") → 32-byte symmetric key
```

**Known observation: HKDF salt is omitted.** Per RFC 5869 section 2.2, when the salt is not provided, HKDF uses a zero-filled byte string of HashLen. This is acceptable when the input keying material (IKM) has sufficient entropy, which it does - the BIP-39 seed provides 512 bits. The domain separation comes from distinct `info` strings. An explicit salt would not meaningfully improve security here but could be added in a future key derivation version if desired.

### Encryption

- **Algorithm:** XChaCha20-Poly1305 (256-bit key, 192-bit nonce, 128-bit tag).
- **Nonce generation:** 24 bytes from `crypto.getRandomValues()` (via `@noble/hashes/utils.randomBytes`). The 192-bit nonce space makes random nonce collisions negligible even at scale (~2^96 messages before birthday bound).
- **Payload:** JSON-serialized note fields (title, body, tags, metadata flags) are encrypted as a single blob. The server stores base64-encoded ciphertext and nonce.

**Known limitation: no Associated Authenticated Data (AAD).** The note's `id` and `user_pubkey` are not bound to the ciphertext via AAD. This means a server-side attacker with database write access could swap ciphertexts between note rows belonging to the same user without the client detecting it. Practical impact is low - the attacker needs direct database access and can only swap data within a single user's notes (cross-user swaps fail because the encryption key differs). Adding AAD would require a ciphertext format migration. Tracked for a future version.

### Challenge-response authentication

Device registration, pubkey linking, and account deletion all use Ed25519 signatures over structured challenge messages (e.g., `link:<authUid>`, `register-device:<authUid>:<deviceId>`). The `authUid` binding prevents replay across sessions.

## PIN protection

### Design intent

The 4-digit PIN is a **UI convenience gate**, not a security boundary. It protects the phrase modal and PIN-protected notes against casual shoulder-surfing on the user's own device. It is not designed to resist an attacker who has:

- Access to the device's filesystem (the PIN hash is in localStorage and synced settings)
- The user's BIP-39 phrase (which grants full decryption without any PIN)
- Time and compute to brute-force 10,000 combinations offline

### Implementation

- **Hash:** PBKDF2-SHA256, 600,000 iterations, 16-byte random salt, 256-bit output.
- **Verification:** Constant-time comparison (XOR accumulator, no early exit).
- **Storage:** Base64-encoded hash and salt in `UserSettings` (encrypted, synced) with a localStorage cache for synchronous `hasPin()` checks.
- **Session unlock:** Timestamp in sessionStorage (per-tab). Configurable timeout: always ask, never re-ask, or re-ask after N minutes.

### Brute-force protection

UI-level exponential backoff prevents casual brute-forcing: after 5 consecutive failed attempts, PIN input is locked for 30 seconds, doubling with each subsequent failure (60s, 120s, 240s...). The lockout state is stored in localStorage (survives tab close) - sessionStorage was previously used but allowed an attacker to reset the counter by simply closing and reopening the tab, which defeated the protection. A successful verify clears the failure counter. The same counter is shared across every PIN entry surface (note unlock, app lock screen, etc.) so attempts can't be split across views to multiply the effective threshold.

This is a UX defense, not a cryptographic one. An attacker with access to localStorage can extract the PBKDF2 hash and brute-force offline without ever touching the UI.

### Accepted risk

A 4-digit PIN has 10,000 possible values. At 600,000 PBKDF2 iterations, offline brute-force on modern hardware takes minutes to hours depending on the attacker's setup. The UI lockout prevents the much faster path of mashing digits in the browser. This is acceptable given the stated threat model (personal device, casual protection). Users who need stronger protection should rely on OS-level device encryption and screen lock, which we recommend in the phrase storage guidance.

### Lock / PIN-protect notes

The `locked` and `pinProtected` flags on notes are **client-side enforcement only**. They live inside the encrypted ciphertext (the server never sees them), and the client hides or gates access to notes with these flags set. However, any client with the user's phrase can decrypt all notes regardless of these flags - there is no server-side enforcement and no separate encryption key for locked notes.

This is a deliberate design choice: adding a second encryption layer for locked notes would require a second key (derived from the PIN), which would make those notes unrecoverable if the user forgets their PIN. The current model treats lock/PIN-protect as organizational privacy features (hiding sensitive notes from a quick glance), not as cryptographic access control.

### Local phrase-at-rest: biometric and PIN wrapping

On a trusted device the BIP-39 phrase is stored locally so the user can unlock without re-typing it. Two optional features "lock" that stored phrase. **Both are convenience gates at the same trust level as plaintext phrase storage, not cryptographic protection** - they defend against shoulder-surfing and a borrowed, unlocked device, never against an attacker who can read the device's storage. The implementation (`packages/web/src/biometric.ts`) is explicit about this.

- **Biometric unlock** (WebAuthn platform authenticator - Touch ID / Face ID / Windows Hello). On enrollment a random AES-GCM-256 key encrypts the phrase, and **both the wrapped phrase and the raw wrap key are stored in localStorage**. The WebAuthn assertion is a user-presence check that gates the UI flow; it does **not** derive or release the key. Consequently anyone with localStorage read access can decrypt the phrase without ever passing the biometric prompt. This provides no confidentiality beyond plaintext storage. A future version could bind the key to the authenticator via the WebAuthn PRF extension, which would make biometric a real cryptographic gate; until then it is presence-only.

- **PIN-wrapped phrase.** When app lock is enabled, the phrase is wrapped with an AES key derived from the 4-digit PIN (PBKDF2-SHA256, 600,000 iterations, 16-byte salt) and stored in synced `UserSettings` plus localStorage. Because a 4-digit PIN has only 10,000 values and the UI lockout (see above) does not apply to offline attacks, an attacker holding the wrapped blob can brute-force the PIN offline in minutes-to-hours and recover the **master phrase** - i.e. the root key for the entire account on every device, not merely one note. This is a sharper consequence than the per-note PIN gate, and is accepted for the same reason: it only matters once an attacker already has storage access to a trusted device, which is out of scope (see Device compromise, below).

The user-facing copy describes these honestly as gates ("a biometric gate so others nearby can't access your notes", "blocks casual viewing if someone borrows your device"), not as encryption. Users who need protection against an attacker with device/storage access should rely on OS-level device encryption and screen lock.

## Sync and conflict resolution

- **Model:** Pull-then-push, last-write-wins by `updated_at` timestamp.
- **Known limitation:** Concurrent offline edits to the same note on two devices will result in the newer edit silently winning. No CRDT or conflict UI exists. Accepted for V1.
- **Tombstones:** Hard deletes are propagated as server-side DELETE operations during sync push.

## Quota and abuse protection

- **Cloudflare Turnstile** on signup (invisible managed challenge, server-verified).
- **Per-row:** 1 MB ciphertext CHECK constraint.
- **Per-pubkey:** 10,000 notes, 50 MB total (free) / 500 MB (Pro). Enforced by Postgres triggers on `pubkey_quotas`.
- **Provisional account purge:** Anonymous auth users with no linked pubkey are deleted after 30 days (pg_cron).
- **Burn notes:** 64 KB ciphertext CHECK per row, 24h TTL purge, and a global ceiling of 500 inserts/hour (Postgres trigger `enforce_burn_note_rate_limit`). Burn creation is anonymous by design (session-less anon client), so per-user/per-pubkey limits do not apply; the global ceiling is a backstop to Cloudflare's per-IP limits and bounds storage blast radius. Tradeoff: a flooder can deny new burn shares globally for up to an hour.
- **Cloudflare rate limiting:** IP-level rules on signup and sync endpoints.

## OAuth users

OAuth (Google, Apple, GitHub) is an identity-only sign-in path. At first OAuth sign-in, the user chooses between two key custody models:

### Account identity and cross-provider linking

How an OAuth sign-in resolves to an account is **not** decided by our code. It is decided by Supabase GoTrue, by **confirmed email**, not by the provider's `sub` claim. When a user signs in with a new provider whose verified email matches an existing user's confirmed email, GoTrue merges the new identity into the **same `auth.users` row** (same `auth.uid`). Our code (`auth.tsx` `hydrateFromOAuthSession`) then reads `app_metadata.pubkey` off whichever user GoTrue returns. Same uid means same pubkey, same encryption key, same notes.

This is a load-bearing product feature, not an accident: it is what lets a user who signed up with Google sign in later with Apple (e.g. on iOS) and reach the same account. There is no alternative link key, because each provider issues a different `sub`; the email is the only shared identifier.

**Safety condition.** This is safe only because every enabled provider (Google, Apple, GitHub) proves email ownership before reporting an email as verified. To merge into a victim's account, an attacker must control the victim's email address, at which point they already control most of the victim's accounts. This is the standard, accepted property of email-based OAuth linking.

**Invariant (do not break):** as long as custodial mode exists, never enable an auth method that can present an *unverified* or *unproven* email as confirmed (e.g. email/password with verification disabled, a misconfigured magic-link path, or a provider that does not verify email ownership). Such a method would let an attacker mint a confirmed-email identity for an address they do not control, merge into a custodial victim's `auth.uid`, and then call `get-custodial-phrase` (JWT-only, no signature challenge) to retrieve the **plaintext** recovery phrase, fully decrypting all of the victim's notes. Self-custody users are unaffected (no server-side phrase; the attacker reaches ciphertext and a phrase-entry dead end). Custodial users would be fully compromised. This invariant is the line between a convenience feature and a custodial phrase-leak vulnerability.

**Known UX failure mode (not a security issue, but a data-loss-shaped one).** The merge only fires when the second provider returns the *same* email as the first. Apple's "Hide My Email" returns a `@privaterelay.appleid.com` relay address, and a user's Apple ID email may simply differ from their Google email. In either case no merge occurs and the user silently lands in a fresh, empty account. Custodial users are hit hardest: they are the least likely to have saved their recovery phrase, so an email mismatch on a new device leaves them with no in-app recovery path (they must re-sign-in with the original provider on a platform where it is offered, then hand off via QR). Any "Apple-only on iOS" decision must account for this; the new-OAuth-user onboarding path should assume the user may be an existing user whose email did not match and surface phrase / QR recovery prominently.

### Self-custody (maximum privacy)

The user's BIP-39 phrase is generated client-side and never transmitted to the server. The same zero-knowledge guarantees as phrase-only signup apply:

- The server stores only the user's pubkey under `app_metadata.pubkey`.
- OAuth proves identity (provider's stable `sub` claim). It does not give the server any access to key material.
- A new device requires the user's phrase or a QR sign-in code from an existing device.

### Custodial (keep it simple)

The user explicitly opts to have their BIP-39 phrase stored server-side for convenience. The phrase is encrypted with AES-256-GCM using a dedicated server secret (`CUSTODIAL_PHRASE_KEY`) and stored in `custodial_phrases`. This enables 1-click sign-in on new devices via OAuth alone.

**Trust implications for custodial users:**

- The server operator (and anyone who obtains both database access AND the `CUSTODIAL_PHRASE_KEY` secret) can decrypt the user's phrase and therefore all their data.
- A valid legal order compelling the server operator could result in decryption of custodial users' data.
- Custodial users retain: encryption in transit (TLS), encryption at rest in the database (AES-256-GCM), and protection against database-only breaches (attacker needs the secret too).
- Users can upgrade from custodial to self-custody at any time (one-way ratchet: the server deletes their phrase). They cannot downgrade from self-custody to custodial.

**Known limitations of custodial mode (flagged for audit):**

- `get-custodial-phrase` requires only a valid JWT - no secondary challenge (unlike `delete-account`, which requires an ed25519 signature). A stolen session token is sufficient to exfiltrate the phrase. The window of vulnerability is the JWT's lifetime. Adding a signature challenge is not straightforward here because the user may not yet have a signing key (the phrase is needed to derive it).
- `store-custodial-phrase` validates word count (12) but does not verify words are from the BIP-39 wordlist. Low risk since an attacker can only corrupt their own recovery phrase.
- Neither custodial endpoint has rate limiting beyond Supabase's default connection limits. Standard for edge functions but worth noting given `get-custodial-phrase` returns the crown jewels.
- The decrypted phrase is held in Deno isolate memory briefly during `get-custodial-phrase` responses. No explicit memory zeroing. This is inherent to the Deno runtime.

**Design rationale:** The choice is presented at first OAuth sign-in with explicit tradeoff explanation. This is the product differentiator - most apps store keys server-side silently; we ask the user. See `docs/custodial-key-spec.md` for the full architecture.

**Historical note:** Prior to v0.152.0 (2026-05), the `oauth-phrase` edge function derived OAuth users' phrases server-side from a Supabase secret (`OAUTH_PHRASE_PEPPER`). This was a silent server-side decision with no user consent. The function was deleted and the pepper unset in v0.173.4 after all 5 legacy users confirmed migration. The custodial key storage introduced in v0.172.0 is an explicit opt-in replacement.

## Out-of-scope threats

- **Device compromise:** OS-level malware, keyloggers, memory inspection.
- **Supply-chain attacks on the web bundle:** A compromised Cloudflare deployment or CDN could serve malicious JS. Mitigated for desktop users (Tauri bundles the frontend). SRI or reproducible builds are not yet implemented for the web version.
- **Denial of service:** Volumetric attacks against Cloudflare or Supabase infrastructure.
- **Social engineering:** Tricking users into revealing their phrase.
- **Quantum computing:** XChaCha20 is symmetric and quantum-resistant at 256-bit key length. Ed25519 is vulnerable to Shor's algorithm but this is not a near-term practical concern.
