# Security

This document describes how PrivacyNotes handles your data, what we protect against, and what we don't. It's written for users who want to know what they're trusting, and for anyone reviewing the project.

If you find a vulnerability, please email privacynotes@lifetimelabs.dev instead of opening a public issue.

## In one paragraph

PrivacyNotes is end-to-end encrypted. Your 12-word recovery phrase is generated on your device and never sent anywhere. From it we derive two keys: one to encrypt every note, task, and journal entry before it leaves the device, and one to sign requests so the server can tell it's you without knowing who you are. The server stores ciphertext and a public key. Neither the server nor we hold the keys required to decrypt it - those live only on your devices.

## What the server sees

The server is Supabase (Postgres + Row Level Security) in Zurich. For each user it stores:

- A public Ed25519 key, which acts as the account identifier.
- Encrypted blobs of notes, tasks, journal entries, settings, and version history.
- Nonces and timestamps required to sync and resolve order.
- Sizes of the encrypted blobs (a row in a database has a size).

It does not store: titles, body text, tags, the recovery phrase, or anything derived from them. Phrase-flow users sign up with anonymous Supabase auth - no email, no name, no identifier tied to who they are. OAuth users (Google, Apple) have an identity from the provider attached to their session; see the OAuth section below for what that does and does not mean.

If the server is compromised tomorrow, the attacker gets a database of opaque bytes addressed by public key. They can correlate which key syncs at which time and infer crude things like "this user has roughly 200 notes," but they cannot read content.

## Cryptography

We rely on the noble suite by Paul Miller. These are audited, widely used libraries; if they're wrong, a lot of the ecosystem is wrong with us.

**Phrase to keys.** A BIP-39 12-word phrase (128 bits of entropy) is converted to a 64-byte seed via `mnemonicToSeedSync`. From the seed:

```
HKDF-SHA256(seed, info="privacynotes-signing-v1")    → 32-byte Ed25519 private key
HKDF-SHA256(seed, info="privacynotes-encryption-v1") → 32-byte symmetric key
```

The HKDF salt is omitted. RFC 5869 §2.2 permits this when the input keying material has high entropy, which the BIP-39 seed does. Domain separation between the two derived keys is enforced by the distinct `info` strings. We could add an explicit salt in a future key derivation version and may do so.

**Encryption.** XChaCha20-Poly1305 with a 256-bit key, 192-bit nonce, and 128-bit auth tag. Nonces come from `crypto.getRandomValues()` via `@noble/hashes/utils.randomBytes`. The 192-bit nonce space puts random-collision risk far past anything a single user could plausibly produce.

**Authentication.** Sensitive endpoints (device registration, account deletion, key linking) require an Ed25519 signature over a structured challenge that includes the session's auth UID. The binding prevents replay across sessions.

**Known limitation: no AAD.** Note ID and owner pubkey are not bound to the ciphertext as Associated Authenticated Data. A server-side attacker with direct write access to the database could swap two ciphertexts that belong to the same user. They cannot cross-swap between users because the keys differ, and they cannot read either blob. Fixing this requires a ciphertext format migration, which we'd rather do once, carefully, than rush.

## PIN protection

The optional 4-digit PIN is a UI gate, not a cryptographic boundary. It's there to keep someone glancing at your screen from opening your phrase modal or a sensitive note. It is not designed to resist someone who already has your phrase (which decrypts everything regardless) or someone who can extract the local storage hash and brute-force it offline.

What it does:

- PBKDF2-SHA256, 600,000 iterations, 16-byte random salt, 256-bit output.
- Constant-time comparison on verify.
- Exponential lockout in the UI after 5 wrong attempts, doubling each round. Counter lives in localStorage so closing a tab doesn't reset it. Same counter applies across every PIN entry surface in the app.

What it doesn't do:

- 4-digit PINs have 10,000 values. 600k PBKDF2 iterations slow this down enough that mashing the UI is hopeless, but an attacker with the hash and modern hardware brute-forces it in minutes to hours. We're upfront about this. If you want stronger protection, rely on OS-level disk encryption and screen lock. The phrase storage guidance in the app says as much.

Locked notes and PIN-protected notes carry flags inside the ciphertext. They are hidden or gated by the client. They are not separately encrypted, because layering a second key derived from the PIN would mean losing those notes if you forget the PIN. We treat lock/PIN-protect as organizational privacy, not cryptographic access control. This is a trade we've made deliberately.

## Sync

Pull-then-push, last-write-wins by `updated_at`. If you edit the same note offline on two devices, the later timestamp wins on next sync and the earlier edit is lost. No CRDT, no merge UI. This is a known limitation and accepted for the current version.

Deletes are hard deletes and propagate to the server during the push phase.

## What we measure

The server-side data we hold beyond ciphertext and the pubkey identifier:

- **Device records**, one per registered device per account. Stores `device_id`, `device_name` (user-entered text), a coarse `platform` label (`web` / `desktop` / `ios` / `android`), `created_at`, `last_seen_at`, an optional `revoked_at`, and a `device_group` identifier we use to keep multiple browser installs on the same physical machine within one slot.
- **Device-grouping hashes**, four per device. Each is HMAC-SHA256 of a coarse environment signal (OS family, WebGL renderer, CPU core count, browser language), computed on your device using a pepper derived from your BIP-39 phrase. Purpose: keep multiple browsers on the same physical machine within one device slot for free-tier limits - not behavioral tracking, not advertising, not shared with anyone. The server never sees the raw values and cannot reverse the hashes without the pepper, which lives only on your device. Because the pepper is per-user, the same hardware produces different hashes for different accounts - we cannot correlate a device across accounts. Caveat: browser updates and hardened browsers (Brave, Mullvad, Tor) can change the underlying signals; if that happens, your device may be placed in a new slot until the old record is pruned or revoked. You won't be locked out, but you may temporarily consume an extra slot.
- **Per-account quotas**: counters for the number of notes, total ciphertext bytes, and image bytes you currently hold. Used to enforce free vs. Pro storage caps. Derived from the data you've stored, not from anything you've told us about yourself.
- **Subscription records** if you've bought Pro or extra storage through Paddle. Includes a payment provider subscription id and your pubkey. Email and billing details are held by Paddle as Merchant of Record, not by us.
- **Aggregate operator dashboards**: signups per day, retention cohorts, activation funnel, totals, platform breakdown (web vs. desktop vs. mobile). All computed in-database from the records above. No individual content is involved, and no cross-user fingerprint correlation is possible.

What we explicitly do not collect or persist on accounts: user-agent strings, geolocation, behavioral telemetry, analytics events tied to note content, or anything that lets us reach you outside the app. We do not run third-party JavaScript on the application.

What does touch IP addresses, honestly: Cloudflare and Supabase transiently process them at the network layer for routing and abuse prevention, and we use them for the IP-level rate limits described under "Quotas and abuse protection." We do not write IPs into user records or associate them with content. They exist where the stack inherently sees them, and nowhere else.

## OAuth users (Google, Apple)

OAuth is a convenience entry point. The user's recovery phrase is generated on their device at first sign-in and never leaves it, exactly as in the phrase flow. OAuth provides three things: a one-click way to return on a known device, abuse protection (Google/Apple have already proved the user is a real human), and a stable identity to attach things like Pro subscriptions to.

OAuth is **not** a key recovery mechanism. If you sign in on a new device with Google or Apple, we will recognize you, but we cannot unlock your data for you - your encryption keys live only on the devices you've used before. You'll be asked to type your phrase or scan a QR sign-in code from an existing device. This is the same model WhatsApp and Telegram use: identity is one thing, key material is another, and we never conflate them.

## What we trust

- **Your device and browser.** If the operating system is compromised or the browser is malicious, none of the above helps. This is the universal limit of in-app encryption.
- **The cryptographic libraries.** `@noble/ciphers`, `@noble/hashes`, `@noble/ed25519`, `@scure/bip39`. Audited and widely deployed.
- **The frontend bundle.** Frontend assets built from this codebase and served over Cloudflare. A compromised CDN deployment could ship malicious JavaScript that exfiltrates the phrase. This is the standard supply-chain risk for any web app. We have not yet added Subresource Integrity or reproducible web builds. Code-signed native builds would structurally narrow this trust boundary - they are on the roadmap and not yet shipped.

## What we don't protect against

- A compromised endpoint. Malware on your machine reads plaintext while the app is unlocked, same as any E2E system.
- A targeted adversary with custodial access to your unlocked device.
- You losing your recovery phrase. There is no reset. We chose this on purpose; a recoverable phrase would be a backdoor.
- Social engineering. Nobody from PrivacyNotes will ever ask for your phrase. If someone does, they are not us.
- Denial of service against our infrastructure providers.
- Future cryptographically relevant quantum computers, eventually. XChaCha20-Poly1305 at 256-bit keys remains strong against Grover-class attacks; Ed25519 does not against Shor. This is not a near-term practical concern but is worth noting.
- Server-side deletion. The server cannot read your notes, but it can drop the rows. Because the sync engine is pull-then-push with last-write-wins, a compromised server (or anyone who obtains valid session credentials) can delete notes server-side, and the next sync will propagate the deletion to your local copy. Encrypted local exports are the only mitigation we offer today; a snapshot-style local backup that survives a hostile server pull is on the list.

## Quotas and abuse protection

- Cloudflare Turnstile on signup.
- 1 MB CHECK constraint on each ciphertext row.
- Per-user quotas enforced by Postgres triggers (10,000 notes, 50 MB free, 500 MB Pro).
- Anonymous accounts that never link a pubkey are purged after 30 days by a scheduled job.
- IP-level rate limiting on signup and sync.

## Audit status

No third-party audit has been performed yet. The project is pre-revenue. The first significant spend out of beta revenue is a third-party security audit, with Cure53 as the target firm. We've reached out for a scoping conversation. We'd rather state this plainly than wave at "audit coming soon."

In the meantime, the cryptographic code lives in this open-core repo so anyone who wants to inspect or critique the design can do so without trusting our word for it.

## Reporting a vulnerability

Email privacynotes@lifetimelabs.dev. If a fix requires coordination, we'll work with you on timing before public disclosure. We don't currently run a paid bounty program; we'd like to once it's responsibly affordable.
