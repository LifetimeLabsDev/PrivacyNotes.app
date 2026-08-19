# Verify it yourself

You should not have to take our word for any of this.

This page is three ways to check that PrivacyNotes encrypts your notes on your device before they reach our server. They take about a minute, about ten minutes, and about a weekend. The first one needs nothing but a browser, and it is the one that actually settles the question.

Accurate as of v0.413.1 (2026-08-19). The payloads below are real, captured from an actual sync.

**One caveat before you start.** Everything below describes self-custody, which is the default and what you get from a 12-word phrase. If you signed up with Google or Apple and chose the custodial option, your phrase is stored on our server encrypted under a server-held key, which means the server can decrypt your notes. That is a deliberate convenience mode with a real cost, it is spelled out in [THREAT_MODEL.md](THREAT_MODEL.md), and tier 1 below will still show you ciphertext on the wire either way.

---

## Tier 1: one minute, no tools

You need a browser. You do not need an account you care about, an email address, or a build toolchain.

1. Open the app and create an account. It is 12 words, generated in your browser. No email, no password.
2. Open your browser's developer tools (F12) and select the **Network** tab.
3. Type something into a note that you would never find anywhere else. Something like `platypus-hovercraft` works.
4. Leave the note, or press the sync indicator at the bottom of the window. Writes are batched, so they do not go out on every keystroke.
5. Find the request to `sync.privacynotes.app/rest/v1/notes` and look at its payload.

The first time a note is saved you get the full row:

```json
{
  "id": "84c337d5-0fc6-428a-bc4b-8ae612a79580",
  "user_pubkey": "d839f864ff0bf1f6dc51e045f030cd23...",
  "ciphertext": "cALuFuhqcjRpsfS3t4CITLKL1pZHliIpdSkuboFvJCR1qBAlEdpA4Q9b...",
  "nonce": "Gb9HxuYo4+VVtcEEfo9NIEwKn8g243vS",
  "created_at": "2026-08-19T13:05:06.161Z",
  "updated_at": "2026-08-19T13:05:34.149Z"
}
```

Every later edit to that note sends even less, because the row already exists:

```json
{
  "ciphertext": "GRUUN9plghgaXzepWTnqImR3B/BO5aWQ+l4wfTWJT4DPGijmqgpn9jdQ...",
  "nonce": "Fo5PS4c/GAYyTI5rp4ChoB7ckkiP3E7j",
  "updated_at": "2026-08-19T13:05:34.149Z"
}
```

Now the actual test: **use find-in-page on that payload and search for `platypus-hovercraft`.** Zero hits. Search for your note's title. Zero hits. The only thing carrying your words is `ciphertext`, and it is a base64 blob we have no key for.

**The stronger version of the same check, if you want it.** Do not filter the network list at all. Type your note, let it sync, and look at every request the app made. There should be exactly one host in that list, `sync.privacynotes.app`, and your word should appear in none of them: not in a body, not in a URL, not in a query string. No analytics host, no error reporter, no third party of any kind. That check is harder to fake than the first one, and it takes about the same amount of time.

That is the whole claim, and you just checked it without trusting us, reading any code, or waiting for an audit.

### What else you can see, and what it means

Be suspicious of anyone who shows you only the good part, so here is the rest of that payload:

- **`user_pubkey`** is your public identity, derived from your phrase. The server needs it to know which rows are yours. It also rides in the query string of update and fetch requests, for the same reason.
- **`id`, `created_at`, `updated_at`** are the note's id and timestamps, in the clear. Our server therefore knows how many notes you have and when you touched them. It cannot know what any of them say.
- **`nonce`** is a fresh 24 random bytes for every single write. It is not secret and it is not a key.

That is the complete list. The full accounting of what our server can observe, including device records and quota counters, is in [THREAT_MODEL.md](THREAT_MODEL.md).

### The thing you will find next, so let us get to it first

If you keep poking around developer tools, your next stop is **Application, then IndexedDB**, and there you will find your notes sitting in plain text on your own disk. Specifically: database `privacynotes`, store `notes`, with `title` and `body` in the clear. Search it for `platypus-hovercraft` and this time you get a hit.

That is deliberate, and it is not a hole in the above.

Encryption protects your notes from us and from anyone in between. On your own device, the key is also on your device, so encrypting local storage with it would protect you from nobody: anything that can read the database can read the key sitting next to it. What actually protects data on your machine is your operating system's full-disk encryption and your screen lock, which is a boundary we cannot implement for you and should not pretend to.

The consequence, stated plainly: **someone with access to your unlocked device can read your notes.** The PIN and biometric options in the app are convenience gates against a borrowed laptop, not cryptography, and we describe them that way everywhere. See "Local storage at rest" in [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Tier 2: ten minutes, reading code

About 300 lines decide everything. They are in [`crypto/crypto.ts`](crypto/crypto.ts), and four functions are the whole story:

| Function | What to check |
| :--- | :--- |
| `phraseToSeed` | Your 12 words become a 64-byte BIP-39 seed. Standard, offline, no network. |
| `deriveEncryptionKey` | HKDF-SHA256 over that seed with the info string `privacynotes-encryption-v1` produces the 32-byte content key. Same phrase, same key, on every device, with nothing to fetch. |
| `encryptNote` | XChaCha20-Poly1305. A fresh random 24-byte nonce per write. Title, body, tags, flags, tracker data and folder id all go inside one JSON blob before encryption, so none of them leak as separate fields. |
| `decryptNote` | The inverse. Wrong key or tampered ciphertext throws on the Poly1305 authentication check rather than returning garbage. |

Identity works the same way: `deriveSigningKey` derives an Ed25519 keypair from the same seed under a different info string, and the public half is your user id. Signatures authenticate sensitive operations like registering or revoking a device.

**What a backdoor would look like, so you know what to look for.** This is more useful than "read the code":

- The encryption key, the seed, or the phrase being sent anywhere. Follow `deriveEncryptionKey`'s return value and check that it only ever reaches `encryptNote` and `decryptNote`.
- A second recipient. Anything encrypting the same note twice, or wrapping the content key under a second public key, would be key escrow. There is one key.
- A predictable or reused nonce. It is `randomBytes(24)` on every call.
- Plaintext on the wire. Tier 1 already covers this from the outside.

The encryption layer and the database schema are published today. The full client source follows when the native apps have shipped, alongside a third-party audit, and both are covered below.

---

## Tier 3: a weekend, building it

This is the hardest question in the whole category, and we are not going to pretend it is solved.

**What you can check today.** Every release binary is signed, and we publish hashes with each release. Verify the signature and the hash and you know the file you downloaded is the file we built.

**What that does not prove.** It does not prove that the file we built came from the source we published. Answering that needs reproducible builds, where you build from source and land on byte-identical output. We consider the Android APK and the Linux AppImage the realistic targets, and it is on the roadmap rather than shipped. We will say so on this page when that changes, and not before.

**The web app is the weakest case and always will be.** JavaScript served over the web can in principle be changed per user, per session, and no amount of published source fixes that, for us or for anyone else in this category. If that is inside your threat model, use the desktop or mobile app, where you at least hold a signed artifact that does not change under you between visits.

We would rather write that down than let you find out later.

---

## What is published today, and what follows

| | Status |
| :--- | :--- |
| Encryption layer (`crypto/`) | Published |
| Database schema and access rules (`schema/`) | Published |
| Threat model | Published |
| Full client source (web, desktop, mobile) | Committed, ships when the native apps have shipped |
| Sync protocol specification | Ships with the client source |
| Third-party security audit report | Planned, published in full or in summary when it is done |
| Sync backend | Stays closed. See below |

**On the backend.** Our sync server is not open source and we are not going to imply otherwise. The design point is that it does not need your trust: it holds ciphertext, nonces, a public key and timestamps, which is exactly what tier 1 lets you confirm from the outside without any cooperation from us. The parts of the system whose behaviour you actually have to trust, the code that holds your key and does the encrypting, are the parts we publish.

Independent verification of the closed remainder is what the third-party audit is for, and we will link the report here when it exists rather than asking for credit in advance.

---

## Found something?

If any of the above does not hold up on your machine, we want the report more than we want to be right. Security contact and disclosure policy are in [SECURITY.md](SECURITY.md).
