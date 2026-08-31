# Verify it yourself

You should not have to take our word for any of this.

This page is three ways to check that PrivacyNotes encrypts your notes on your device before they reach our server. They take about a minute, about ten minutes, and about a weekend. The first one needs nothing but a browser, and it is the one that actually settles the question.

Accurate as of v0.488.3 (2026-08-31). The payloads below are real, captured from an actual sync.

**One caveat before you start.** Everything below describes self-custody, the default. If you signed up with Google, Apple or GitHub and chose the custodial option, the server holds your phrase and can decrypt your notes - the trade is spelled out in [SECURITY.md](SECURITY.md) - though tier 1 still shows you ciphertext on the wire either way.

---

## Tier 1: one minute, no tools

You need a browser. You do not need an account you care about, an email address, or a build toolchain.

1. Open the app and create an account. It is 12 words, generated in your browser. No email, no password.
2. Open your browser's developer tools (F12) and select the **Network** tab.
3. Type something into a note that you would never find anywhere else. Something like `platypus-hovercraft` works.
4. Leave the note, or press the sync indicator at the bottom of the window. Writes are batched, so they do not go out on every keystroke.
5. Find the request to `sync.privacynotes.app/rest/v1/notes` and look at its payload.
6. Then switch to the **Application** tab, open **IndexedDB**, database `privacynotes`, store `notes`, and search it for the same word.

Step 5 shows you what leaves your machine. Step 6 shows you what stays on it. Both come back with no hit, and the second one is the newer claim, so it is worth doing rather than reading about.

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

**The stronger version of the same check, if you want it.** Do not filter the network list at all. Type your note, let it sync, and look at every request the app made. **Your words appear in none of them: not in a body, not in a URL, not in a query string.** That is the claim, and it is the one worth checking.

You will see more than one host, so here is the complete list of what can appear and why, before you find it yourself:

- **`use.privacynotes.app`**, which served the app you are looking at.
- **`sync.privacynotes.app`**, carrying the ciphertext from tier 1.
- **`/favicon?domain=...`**, if your note contains a link. To draw the little site icon next to a link, the app asks our proxy for that icon by domain, so the DOMAIN you typed is in that URL. Not the note, not the link's path, just the domain. It is on by default and you can switch it off in Settings under Appearance. It is the one place where something you typed leaves the device in readable form.
- **`challenges.cloudflare.com`**, only if the sign-up gate asked you to prove you are human. It is a bot check and it loads only when there is a challenge.
- **Nothing from a payment processor.** Buying opens a separate checkout page on `privacynotes.app`, so Paddle's script runs there and never in the app you are inspecting. If you want to watch it, do that on the checkout tab; this tab stays clean.

No analytics host, no error reporter, and nothing else at all. The desktop and mobile apps do not load Turnstile. That check is harder to fake than the first one, and it takes about the same amount of time.

That is the whole claim, and you just checked it without trusting us, reading any code, or waiting for an audit.

### What else you can see, and what it means

Be suspicious of anyone who shows you only the good part, so here is the rest of that payload:

- **`user_pubkey`** is your public identity, derived from your phrase. The server needs it to know which rows are yours. It also rides in the query string of update and fetch requests, for the same reason.
- **`id`, `created_at`, `updated_at`** are the note's id and timestamps, in the clear. Our server therefore knows how many notes you have and when you touched them. It cannot know what any of them say.
- **`nonce`** is a fresh 24 random bytes for every single write. It is not secret and it is not a key.

That is the complete list. The full accounting of what our server can observe, including device records and quota counters, is in [THREAT_MODEL.md](THREAT_MODEL.md).

### What step 6 showed you, and what it does not buy

The rows in that store are not your notes. Each one carries `sv: 1` and a `sealed` field holding a nonce and a ciphertext, and the title, body, tags and tracker data live inside that ciphertext. That is why the search came back empty. The rows are sealed with XChaCha20-Poly1305 under a key derived from your phrase (the `privacynotes-local-at-rest-v1` branch in the same key table below), and the ciphertext is bound to its own row and table, so a blob moved onto another row fails to open instead of decrypting.

One panel over, in **Local Storage**, sits the root secret: the key `privacynotes.phrase`. Its value starts with `pnwrap1:` - an AES-GCM envelope, not your twelve words. The key that opens it lives in IndexedDB as a non-extractable WebCrypto key, which the browser will use but never hand to script, so a copied localStorage file or a storage backup does not carry your phrase in readable form. With the PIN app lock enabled, that envelope is removed entirely and the phrase exists only wrapped under your PIN.

Be clear about what all of this does not buy, because the honest limits have not moved: code running in the app's origin on your machine can use the keys; someone with your live browser profile boots the app signed in; and while the app runs, your notes are plaintext in memory - that is what an app that shows you your notes is. Two timing caveats worth knowing: existing rows seal on the first unlock after the update that introduced sealing, and browser storage engines keep old values in free disk pages for a while after rewriting, so "everything on disk is ciphertext" becomes fully true a little after it becomes mostly true. What protects an unlocked machine is still OS disk encryption and your screen lock. The full accounting, including every field that stays readable for the indexes, is "Local storage at rest" in [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Tier 2: ten minutes, reading code

About 560 lines decide everything. They are in [`crypto/crypto.ts`](crypto/crypto.ts), and these functions are the whole story:

| Function | What to check |
| :--- | :--- |
| `phraseToSeed` | Your 12 words become a 64-byte BIP-39 seed. Standard, offline, no network. |
| `deriveEncryptionKey` | HKDF-SHA256 over that seed with the info string `privacynotes-encryption-v1` produces the 32-byte content key. Same phrase, same key, on every device, with nothing to fetch. |
| `deriveLocalDataKey` | The same HKDF construction under `privacynotes-local-at-rest-v1` produces the key that seals rows in your own browser storage. Disjoint from the sync key by its info string, so a local ciphertext can never pass as a server row or the reverse. |
| `encryptNote` | XChaCha20-Poly1305. A fresh random 24-byte nonce per write. Title, body, tags, flags, tracker data and folder id all go inside one JSON blob before encryption, so none of them leak as separate fields. |
| `decryptNote` | The inverse. Wrong key or tampered ciphertext throws on the Poly1305 authentication check rather than returning garbage. |

Identity works the same way: `deriveSigningKey` derives an Ed25519 keypair from the same seed under a different info string, and the public half is your user id. Signatures authenticate sensitive operations like registering or revoking a device.

**What a backdoor would look like, so you know what to look for.** This is more useful than "read the code":

- The encryption key, the seed, or the phrase being sent anywhere. Follow `deriveEncryptionKey`'s return value and check that it only ever reaches `encryptNote` and `decryptNote`.
- A second recipient. Anything wrapping the content key under a second key, or encrypting for anyone but you, would be key escrow. There is one key. (Note history is not that: a version row is the same note encrypted again under the SAME key, so what to look for is a second KEY, never a second ciphertext.)
- A predictable or reused nonce. It is `randomBytes(24)` on every call.
- Plaintext on the wire. Tier 1 already covers this from the outside.

The encryption layer and the full client source are published today. The third-party audit follows, and the status of both is covered below.

---

## Tier 3: a weekend, building it

This is the hardest question in the whole category, for us and for everyone else.

**What you can check today.** The full client source is in this repository, and it builds:

```
cd application
pnpm install
pnpm build          # the web app
pnpm desktop:build  # the desktop app, for the machine you are on
```

No secrets, no signing keys, no cooperation from us. Run what you built, point your network tab at it, and tier 1 applies to your own binary. Separately, every release we ship is signed and published with hashes, so you can confirm a downloaded file is the file we built.

**What that does not prove.** It does not prove that the binary we ship came from the source you just read. Answering that needs reproducible builds, where your build and ours land on byte-identical output. We consider the Android APK and the Linux AppImage the realistic targets, and it is on the roadmap rather than shipped. We will say so on this page when that changes, and not before.

**The web app is the weakest case and always will be.** JavaScript served over the web can in principle be changed per user, per session, and no amount of published source fixes that, for us or for anyone else in this category. If that is inside your threat model, use the desktop or mobile app, where you hold a signed artifact that does not change under you between visits.

---

## What is published today, and what follows

| | Status |
| :--- | :--- |
| Encryption layer (`crypto/`) | Published |
| Threat model | Published |
| Full client source (web, desktop, mobile) | Published, in [`application/`](application/) |
| Sync protocol specification | Published, in [`docs/`](docs/) |
| Third-party security audit report | Planned, published in full or in summary when it is done |
| Sync backend, including the database schema | Closed. See the note under this table |

The sync backend is closed because the hosted service is what funds the product, and the database schema is part of it. Nothing in the three tiers depends on either. The client you can read encrypts before upload, and tier 1 shows you from the outside exactly what reaches the server: ciphertext, nonces, a public key and timestamps, and nothing else. That is a stronger check than reading our table definitions, because it measures what actually leaves your machine rather than what we say we store. If self-hosting ever ships, the schema ships with it.


---

## Found something?

If any of the above does not hold up on your machine, we want the report more than we want to be right. Security contact and disclosure policy are in [SECURITY.md](SECURITY.md).
