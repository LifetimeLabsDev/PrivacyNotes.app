---
id: 5ec1
title: How your notes are protected
tags: privacy, encryption
folder: Security
order: 3
---

> [!info]- Every note is encrypted on your device, before it is stored anywhere.
> &nbsp;

![The notes table in our live database. Every note body is one long block of unreadable text.](/onboarding/database.webp)

That is our live database in Zurich, not a drawing of one. Your note goes in the `ciphertext` column. Encrypted bytes are all we store, whichever option you pick below.

## What happens when you write a note

1. Your 12-word phrase becomes a key. This happens on your device.
2. The note is encrypted with that key, on your device. That is how it is saved on your own disk, and how it travels to us.
3. We receive the encrypted note and store it. The screenshot above is what that looks like.
4. Any device with the same phrase makes the same key and opens the note.

## Who holds your key

Every option keeps your notes end-to-end encrypted. They differ in where your phrase lives.

| Option | Where your phrase lives | What that buys you |
| --- | --- | --- |
| **Login, key stored with us** | On our server, encrypted | A new device signs in with that login alone |
| **Login, key on your device** | With you, nowhere else | Sign in with Google, Apple or GitHub, and still hold the key |
| **Phrase only, no login** | With you, nowhere else | No email, no name, no login at all |

The bottom two mean we could not read a note even if we were compelled to. The first trades that away for convenience: your phrase sits on our server under a key of ours, so a new device needs nothing but your login. If our server were ever breached, that key could be exposed.

You are not locked into the one you picked. Change it in **Settings > Security > Your Phrase**.

> [!warning] Keep your own copy of the phrase
> Your phrase opens your notes. If you lose it, nobody can recover it for you, us included. <span style="color: #e03131">Write it on paper today.</span>

## Check it yourself

[Detailed verification instructions on GitHub](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Open your browser's Network tab, then edit a note. Watch what we receive: one block of unreadable text.
- [ ] Read the encryption code. It is public, and short enough to finish in one sitting.

| What | Where |
| --- | --- |
| The encryption itself | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| The database layout | [schema.sql](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/schema/schema.sql) |
| What an attacker can and cannot do | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| How to report a hole | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] One lock covers all of it
> Notes, journal entries, bookmarks, Vault items and file attachments are encrypted the same way. [[Moving in]] shows how to bring each of them across.
