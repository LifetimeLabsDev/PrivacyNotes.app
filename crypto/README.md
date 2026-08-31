# crypto

The encryption layer, at the top of the repository because it is what most
people come here to read.

These two files are copies. The canonical source is
[`application/packages/shared/src/`](../application/packages/shared/src), which is
what the apps actually build against. The copies exist so the link is short.
If the two ever disagree, the one under `application/` is the real one, and
the difference is a bug worth reporting.

| File | What it does |
| :--- | :--- |
| `crypto.ts` | Phrase to seed, key derivation, note encryption and decryption, the signing key. |
| `blob.ts` | The same encryption applied to attachments and images. |

[`../VERIFY.md`](../VERIFY.md) walks through what to check here and what a
backdoor would look like, which is more useful than reading top to bottom.

## Licence history

This repository is AGPL-3.0 today. Earlier releases of these two files were
published under the MIT licence.

That earlier grant still stands for anyone who already holds a copy of those
releases. A licence change applies going forward and is not retroactive, and
we would rather write that down than let anyone assume otherwise.
