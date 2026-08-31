# Contributing

This repository does not work the way most do, and two minutes here will save you an afternoon.

## What this is

The client applications: web, desktop and mobile, published in full.

The tree is a filtered copy of the repository we develop in, regenerated one commit at a time. The merge button is never used here.

## Code contributions: not yet

We are not taking code contributions at this stage. The mirror pipeline is one-way, review capacity is one person, and absorbing external patches well takes machinery we have not built. A pull request will be read and closed with thanks, and nothing from it is taken quietly. An approved-contributors model may come later; this file will say so when it does.

What we DO want, today:

- **Bug reports.** An [issue](../../issues) with steps beats a patch we cannot take.
- **Translation feedback.** If something reads wrong in your language, open a [translation issue](../../issues/new?template=translation.yml). The wrong gender, a robotic phrasing, a word nobody says. You see it instantly and we never would. Do not send catalog edits: a catalog has to move in every language at once, so those are made upstream in one pass.
- **Security reports.** Never as a public issue: [SECURITY.md](SECURITY.md) has the address and the PGP key.

## Build it yourself

The code is AGPL-3.0: build it, run it, patch your own build, fork it (see [NOTICE.md](NOTICE.md) for the marks).

```
cd application
pnpm install
pnpm build
```

Node 22 or later, and pnpm. That is the whole setup for the web app. `pnpm dev` runs it on localhost.

The desktop app builds for the machine you are on. It needs the [Rust toolchain](https://rustup.rs) on top, plus [Tauri's system packages](https://tauri.app/start/prerequisites/) on Linux:

```
pnpm desktop:build
```

The result is unsigned and does not self-update. Release signing and the update pipeline use our keys, which are not in this repository, so no one else can build a release that passes for ours.

To check a build the way we do:

```
pnpm typecheck   builds the shared package, then type-checks web
pnpm test:crypto known-answer tests for the encryption
pnpm test:backup known-answer tests for the .pnbackup format
```

The last two are the proof [VERIFY.md](VERIFY.md) offers a reader; a change that turns them red is a change that breaks somebody's existing notes. They pin the encryption and the backup format against committed vectors, so they answer the question a stranger actually has, which is whether the crypto does what we say.

Our wider unit and integration suites run upstream and are not published here, so a pull request is checked against them by us rather than by you.

The scripts block holds only what works: it is recomputed when this tree is built, so a script whose tool we did not publish is removed rather than left here to fail on you. House checks that read private files (style rules, translation staleness, dead-code analysis) live upstream.

## Reading the code

Comments carry `// Spec:` pointers into our internal design documents, and `backlog #N` into our tracker. Neither is published here, and neither is a broken link: the comment states the constraint, and the pointer only records which document owns it.

Four of those documents ARE here, under the names they are published as, and code that cites them uses the name you can open: [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), [VERIFY.md](VERIFY.md), and the protocol spec in [docs/](docs/).

## License

The published tree is AGPL-3.0. The name, the wordmark and the icon are outside that grant; [NOTICE.md](NOTICE.md) covers them.
