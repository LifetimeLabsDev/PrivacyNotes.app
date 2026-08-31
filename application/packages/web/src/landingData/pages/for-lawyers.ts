/**
 * Dataset for the /for/lawyers audience page.
 *
 * This file must stay FREE OF IMPORTS of any kind: landing-pages.ts
 * transpiles it standalone and evaluates it as a data-URL module (same as
 * src/guides.ts). Registry ids are validated at build time. Price tokens:
 * {price}, {earlyPrice}, {proPrice}.
 *
 * Claims discipline: never a compliance certification (no HIPAA/GDPR seals,
 * no "privileged" guarantees), never legal advice. Claim architecture,
 * invite verification. The honesty box is load-bearing, keep it.
 * Spec: ops/docs/plans/marketing-pages.md (these landing pages are English only, permanently)
 */
export default {
  kind: 'for',
  slug: 'lawyers',
  seo: {
    title: 'Encrypted Notes for Lawyers - Zero-Knowledge | PrivacyNotes',
    description:
      'Client notes only you can read. End-to-end encrypted, Swiss servers, published cryptography, no account required. Built for confidential work.',
    breadcrumb: 'For lawyers',
  },
  hero: {
    kicker: 'PrivacyNotes for lawyers',
    h1: 'Encrypted note-taking for lawyers and law firms',
    sub: 'The DMS holds the record. Everything around it, the hunches, the strategy notes, the things a client said off the record, tends to end up in whatever notes app was closest. PrivacyNotes is a notebook with the confidentiality of your file room: every note encrypted on your device, readable by you and no one else. Not us, not a cloud provider, not anyone who asks us.',
    cta: 'Try the demo, no signup',
    ctaSecondary: 'How the encryption works',
    micro: 'The demo runs in your browser with example notes and saves nothing. Kick the tires before anything real goes in.',
  },
  chips: ['zero-knowledge', 'swiss-servers', 'no-email', 'open-source', 'no-subscription'],
  pains: {
    h2: 'The quiet problem with cloud notes',
    lead: 'Most notes apps can read everything you type: that is how their search, AI features and support tooling work. For confidential material, the app is not a tool, it is a counterparty.',
    items: [
      {
        q: '"My notes about a matter sit in some US cloud, readable by the provider."',
        a: 'Here they sit on Swiss servers as ciphertext. A provider that never holds a readable copy of your notes cannot leak one, sell one, train an AI on one, or be ordered to produce one.',
      },
      {
        q: '"If an account at the firm gets phished, what walks out the door?"',
        a: 'Nothing readable. Notes only decrypt with the 12-word phrase, which never touches a server. A stolen password is not a stolen key.',
      },
      {
        q: '"I draft on the train, in chambers, in a courthouse basement with no signal."',
        a: 'Everything is offline-first. Write with no connection at all; it encrypts locally and syncs sealed when you are back.',
      },
    ],
  },
  mechanism: {
    kicker: 'The mechanism, not a promise',
    h2: '"We cannot read it" is architecture, not policy',
    lead: 'A privacy policy is a promise that can change with an acquisition or a court order. Key custody cannot. Your key is derived from your 12-word phrase, on your device, and never leaves it.',
    plain: '"Client call: settlement floor is 40k, do not open below 60."',
    cap: 'Lose the phrase and even you cannot recover the notes. That is not a flaw, it is the proof: a provider who could reset your access could also read your files.',
  },
  timeline: {
    h2: 'A matter, start to close',
    lead: 'The same five features every confidentiality-critical profession leans on, walked through one representation.',
    steps: [
      {
        title: 'Intake',
        tag: 'PIN-protected notes',
        body: 'First conversation, conflict-check thoughts, the client’s own words. Keep the matter’s notes behind a second PIN: the contents stay hidden even when the laptop is open in a meeting.',
      },
      {
        title: 'Research and drafting',
        tag: 'Markdown + note-links',
        body: 'Strategy memos in markdown, connected with note-links so the theory of the case, the witness list and the timeline stay one click apart. Every checkbox across the matter shows up in one Tasks view.',
      },
      {
        title: 'Credentials and access',
        tag: 'Vault',
        body: 'Court portal logins, registry passwords, the client’s data-room access: in the vault, encrypted like everything else, instead of a sticky note or a browser profile.',
      },
      {
        title: 'On site',
        tag: 'Offline-first',
        body: 'Hearing prep in the corridor, notes during the hearing, no wifi anywhere. It all works fully offline and syncs sealed when you are back at the office.',
      },
      {
        title: 'Sharing and closing',
        tag: 'Burn After Reading + export',
        body: 'Hand a summary to co-counsel as a link that destroys itself after being read instead of living forever in an inbox. When the matter closes, export clean markdown for the file: nothing is trapped in a format.',
      },
    ],
  },
  verify: {
    kicker: 'Due diligence, invited',
    h2: 'Verify it like you would verify anything else',
    lead: 'You would not accept "trust us" from opposing counsel. Do not accept it from a notes app. Each claim below is checkable, most of them in minutes.',
  },
  honesty: {
    title: 'A word of care',
    body: 'PrivacyNotes is not practice-management software and we do not certify compliance regimes: no seal, no acronym, no letter of comfort. The claim is narrower and it is checkable: zero-knowledge architecture, published encryption code, Swiss hosting. Whether that satisfies your bar’s rules on client data is your call to make, and the design’s job is to give that assessment something solid to bite on. The official record belongs in your DMS; this is the notebook beside it.',
  },
  pricing: {
    kicker: 'What it costs',
    h2: 'Priced like a tool, not a per-seat platform',
    big: '$0 to evaluate, {price} once for Pro',
    body: 'The free tier is the whole app, smaller: all seven pillars including markdown, two devices. Pro is a one-time purchase that adds unlimited devices, note history, PIN-protected notes and 500 MB of encrypted files. No per-seat licensing, no annual renewal to expense every year.',
  },
  faqIntro: { kicker: 'Questions', h2: 'What counsel asks before trusting us' },
  faq: [
    {
      q: 'Can PrivacyNotes be compelled to hand over my notes?',
      a: 'We can be compelled to hand over what we hold, and what we hold is ciphertext plus minimal metadata. Keys are derived from your phrase and never reach us, so a readable version of your notes does not exist anywhere we can access. That is the difference between a promise not to look and an inability to look.',
    },
    {
      q: 'What exactly do you store about me?',
      a: 'With phrase sign-in: no email, no name, no phone number. The server sees encrypted blobs, sync timestamps and storage totals. The published threat model enumerates it precisely, because "what do they hold" should not be a mystery.',
    },
    {
      q: 'Is OneNote or Evernote secure enough for client notes?',
      a: 'They encrypt in transit and at rest, but the provider holds the keys: their staff, their search indexing and their AI features can technically read content. That is a policy promise, not an architectural guarantee. Zero-knowledge apps remove the provider from the trust equation entirely.',
    },
    {
      q: 'Do AI note-taking tools put confidentiality at risk?',
      a: 'Bar associations have been warning about exactly this: cloud AI notetakers process readable content on someone else’s servers. PrivacyNotes does no cloud AI processing; nothing readable exists server-side to process.',
    },
    {
      q: 'My laptop gets stolen. Then what?',
      a: 'Your notes are sealed on disk under a key derived from your phrase, so the drive alone gives up ciphertext. Use full-disk encryption and the app lock on top of that. PIN-protected notes sit behind an extra gate inside an unlocked app. Revoke the stolen laptop from any other signed-in device, and it stops syncing.',
    },
    'lose-phrase',
  ],
  band: {
    h2: 'Try it with fake notes first',
    sub: 'The demo runs in your browser and saves nothing. Use invented clients, test the PIN, watch the network tab. Then decide.',
    cta: 'Open the demo',
    micro: 'Free forever. No credit card. No email needed.',
  },
  sticky: { text: 'Zero knowledge, Swiss servers.', cta: 'Try the demo' },
  mesh: {
    compare: ['vs-standard-notes'],
    features: ['markdown-editor'],
  },
};
