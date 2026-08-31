/**
 * Dataset for the /markdown-editor landing page.
 *
 * This file must stay FREE OF IMPORTS of any kind: landing-pages.ts
 * transpiles it standalone and evaluates it as a data-URL module (same as
 * src/guides.ts). Registry items (chips, benefits, FAQs) are referenced by
 * string id and validated at build time. Price mentions use {price},
 * {earlyPrice}, {proPrice} tokens - never literal dollar amounts.
 * Editable by hand or via the local builder: pnpm landing:builder.
 * Spec: ops/docs/plans/marketing-pages.md (these landing pages are English only, permanently)
 */
export default {
  kind: 'feature',
  slug: 'markdown-editor',
  seo: {
    title: 'Free Markdown Editor - Private, No Signup | PrivacyNotes',
    description:
      'Write markdown in your browser with live preview. No account, no signup. Your notes are encrypted end-to-end and never readable by anyone but you.',
    breadcrumb: 'Markdown editor',
  },
  hero: {
    badge: 'Free, in your browser, right now',
    h1: 'Free markdown editor. Private by default.',
    sub: 'Live preview, keyboard-first, works offline. No account to start writing, and when you do sync, your text is encrypted on your device before it goes anywhere. We could not read your drafts if we tried.',
    cta: 'Start writing, no signup',
    ctaSecondary: 'Download the apps',
    micro:
      'The button opens the live demo: a full editor seeded with examples, saving nothing.',
    editorLines: [
      { text: '# Draft: launch post', cls: 'h' },
      { text: '', cls: '' },
      { text: 'We built this because every "free" editor', cls: '' },
      { text: 'wanted an account first, then our **data**.', cls: '' },
      { text: '', cls: '' },
      { text: '- Live preview as you type', cls: '' },
      { text: '- [x] ship the editor', cls: 'done' },
      { text: '- [ ] write this post', cls: '' },
      { text: '', cls: '' },
      { text: 'See also [[pricing-thoughts]]', cls: 'lk' },
      { text: '', cls: '' },
      { text: 'Your words, your disk, your key.', cls: '' },
    ],
  },
  chips: ['free-forever', 'zero-knowledge', 'swiss-servers', 'no-subscription', 'open-source'],
  benefitsIntro: {
    kicker: 'Why this one',
    h2: 'Markdown editors are easy. Private ones are not.',
    lead: 'Most "free online editors" are a signup funnel with a text area attached. This is the opposite: a real editor first, and an architecture around it engineered so nobody upstream can read what you write.',
  },
  benefits: [
    'real-editor',
    'private-architecture',
    'note-links',
    'tasks-surface',
    'plain-files',
    'offline-first',
  ],
  disk: {
    kicker: 'Your notes, on your disk',
    h2: 'It can work on a folder of plain .md files',
    body1:
      'On desktop, point PrivacyNotes at a folder of markdown files and work on them in place: edits save straight back to disk as plain .md, nothing is imported into a silo.',
    body2:
      'And when you sync that folder across devices, the sync is end-to-end encrypted, and it is {price} once, not a yearly plan.',
    micro: 'Files stay yours either way: any other editor can open them tomorrow.',
    tree: [
      { text: 'notes/', cls: 'dir' },
      { text: '  projects/', cls: 'dir' },
      { text: '    launch-post.md   <- editing now', cls: 'hl' },
      { text: '    pricing-thoughts.md', cls: '' },
      { text: '  journal/', cls: 'dir' },
      { text: '    2026-08-19.md', cls: '' },
      { text: '  readme.md', cls: '' },
    ],
  },
  generic: {
    kicker: 'The honest table',
    h2: 'Against the typical online editor',
    lead: 'No names needed; you know the pattern. A text box, a mandatory account, and your words in someone else’s database.',
    rows: [
      {
        label: 'Start writing without an account',
        us: 'Yes',
        them: 'Rarely',
        themNote: 'Signup wall first, editor second',
      },
      {
        label: 'Provider can read your text',
        us: 'No',
        usNote: 'Encrypted on your device before sync',
        them: 'Yes',
        themNote: 'Plaintext in their database',
      },
      { label: 'Works offline', us: 'Yes', them: 'Usually not' },
      {
        label: 'Your files as plain .md',
        us: 'Yes',
        usNote: 'Import and export, or live on a folder',
        them: 'Sometimes',
        themNote: 'Export buried or partial',
      },
      {
        label: 'Price of sync',
        us: 'Free (2 devices)',
        usNote: 'Pro: {price} once, unlimited devices',
        them: 'Subscription',
        themNote: 'Or "free", paid with your data',
      },
    ],
  },
  cheatsheet: {
    kicker: 'Reference',
    h2: 'The markdown you need, on one screen',
    lead: 'Everything below works in the editor exactly as written. Paste this page into the demo and watch it render.',
    cols: [
      [
        { syn: '# Heading', res: 'heading' },
        { syn: '**bold**', res: 'bold' },
        { syn: '*italic*', res: 'italic' },
        { syn: '~~strike~~', res: 'strikethrough' },
        { syn: '`code`', res: 'inline code' },
        { syn: '``` fence', res: 'code block' },
      ],
      [
        { syn: '- item', res: 'bullet list' },
        { syn: '- [ ] task', res: 'checkbox, shows in Tasks too' },
        { syn: '> quote', res: 'block quote' },
        { syn: '[text](url)', res: 'link' },
        { syn: '[[note title]]', res: 'note-link to another note' },
        { syn: '| a | b |', res: 'table' },
      ],
    ],
  },
  how: {
    kicker: 'Zero friction',
    h2: 'From this page to writing in one click',
    steps: [
      {
        title: 'Open the demo',
        body: 'A full editor in your browser, seeded with examples. Nothing is saved, nothing is sent, nobody asks for an email.',
      },
      {
        title: 'Bring a real draft',
        body: 'Paste something you are actually writing. Try the shortcuts, the preview, the source view, a note-link.',
      },
      {
        title: 'Keep it, if it fits',
        body: 'Create a vault with a 12-word phrase. From then on your notes encrypt on your device and follow you everywhere.',
      },
    ],
  },
  faqIntro: { kicker: 'Questions', h2: 'What "free" actually means here' },
  faq: [
    {
      q: 'Is it actually free, or a trial?',
      a: 'Free forever, no time limit, no credit card. Markdown editing, live preview, sync across 2 devices, import and export: all on the free tier. Pro ({price} once, not a subscription) adds unlimited devices, note history, PIN-protected notes and more storage.',
    },
    'account-needed',
    {
      q: 'Where is my text stored?',
      a: 'On your device first. If you sync, an end-to-end encrypted copy goes to Swiss servers that cannot decrypt it: the key never leaves your machine. The encryption code is public, and you can watch the ciphertext leave your browser in the network tab.',
    },
    {
      q: 'Can I use my existing markdown files?',
      a: 'Yes, three ways: import a folder of .md files, drop in exports from Obsidian, Notion or any markdown app, or, on desktop, work on a folder in place so edits save straight back to disk.',
    },
    'export-leave',
  ],
  band: {
    h2: 'The editor is one click away',
    sub: 'No signup, no install, no cookie wall. Open it, paste a draft, decide for yourself.',
    cta: 'Open the editor',
    micro: 'Free forever. No credit card. No account until you want sync.',
  },
  sticky: { text: 'Full editor, zero signup.', cta: 'Start writing' },
  mesh: {
    compare: ['vs-standard-notes'],
    guides: ['obsidian', 'markdown'],
  },
};
