// Per-locale marketing head data, shared by two consumers that must never
// disagree: seo.ts applies it in the browser after the bundle boots, and
// marketing-shell.ts bakes it into one pre-rendered index.html per locale at
// build time. The build copy is the one that matters for anything that does
// not run JavaScript - every social scraper, and most AI crawlers - so this
// module holds no DOM references and can be imported from Node.
//
// Copy lives here and nowhere else. Editing a title or description is a
// user-facing string change in every language we ship: it lands in every
// locale catalog in the same change, never English alone.

// Carries the .ts extension, unlike every other import under src/. This is
// the one src module that vite.config.ts pulls into its own graph (through
// marketing-shell.ts), and Vite's native config loader hands that graph to
// Node, which does not resolve an extensionless relative specifier. The app
// tsconfig sets `allowImportingTsExtensions` for this single import.
import { LOCALE_TO_SLUG } from './localeRoutes.ts';

export const ORIGIN = 'https://privacynotes.app';

export const HREFLANG: Record<string, string> = {
  en: 'en',
  de: 'de',
  fr: 'fr',
  it: 'it',
  es: 'es',
  nl: 'nl',
  pl: 'pl',
  'pt-PT': 'pt-PT',
  'pt-BR': 'pt-BR',
  ja: 'ja',
  ko: 'ko',
  'zh-TW': 'zh-TW',
  ca: 'ca',
  cs: 'cs',
  tr: 'tr',
  sv: 'sv',
  ar: 'ar',
  uk: 'uk',
  ru: 'ru',
  th: 'th',
};

/**
 * Extra hreflang values a locale answers to on top of its own code.
 *
 * Generic `pt` resolves to European Portuguese, not Brazilian. The readers who
 * land on a bare-language fallback are by definition the ones whose region
 * matched neither pt-BR nor pt-PT - Angola, Mozambique, Cape Verde,
 * Guinea-Bissau, Sao Tome, Timor-Leste, Macau - and every one of those follows
 * the European norm. Brazil has its own exact pt-BR match and never needs the
 * fallback. This also keeps the tags agreeing with preferredLocale() in
 * languages.tsx, which prefix-matches pt-AO and friends onto pt-PT.
 */
const HREFLANG_ALIASES: Record<string, string[]> = {
  'pt-PT': ['pt'],
  // Traditional Chinese answers to the generic script tag and to the two other
  // regions that read it. Mirrors the fallbackLng map in i18n.ts. Bare `zh` is
  // left off on purpose (it reads as Simplified).
  'zh-TW': ['zh-Hant', 'zh-HK', 'zh-MO'],
};

export const META: Record<string, { title: string; description: string }> = {
  en: {
    title: 'PrivacyNotes: Your Encrypted Vault for Notes, Tasks & Journals',
    description: 'Note down your thoughts, tasks, and journal - encrypted, always. End-to-end encrypted with zero tracking, hosted in Switzerland.',
  },
  de: {
    title: 'PrivacyNotes: Dein verschlüsselter Tresor für Notizen, Aufgaben und Tagebuch',
    description: 'Halte deine Gedanken, Aufgaben und dein Tagebuch fest - immer verschlüsselt. Ende-zu-Ende-verschlüsselt, ohne Tracking, gehostet in der Schweiz.',
  },
  fr: {
    title: 'PrivacyNotes : votre coffre chiffré pour notes, tâches et journal',
    description: 'Notez vos pensées, tâches et votre journal - toujours chiffrés. Chiffrement de bout en bout, sans suivi, hébergé en Suisse.',
  },
  it: {
    title: 'PrivacyNotes: il tuo caveau cifrato per note, attività e diario',
    description: 'Annota pensieri, attività e diario - sempre cifrati. Crittografia end-to-end, senza tracciamento, ospitato in Svizzera.',
  },
  es: {
    title: 'PrivacyNotes: tu bóveda cifrada para notas, tareas y diario',
    description: 'Anota tus pensamientos, tareas y diario - siempre cifrados. Cifrado de extremo a extremo, sin rastreo, alojado en Suiza.',
  },
  nl: {
    title: 'PrivacyNotes: jouw versleutelde kluis voor notities, taken en dagboek',
    description: 'Noteer je gedachten, taken en dagboek - altijd versleuteld. End-to-end versleuteld, zonder tracking, gehost in Zwitserland.',
  },
  pl: {
    title: 'PrivacyNotes: Twój zaszyfrowany sejf na notatki, zadania i dziennik',
    description: 'Zapisuj myśli, zadania i dziennik - zawsze zaszyfrowane. Szyfrowanie end-to-end, bez śledzenia, hostowane w Szwajcarii.',
  },
  'pt-PT': {
    title: 'PrivacyNotes: o teu cofre encriptado para notas, tarefas e diário',
    description: 'Anota os teus pensamentos, tarefas e diário - sempre encriptados. Encriptação ponta a ponta, sem rastreio, alojado na Suíça.',
  },
  'pt-BR': {
    title: 'PrivacyNotes: seu cofre criptografado para notas, tarefas e diário',
    description: 'Anote seus pensamentos, tarefas e diário - sempre criptografados. Criptografia de ponta a ponta, sem rastreamento, hospedado na Suíça.',
  },
  ja: {
    title: 'PrivacyNotes: ノート、タスク、ジャーナルのための暗号化された保管庫',
    description: '思考、タスク、ジャーナルを記録。常に暗号化されます。エンドツーエンド暗号化、トラッキングなし、スイスでホスティング。',
  },
  ko: {
    title: 'PrivacyNotes: 노트, 할 일, 저널을 위한 암호화된 보관함',
    description: '생각, 할 일, 저널을 기록하세요. 항상 암호화됩니다. 종단간 암호화, 추적 없음, 스위스에서 호스팅.',
  },
  'zh-TW': {
    title: 'PrivacyNotes: 筆記、任務、日誌的加密保險庫',
    description: '記錄你的想法、任務與日誌，全程加密。端對端加密，零追蹤，主機位於瑞士。',
  },
  ca: {
    title: 'PrivacyNotes: la teva caixa forta xifrada per a notes, tasques i diari',
    description: "Anota els teus pensaments, tasques i diari, sempre xifrats. Xifratge d'extrem a extrem, sense seguiment, allotjat a Suïssa.",
  },
  cs: {
    title: 'PrivacyNotes: tvůj šifrovaný trezor na poznámky, úkoly a deník',
    description: 'Zapisuj si myšlenky, úkoly a deník - vždy zašifrované. End-to-end šifrování, žádné sledování, hostováno ve Švýcarsku.',
  },
  tr: {
    title: 'PrivacyNotes: notlar, görevler ve günlükler için şifreli kasanız',
    description: 'Düşüncelerinizi, görevlerinizi ve günlüğünüzü yazın - her zaman şifreli. Uçtan uca şifreleme, sıfır takip, İsviçre\'de barındırılıyor.',
  },
  sv: {
    title: 'PrivacyNotes: ditt krypterade valv för anteckningar, uppgifter och dagbok',
    description: 'Skriv ner dina tankar, uppgifter och din dagbok - alltid krypterat. Totalsträckskryptering utan spårning, med servrar i Schweiz.',
  },
  ar: {
    title: 'PrivacyNotes: خزنتك المشفّرة للملاحظات والمهام واليوميات',
    description: 'دوّن أفكارك ومهامك ويومياتك - مشفّرة دائمًا. تشفير من طرف إلى طرف دون تتبع، مع استضافة في سويسرا.',
  },
  uk: {
    title: 'PrivacyNotes: ваш зашифрований сейф для нотаток, завдань і щоденника',
    description: 'Записуйте думки, завдання й щоденник, завжди зашифровані. Наскрізне шифрування без стеження, із серверами у Швейцарії.',
  },
  ru: {
    title: 'PrivacyNotes: ваш зашифрованный сейф для заметок, задач и дневника',
    description: 'Записывайте мысли, задачи и дневник, всегда в зашифрованном виде. Сквозное шифрование без слежки, с серверами в Швейцарии.',
  },
  th: {
    title: 'PrivacyNotes: ตู้นิรภัยเข้ารหัสสำหรับโน้ต งาน และบันทึกประจำวันของคุณ',
    description: 'จดความคิด งาน และบันทึกประจำวันของคุณ เข้ารหัสอยู่เสมอ เข้ารหัสแบบต้นทางถึงปลายทาง ไม่มีการติดตาม และโฮสต์ในสวิตเซอร์แลนด์',
  },
};

/**
 * The indexable URL for a marketing locale.
 *
 * English is the one locale with two live URLs: the apex "/" and the
 * explicit "/en" slug. They serve the same page, so only one can be the
 * canonical - and it has to be "/", which is also the x-default and the
 * URL the marketing pages link to for English. Pointing English at "/"
 * here makes /en self-declare "/" as its canonical instead of competing
 * with it, and keeps the hreflang cluster from naming two English
 * entries. /en still works for humans who want to force English while
 * signed in - and brand marks link it on purpose, because the apex is
 * the smart entry and would open the app instead of the homepage
 * (static-page-chrome.ts).
 */
export function marketingPath(locale: string): string {
  return locale === 'en' ? '/' : (LOCALE_TO_SLUG[locale] ?? '/');
}

/**
 * The full hreflang cluster, x-default first. One list so the runtime tags
 * and the pre-rendered ones can never drift apart.
 */
export function hreflangPairs(): { hreflang: string; path: string }[] {
  const out = [{ hreflang: 'x-default', path: '/' }];
  for (const loc of Object.keys(LOCALE_TO_SLUG)) {
    const hl = HREFLANG[loc];
    if (!hl) continue;
    const path = marketingPath(loc);
    out.push({ hreflang: hl, path });
    for (const alias of HREFLANG_ALIASES[loc] ?? []) out.push({ hreflang: alias, path });
  }
  return out;
}

/**
 * og:locale per locale. Open Graph wants language_TERRITORY and treats a bare
 * language code as malformed, so this cannot just be the hreflang tag with an
 * underscore: `de` has to become `de_DE`. The territory is a formatting
 * requirement of the spec, not a claim about which country a reader is in -
 * hreflang above is what actually targets regions, and it stays language-only
 * on purpose.
 */
const OG_LOCALE: Record<string, string> = {
  en: 'en_US',
  de: 'de_DE',
  fr: 'fr_FR',
  it: 'it_IT',
  es: 'es_ES',
  nl: 'nl_NL',
  pl: 'pl_PL',
  'pt-PT': 'pt_PT',
  'pt-BR': 'pt_BR',
  ja: 'ja_JP',
  ko: 'ko_KR',
  'zh-TW': 'zh_TW',
  ca: 'ca_ES',
  cs: 'cs_CZ',
  tr: 'tr_TR',
  sv: 'sv_SE',
  // Arabic is the one language with no territory to name, and the rest of the
  // app already decided that: we ship a bare `ar` catalog and let i18next
  // region-strip ar-SA, ar-AE and ar-EG onto it (see i18n.ts fallbackLng), and
  // its hreflang and URL slug are language-only too. `ar_AR` is the pan-Arab
  // value Open Graph carries for exactly this case, so it is the only one that
  // keeps that decision intact; `ar_SA` would be the first place in the tree
  // to pick a country for Arabic. Spec: ops/docs/i18n-spec.md (per-locale
  // route maps).
  ar: 'ar_AR',
  uk: 'uk_UA',
  ru: 'ru_RU',
  th: 'th_TH',
};

export function ogLocale(locale: string): string {
  return OG_LOCALE[locale] ?? OG_LOCALE.en!;
}
