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
  sk: 'sk',
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
    title: 'PrivacyNotes: Encrypted Notes, Tasks & Journal',
    description: 'A private workspace for notes, tasks and your journal. Encrypted on your device. Start free, import your notes, and pay once for Pro.',
  },
  de: {
    title: 'PrivacyNotes: Verschlüsselte Notizen, Aufgaben und Tagebuch',
    description: 'Ein privater Arbeitsbereich für Notizen, Aufgaben und dein Tagebuch. Verschlüsselt auf deinem Gerät. Starte kostenlos, importiere deine Notizen und zahle einmal für Pro.',
  },
  fr: {
    title: 'PrivacyNotes : notes, tâches et journal chiffrés',
    description: 'Un espace privé pour tes notes, tes tâches et ton journal. Chiffré sur ton appareil. Commence gratuitement, importe tes notes et paie une seule fois pour Pro.',
  },
  it: {
    title: 'PrivacyNotes: note, attività e diario cifrati',
    description: 'Uno spazio privato per note, attività e il tuo diario. Cifrato sul tuo dispositivo. Inizia gratis, importa le tue note e paga una volta sola per Pro.',
  },
  es: {
    title: 'PrivacyNotes: notas, tareas y diario cifrados',
    description: 'Un espacio privado para notas, tareas y tu diario. Cifrado en tu dispositivo. Empieza gratis, importa tus notas y paga una sola vez por Pro.',
  },
  nl: {
    title: 'PrivacyNotes: versleutelde notities, taken en dagboek',
    description: 'Een privéwerkplek voor notities, taken en je dagboek. Versleuteld op je apparaat. Begin gratis, importeer je notities en betaal één keer voor Pro.',
  },
  pl: {
    title: 'PrivacyNotes: zaszyfrowane notatki, zadania i dziennik',
    description: 'Prywatna przestrzeń na notatki, zadania i twój dziennik. Szyfrowana na twoim urządzeniu. Zacznij za darmo, zaimportuj notatki i zapłać raz za Pro.',
  },
  'pt-PT': {
    title: 'PrivacyNotes: notas, tarefas e diário encriptados',
    description: 'Um espaço privado para notas, tarefas e o teu diário. Encriptado no teu dispositivo. Começa grátis, importa as tuas notas e paga uma vez pelo Pro.',
  },
  'pt-BR': {
    title: 'PrivacyNotes: notas, tarefas e diário criptografados',
    description: 'Um espaço privado para notas, tarefas e seu diário. Criptografado no seu dispositivo. Comece grátis, importe suas notas e pague uma vez pelo Pro.',
  },
  ja: {
    title: 'PrivacyNotes: 暗号化されたノート、タスク、ジャーナル',
    description: 'ノート、タスク、ジャーナルのためのプライベートなワークスペース。デバイス上で暗号化されます。無料で始めて、ノートをインポートし、Proは一度の支払いで手に入ります。',
  },
  ko: {
    title: 'PrivacyNotes: 암호화된 노트, 할 일, 저널',
    description: '노트, 할 일, 저널을 위한 비공개 작업 공간이에요. 기기에서 암호화돼요. 무료로 시작하고, 노트를 가져오고, Pro는 한 번만 결제하세요.',
  },
  'zh-TW': {
    title: 'PrivacyNotes: 加密的筆記、任務與日誌',
    description: '專屬於你的筆記、任務與日誌空間，在你的裝置上加密。免費開始，匯入你的筆記，Pro 只需付款一次。',
  },
  ca: {
    title: 'PrivacyNotes: notes, tasques i diari xifrats',
    description: 'Un espai privat per a notes, tasques i el teu diari. Xifrat al teu dispositiu. Comença gratis, importa les teves notes i paga una sola vegada per Pro.',
  },
  cs: {
    title: 'PrivacyNotes: šifrované poznámky, úkoly a deník',
    description: 'Soukromý prostor pro poznámky, úkoly a tvůj deník. Šifrovaný na tvém zařízení. Začni zdarma, importuj své poznámky a za Pro zaplať jen jednou.',
  },
  sk: {
    title: 'PrivacyNotes: šifrované poznámky, úlohy a denník',
    description: 'Súkromný priestor pre poznámky, úlohy a tvoj denník. Šifrovaný na tvojom zariadení. Začni zadarmo, importuj svoje poznámky a za Pro zaplať iba raz.',
  },
  tr: {
    title: 'PrivacyNotes: Şifreli notlar, görevler ve günlük',
    description: 'Notlarınız, görevleriniz ve günlüğünüz için özel bir çalışma alanı. Cihazınızda şifrelenir. Ücretsiz başlayın, notlarınızı içe aktarın ve Pro için bir kez ödeyin.',
  },
  sv: {
    title: 'PrivacyNotes: krypterade anteckningar, uppgifter och dagbok',
    description: 'En privat arbetsyta för anteckningar, uppgifter och din dagbok. Krypterad på din enhet. Börja gratis, importera dina anteckningar och betala en gång för Pro.',
  },
  ar: {
    title: 'PrivacyNotes: ملاحظات ومهام ويوميات مشفّرة',
    description: 'مساحة عمل خاصة لملاحظاتك ومهامك ويومياتك. مشفّرة على جهازك. ابدأ مجانًا، واستورد ملاحظاتك، وادفع مرة واحدة مقابل Pro.',
  },
  uk: {
    title: 'PrivacyNotes: зашифровані нотатки, завдання й щоденник',
    description: 'Приватний робочий простір для нотаток, завдань і вашого щоденника. Зашифровано на вашому пристрої. Почніть безкоштовно, імпортуйте свої нотатки й заплатіть за Pro лише раз.',
  },
  ru: {
    title: 'PrivacyNotes: зашифрованные заметки, задачи и дневник',
    description: 'Личное рабочее пространство для заметок, задач и вашего дневника. Шифруется на вашем устройстве. Начните бесплатно, импортируйте свои заметки и заплатите за Pro один раз.',
  },
  th: {
    title: 'PrivacyNotes: โน้ต งาน และบันทึกประจำวันที่เข้ารหัส',
    description: 'พื้นที่ทำงานส่วนตัวสำหรับโน้ต งาน และบันทึกประจำวันของคุณ เข้ารหัสบนอุปกรณ์ของคุณ เริ่มใช้ฟรี นำเข้าโน้ตของคุณ และจ่ายครั้งเดียวสำหรับ Pro',
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
  sk: 'sk_SK',
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
