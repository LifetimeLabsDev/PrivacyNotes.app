import { type ReactNode } from 'react';

// Language metadata + inline flag SVGs, dependency-free (react only).
//
// Single source of truth shared by TWO worlds: the app UI (via
// src/languages.tsx, which re-exports these for LanguageSheet,
// LanguageMenu, and LanguageSuggest) and the Node-side static page
// build (faq-page.ts renders <Flag> to a string with
// react-dom/server). Keep this module free of i18n/browser imports so
// the Vite config process can import it safely.

// Endonym only - the language's name in its own language. NEVER translated to
// the active UI locale: a French user sees the picker as "Italiano", not
// "Italien". That is guaranteed structurally by keeping these strings HERE,
// hardcoded, out of the locale catalogs - the translation pipeline and
// freelancers only ever touch locales/*/*.json, so they cannot reach these. Do
// not move `native` into a catalog. (The "System (automatic)" row is a
// description, not a language name, so it is translated normally via the
// settings catalog.)
//
// There used to be a second field, `sub`, holding the English name for a
// subtitle line under the endonym in LanguageSheet's tiles. It was dropped in
// v0.409.x: 18 two-line tiles made the language pane taller than the settings
// modal, pushing the spell-check control off the bottom. Endonym-only is what
// LanguageMenu, LanguageSuggest and the static help-page menu always rendered,
// so the pickers now agree. Do not add an English gloss back without solving
// the height first.
export const LANGUAGE_META: Record<string, { native: string }> = {
  en: { native: 'English' },
  de: { native: 'Deutsch' },
  fr: { native: 'Français' },
  it: { native: 'Italiano' },
  es: { native: 'Español' },
  nl: { native: 'Nederlands' },
  pl: { native: 'Polski' },
  // The two Portuguese variants share an endonym, so the region rides in the
  // native name: every picker renders `native` alone, and two rows both reading
  // "Português" are indistinguishable. Kept to the short (PT)/(BR) form so the
  // row does not wrap.
  'pt-PT': { native: 'Português (PT)' },
  'pt-BR': { native: 'Português (BR)' },
  ja: { native: '日本語' },
  ko: { native: '한국어' },
  // Script-based, never region-based: this catalog serves Taiwan, Hong Kong and
  // Macau, so the label says the script and never "Taiwan" (it would contradict
  // the zh-HK/zh-MO fallback). The flag is the ROC flag as an eyes-open
  // compromise; see ops/docs/i18n-cjk-plan.md section 4.
  'zh-TW': { native: '繁體中文' },
  ca: { native: 'Català' },
  cs: { native: 'Čeština' },
  tr: { native: 'Türkçe' },
  sv: { native: 'Svenska' },
  ar: { native: 'العربية' },
};

/**
 * Locale codes ordered alphabetically by their native endonym (the label the
 * pickers show). One helper so the app picker, the marketing dropdown, and the
 * static help-page menu all sort identically. `localeCompare` is pinned to 'en'
 * so the order is deterministic across the browser and the Node static build
 * (CI vs local). Non-Latin endonyms (日本語, 한국어, 繁體中文) sort after the
 * Latin ones, which is the expected "the rest last" behavior. Callers that show
 * a System/auto entry keep it pinned first themselves; this sorts languages only.
 */
export function sortByNative(locales: readonly string[]): string[] {
  return [...locales].sort((a, b) =>
    (LANGUAGE_META[a]?.native ?? a).localeCompare(LANGUAGE_META[b]?.native ?? b, 'en'),
  );
}

const FLAG_BOX = {
  width: 26,
  height: 19,
  viewBox: '0 0 60 40',
  preserveAspectRatio: 'none',
  style: { borderRadius: 3, flexShrink: 0 },
};

// Inline flags: no external asset or dependency, CSP-safe, and consistent on
// every OS (Windows degrades flag emoji to two-letter codes).
export function Flag({ code }: { code: string }): ReactNode {
  switch (code) {
    case 'de':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#000" /><rect y="13.3" width="60" height="13.4" fill="#D00" /><rect y="26.7" width="60" height="13.3" fill="#FFCE00" /></svg>;
    case 'fr':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#fff" /><rect width="20" height="40" fill="#0055A4" /><rect x="40" width="20" height="40" fill="#EF4135" /></svg>;
    case 'it':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#fff" /><rect width="20" height="40" fill="#009246" /><rect x="40" width="20" height="40" fill="#CE2B37" /></svg>;
    case 'es':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#AA151B" /><rect y="10" width="60" height="20" fill="#F1BF00" /></svg>;
    case 'nl':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#fff" /><rect width="60" height="13.3" fill="#AE1C28" /><rect y="26.7" width="60" height="13.3" fill="#21468B" /></svg>;
    // Poland is the only flag that is half white with no coloured edge, so it
    // needs a hairline to stay a flag rather than a floating red bar on a light
    // background. Every other flag is framed by its own colours.
    case 'pl':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#fff" /><rect y="20" width="60" height="20" fill="#DC143C" /><rect x="0.5" y="0.5" width="59" height="39" fill="none" stroke="rgba(0,0,0,0.18)" strokeWidth="1" /></svg>;
    case 'pt-PT':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#DA291C" /><rect width="24" height="40" fill="#046A38" /><circle cx="24" cy="20" r="7.5" fill="#FFE800" /><circle cx="24" cy="20" r="4.5" fill="#DA291C" /><rect x="21.75" y="17.5" width="4.5" height="5" fill="#fff" /></svg>;
    case 'pt-BR':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#009C3B" /><polygon points="30,5 54,20 30,35 6,20" fill="#FFDF00" /><circle cx="30" cy="20" r="8" fill="#002776" /></svg>;
    // Japan: white field needs the same hairline as Poland (its edges vanish on
    // a light background); the disc is 3/5 of the height per the spec.
    case 'ja':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#fff" /><circle cx="30" cy="20" r="12" fill="#BC002D" /><rect x="0.5" y="0.5" width="59" height="39" fill="none" stroke="rgba(0,0,0,0.18)" strokeWidth="1" /></svg>;
    // South Korea: red-over-blue taegeuk (a vertical taijitu rotated so red sits
    // on top) plus the four trigrams, simplified but with the correct
    // solid/broken patterns (Geon, Gam, Ri, Gon) at the four corners.
    case 'ko':
      return <svg {...FLAG_BOX}>
        <rect width="60" height="40" fill="#fff" />
        <g transform="rotate(-90 30 20)">
          <path d="M30,10 a10,10 0 0,1 0,20 a5,5 0 0,1 0,-10 a5,5 0 0,0 0,-10 z" fill="#CD2E3A" />
          <path d="M30,10 a10,10 0 0,0 0,20 a5,5 0 0,0 0,-10 a5,5 0 0,1 0,-10 z" fill="#0047A0" />
        </g>
        <g fill="#111">
          <rect x="4.5" y="5" width="11" height="1.2" /><rect x="4.5" y="7.4" width="11" height="1.2" /><rect x="4.5" y="9.8" width="11" height="1.2" />
          <rect x="44.5" y="5" width="4.5" height="1.2" /><rect x="51" y="5" width="4.5" height="1.2" /><rect x="44.5" y="7.4" width="11" height="1.2" /><rect x="44.5" y="9.8" width="4.5" height="1.2" /><rect x="51" y="9.8" width="4.5" height="1.2" />
          <rect x="4.5" y="29" width="11" height="1.2" /><rect x="4.5" y="31.4" width="4.5" height="1.2" /><rect x="11" y="31.4" width="4.5" height="1.2" /><rect x="4.5" y="33.8" width="11" height="1.2" />
          <rect x="44.5" y="29" width="4.5" height="1.2" /><rect x="51" y="29" width="4.5" height="1.2" /><rect x="44.5" y="31.4" width="4.5" height="1.2" /><rect x="51" y="31.4" width="4.5" height="1.2" /><rect x="44.5" y="33.8" width="4.5" height="1.2" /><rect x="51" y="33.8" width="4.5" height="1.2" />
        </g>
        <rect x="0.5" y="0.5" width="59" height="39" fill="none" stroke="rgba(0,0,0,0.18)" strokeWidth="1" />
      </svg>;
    // Taiwan (Traditional Chinese): red field, blue canton, white 12-ray sun
    // (24-point star) with the blue ring and white disc at its centre.
    case 'zh-TW':
      return <svg {...FLAG_BOX}>
        <rect width="60" height="40" fill="#FE0000" />
        <rect width="30" height="20" fill="#000095" />
        <polygon points="15,3 15.9,6.7 18.5,3.9 17.4,7.6 21.1,6.5 18.3,9.1 22,10 18.3,10.9 21.1,13.5 17.4,12.4 18.5,16.1 15.9,13.3 15,17 14.1,13.3 11.5,16.1 12.6,12.4 8.9,13.5 11.7,10.9 8,10 11.7,9.1 8.9,6.5 12.6,7.6 11.5,3.9 14.1,6.7" fill="#fff" />
        <circle cx="15" cy="10" r="2.4" fill="#000095" />
        <circle cx="15" cy="10" r="1.4" fill="#fff" />
      </svg>;
    // Catalonia (senyera): five gold bands, four red. Gold edges get the hairline.
    case 'ca':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#FCDD09" /><rect y="4.44" width="60" height="4.44" fill="#DA121A" /><rect y="13.33" width="60" height="4.44" fill="#DA121A" /><rect y="22.22" width="60" height="4.44" fill="#DA121A" /><rect y="31.11" width="60" height="4.44" fill="#DA121A" /><rect x="0.5" y="0.5" width="59" height="39" fill="none" stroke="rgba(0,0,0,0.18)" strokeWidth="1" /></svg>;
    // Czechia: white over red with the blue hoist triangle reaching the centre
    // (half the flag's length, per the spec). The white upper half needs the
    // same hairline as Poland and Japan or its top edge vanishes on light.
    case 'cs':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#fff" /><rect y="20" width="60" height="20" fill="#D7141A" /><polygon points="0,0 30,20 0,40" fill="#11457E" /><rect x="0.5" y="0.5" width="59" height="39" fill="none" stroke="rgba(0,0,0,0.18)" strokeWidth="1" /></svg>;
    // Turkey: the crescent is a white disc with a red disc punched out of it,
    // offset toward the fly, per the flag law's construction (outer r = G/4,
    // inner r = G/5, centres 0.0625G apart on the midline). The star sits at
    // 0.8125G with one point toward the fly. Red field, so no hairline.
    case 'tr':
      return <svg {...FLAG_BOX}>
        <rect width="60" height="40" fill="#E30A17" />
        <circle cx="20" cy="20" r="10" fill="#fff" />
        <circle cx="22.5" cy="20" r="8" fill="#E30A17" />
        <polygon points="36.5,20 33.74,19.1 33.74,16.2 32.03,18.55 29.26,17.65 30.97,20 29.26,22.35 32.03,21.45 33.74,23.8 33.74,20.9" fill="#fff" />
      </svg>;
    // Sweden: Nordic cross, arms 8 units wide on both axes so they read as one
    // stroke in the 26x19 box (the official 5:8 field is squarer than this
    // 60x40 frame, and every other flag here is normalised the same way).
    case 'sv':
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#006AA7" /><rect y="16" width="60" height="8" fill="#FECC00" /><rect x="18" width="8" height="40" fill="#FECC00" /></svg>;
    // Arabic: language-based label ('Arabic', never a country name, per the
    // zh-TW precedent two cases up), UAE flag as the pragmatic marker - the
    // Saudi flag's shahada calligraphy cannot be drawn respectfully at this
    // size, and the Gulf is the target market. Revisit on complaint, one-line
    // fix.
    case 'ar':
      return <svg {...FLAG_BOX}><rect x="0" y="0" width="15" height="40" fill="#FF0000" /><rect x="15" y="0" width="45" height="13.4" fill="#00843D" /><rect x="15" y="13.4" width="45" height="13.3" fill="#FFFFFF" /><rect x="15" y="26.7" width="45" height="13.3" fill="#000000" /></svg>;
    default:
      return <svg {...FLAG_BOX}><rect width="60" height="40" fill="#012169" /><path d="M0,0 60,40 M60,0 0,40" stroke="#fff" strokeWidth="8" /><path d="M0,0 60,40 M60,0 0,40" stroke="#C8102E" strokeWidth="4" /><rect x="25" width="10" height="40" fill="#fff" /><rect y="15" width="60" height="10" fill="#fff" /><rect x="27" width="6" height="40" fill="#C8102E" /><rect y="17" width="60" height="6" fill="#C8102E" /></svg>;
  }
}
