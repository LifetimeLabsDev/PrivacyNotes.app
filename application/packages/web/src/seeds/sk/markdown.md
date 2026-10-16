---
id: 3d0c
title: Všetko, čo tu markdown dokáže
tags:
folder: Markdown
order: 2
---

Všetko nižšie vzniklo pomocou lišty navrchu tejto poznámky. Žiadne nastavenia, žiadne pluginy. Označ text a lišta pôsobí naň. Klikni do prázdneho riadka a lišta začne niečo nové.

## Slová

Slovo môže byť **tučné**, *kurzívou* alebo ***oboje***. Môžeš ho prečiarknuť, ~~ako toto~~. Môžeš ho <u>podčiarknuť</u>. Drobné písmo patrí do <sub>dolného indexu</sub> a mocniny do <sup>horného indexu</sup>.

Text môže byť <span style="color: #e03131">červený</span>, <span style="color: #1971c2">modrý</span>, <span style="color: #2f9e44">zelený</span> alebo v ktorejkoľvek z deviatich farieb.

Môže byť ==zvýraznený na žlto== alebo <mark style="background-color: rgba(64, 192, 87, 0.35)">na zeleno</mark>.

Tlačidlo **Aa** mení veľkosť a písmo. Text môže byť <span style="font-size: 0.85em">malý</span>, normálny alebo <span style="font-size: 1.6em">veľký</span>. Môže byť <span style="font-family: ui-sans-serif, system-ui, sans-serif">bezpätkový</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">pätkový</span> alebo <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">neproporcionálny</span>.

## Kde stoja slová

<p style="text-align: center;">Tento odsek je na stred.</p>

<p style="text-align: right;">Tento je posunutý doprava.</p>

Zarovnanie posúva celý odsek, nikdy nie jedno slovo. Daj kurzor do odseku a použi tlačidlo zarovnania.

## Zoznamy

- Obyčajná odrážka
- Ďalšia
  - Stlač Tab a riadok sa posunie dnu
    - A znova

1. Očíslovaný krok
2. Druhý krok
3. Vlož krok kamkoľvek a čísla sa opravia samy

- [x] Zaškrtnuté políčko

- [ ] Políčko

  - [ ] Stlač Tab a úloha sa odsadí

  - [ ] Zaškrtni políčko a pozri si animáciu

- [ ] Stlač Shift a Tab a odsadenie sa zmenší

## Tabuľky

| Región | Poznámky | Podiel |
| --- | :---: | ---: |
| Európa | 1 204 | 48 % |
| Amerika | 902 | 36 % |
| Ázia | 401 | 16 % |

Stredný stĺpec je zarovnaný na stred a posledný doprava. Klikni na okraj stĺpca a potiahni ho, aby bol širší.

## Callouty

Callout je farebný blok pre niečo, čo čitateľ nesmie prehliadnuť.

> [!tip]+ Tip
> Klikni na jeho ikonu a zbalí sa.

> [!warning]+ Varovanie
> Každý druh má vlastnú farbu a vlastnú ikonu.

> [!danger]+ Nebezpečenstvo
> Druhov je veľa. Ponuka **Vložiť** ich vypisuje.

> [!fold]- Zbalený blok
> Žiadne pole a žiadna farba: iba text, ktorý nezavadzia, kým ho neotvoríš.

## Citácie

> Citácia ustúpi od okraja a dostane farebnú čiaru po boku.

## Poznámky pod čiarou

Poznámka pod čiarou odloží zdroj alebo vedľajšiu myšlienku mimo textu.[^1] Napíš `[^1]` za slovo alebo vyber **Poznámka pod čiarou** v ponuke **Vložiť**. Klikni na malé číslo a presunieš sa k poznámke.

## Kód

Kód si zachová medzery a zafarbí sa podľa jazyka. Názov navrchu bloku je jeho jazyk: klikni naň a vyber iný.

```js
export function seal(note, key) {
  const nonce = randomBytes(24);
  return xchacha20poly1305(key, nonce).encrypt(note);
}
```

```python
def rolling_mean(values, window):
    return [sum(values[i:i + window]) / window
            for i in range(len(values) - window + 1)]
```

Dlhý blok sa otvorí zbalený, aby zvyšok poznámky zostal nablízku. Tlačidlo pod ním ukáže všetky riadky.

```js
const WORDS_PER_MINUTE = 200;

export function readingStats(markdown) {
  const text = markdown
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[#*_~`>|-]/g, ' ');

  const words = text.split(/\s+/).filter(Boolean);
  const headings = markdown.match(/^#{1,6} /gm) ?? [];
  const tasks = markdown.match(/^\s*- \[[ x]\] /gm) ?? [];
  const done = tasks.filter((task) => task.includes('[x]'));

  return {
    words: words.length,
    minutes: Math.max(1, Math.round(words.length / WORDS_PER_MINUTE)),
    headings: headings.length,
    tasks: tasks.length,
    done: done.length,
  };
}

export function summary(stats) {
  const parts = [`${stats.words} words`, `${stats.minutes} min read`];
  if (stats.headings > 0) {
    parts.push(`${stats.headings} sections`);
  }
  if (stats.tasks > 0) {
    parts.push(`${stats.done} of ${stats.tasks} tasks done`);
  }
  return parts.join(' · ');
}

export function isLongRead(stats) {
  return stats.minutes >= 10;
}
```

Krátky kúsok kódu vnútri vety vyzerá namiesto toho ako `toto`.

## Matematika

Matematika môže byť vnútri vety, napríklad $a^2 + b^2 = c^2$, alebo stáť na vlastnom riadku:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Obrázky

![Hora Fudži za čerešňovými kvetmi.](/onboarding/fuji.webp){width=50 align=center}

Pretiahni obrázok do poznámky alebo ho vlož. Klikni naň raz a môžeš zmeniť jeho veľkosť alebo ho posunúť doľava, na stred či doprava. Ten vyššie má polovičnú šírku a je na strede.

## Odkazy

Sú dva druhy a zámerne vyzerajú inak.

- Webový odkaz otvorí stránku: [privacynotes.app](https://privacynotes.app/sk)
- Odkaz na poznámku otvorí inú tvoju poznámku: [[Ako sú tvoje poznámky chránené]]

Oba majú tlačidlo na lište. Reťaz vytvorí webový odkaz. Hranaté zátvorky vytvoria odkaz na poznámku: vypíšu tvoje poznámky a ty vyberieš tú, ktorú myslíš. Napísať `[[` urobí to isté.

Odkaz na poznámku nemusí znieť ako názov poznámky. Napíš názov, zvislú čiaru a potom slová, ktoré chceš mať na stránke: [[Ako sú tvoje poznámky chránené|tieto slová]] otvoria tú poznámku.

Odkaz na poznámku vie poznámku otvoriť aj pri jednom z jej nadpisov. Napíš za názov `#` a vyber nadpis: [[Ako sú tvoje poznámky chránené#Kto drží tvoj kľúč]] otvorí tú poznámku pri časti o kľúči. Ikona odkazu pri nadpise v osnove ti taký odkaz skopíruje.

---

*Ak už markdown píšeš, jednoducho ho píš a formátuje sa priebežne. Surový text ktorejkoľvek poznámky uvidíš, keď klikneš na **Zobraziť markdown** vpravo dole v tejto poznámke.*

[^1]: Toto je poznámka pod čiarou. Šípka vedľa nej ťa vráti hore.
