---
id: 3d0c
title: Všechno, co tu markdown umí
---

Všechno níž vzniklo pomocí lišty nahoře v téhle poznámce. Žádná nastavení, žádné doplňky. Označ text a lišta na něj působí. Klikni na prázdný řádek a začne něco nového.

## Slova

Slovo můžeš dát **tučně**, *kurzivou*, nebo ***obojí***. Můžeš ho přeškrtnout, ~~jako tohle~~. Můžeš ho <u>podtrhnout</u>. Drobné písmo jde do <sub>dolního indexu</sub> a mocniny do <sup>horního</sup>.

Text může být <span style="color: #e03131">červený</span>, <span style="color: #1971c2">modrý</span>, <span style="color: #2f9e44">zelený</span> nebo v jedné z devíti barev.

Může být ==zvýrazněný žlutě== nebo <mark style="background-color: rgba(64, 192, 87, 0.35)">zeleně</mark>.

Tlačítko **Aa** mění velikost a písmo. Text může být <span style="font-size: 0.85em">malý</span>, normální nebo <span style="font-size: 1.6em">velký</span>. Může být <span style="font-family: ui-sans-serif, system-ui, sans-serif">bezpatkový</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">patkový</span> nebo <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">neproporcionální</span>.

## Kde slova sedí

<p style="text-align: center;">Tenhle odstavec je na střed.</p>

<p style="text-align: right;">Tenhle je odsunutý doprava.</p>

Zarovnání hýbe celým odstavcem, nikdy jedním slovem. Dej kurzor do odstavce a použij tlačítko zarovnání.

## Seznamy

- Obyčejná odrážka
- Další
  - Zmáčkni Tab a řádek se odsadí
    - A ještě jednou

1. Očíslovaný krok
2. Druhý krok
3. Vlož krok kamkoli a čísla se opraví sama

- [x] Políčko, které jsi zaškrtl

- [ ] Políčko

  - [ ] Zmáčkni Tab a úkol se odsadí

  - [ ] Zaškrtni políčko a podívej se na animaci

- [ ] Zmáčkni Shift a Tab a odsazení se zmenší

## Tabulky

| Region | Poznámky | Podíl |
| --- | :---: | ---: |
| Evropa | 1 204 | 48 % |
| Amerika | 902 | 36 % |
| Asie | 401 | 16 % |

Prostřední sloupec je na střed a poslední zarovnaný doprava. Zatáhni za okraj sloupce a rozšíříš ho.

## Callouty

Callout je barevná krabička na něco, co čtenář nesmí minout.

> [!tip]+ Tip
> Klikni na název calloutu a zavře se.

> [!warning]+ Pozor
> Každý druh má svou barvu a svou ikonu.

> [!danger]+ Nebezpečí
> Je jich devět. Nabídka **Vložit** je vypisuje.

## Citace

> Citace se odsadí od okraje a dostane barevnou linku po straně.

## Poznámky pod čarou

Poznámka pod čarou drží zdroj nebo poznámku mimo text.[^1] Napiš `[^1]` za slovo, nebo vyber **Poznámka pod čarou** v nabídce **Vložit**. Klikni na malé číslo a přejdeš k poznámce.

## Kód

Kód si drží mezery a obarví se podle jazyka. Název nahoře v bloku je jeho jazyk: klikni na něj a vyber jiný.

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

Dlouhý blok se otevře sbalený, aby zbytek poznámky zůstal blízko. Tlačítko pod ním ukáže všechny řádky.

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

Krátký kousek kódu uvnitř věty vypadá takhle: `tohle`.

## Matematika

Matematika může být uvnitř věty, třeba $a^2 + b^2 = c^2$, nebo stát na vlastním řádku:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Obrázky

![Hora Fudži za třešňovými květy.](/onboarding/fuji.webp){width=50 align=center}

Přetáhni obrázek do poznámky, nebo ho vlož. Klikni na něj a změň mu velikost, nebo ho posuň doleva, na střed či doprava. Ten nahoře je na poloviční šířku a na střed.

## Odkazy

Jsou dva druhy a schválně vypadají jinak.

- Webový odkaz otevře stránku: [privacynotes.app](https://privacynotes.app/cs)
- Odkaz na poznámku otevře jinou tvoji poznámku: [[Jak jsou tvoje poznámky chráněné]]

Oba mají tlačítko na liště. Řetěz udělá webový odkaz. Hranaté závorky udělají odkaz na poznámku: vypíšou tvoje poznámky a ty si vybereš tu, kterou myslíš. Napsat `[[` udělá totéž.

Odkaz na poznámku se nemusí zobrazovat jako název poznámky. Napiš název, svislou čáru a pak slova, která chceš mít na stránce: [[Jak jsou tvoje poznámky chráněné|tahle slova]] otevřou tu poznámku.

Odkaz na poznámku ji umí otevřít i u jednoho z jejích nadpisů. Napiš za název `#` a vyber nadpis: [[Jak jsou tvoje poznámky chráněné#Kdo má tvůj klíč]] otevře tu poznámku u části o klíči. Ikona odkazu u nadpisu v osnově takový odkaz zkopíruje za tebe.

---

*Jestli markdown už píšeš, prostě ho piš a formátuje se za pochodu. Surový text za kteroukoli poznámkou uvidíš přes **Zobrazit markdown** vpravo dole v téhle poznámce.*

[^1]: Tohle je poznámka. Šipka vedle ní tě vrátí nahoru.
