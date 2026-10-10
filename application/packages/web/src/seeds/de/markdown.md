---
id: 3d0c
title: Alles, was Markdown hier kann
---

Alles hier unten ist mit der Leiste oben in dieser Notiz entstanden. Keine Einstellungen, keine Plugins. Markier Text, und die Leiste wirkt darauf. Klick in eine leere Zeile, und sie fängt etwas Neues an.

## Wörter

Du kannst ein Wort **fett** machen, oder *kursiv*, oder ***beides***. Du kannst es durchstreichen, so ~~wie hier~~. Du kannst es <u>unterstreichen</u>. Kleingedrucktes steht <sub>tiefgestellt</sub> und Potenzen <sup>hochgestellt</sup>.

Text kann <span style="color: #e03131">rot</span>, <span style="color: #1971c2">blau</span>, <span style="color: #2f9e44">grün</span> oder in einer von neun Farben sein.

Er kann ==gelb hervorgehoben== sein oder <mark style="background-color: rgba(64, 192, 87, 0.35)">grün</mark>.

Der Knopf **Aa** ändert Größe und Schrift. Text kann <span style="font-size: 0.85em">klein</span>, normal oder <span style="font-size: 1.6em">groß</span> sein. Er kann <span style="font-family: ui-sans-serif, system-ui, sans-serif">schlicht</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">serif</span> oder <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">monospace</span> sein.

## Wo die Wörter sitzen

<p style="text-align: center;">Dieser Absatz steht mittig.</p>

<p style="text-align: right;">Dieser hier ist nach rechts geschoben.</p>

Die Ausrichtung bewegt einen ganzen Absatz, nie ein einzelnes Wort. Setz den Cursor in den Absatz und nutz den Ausrichtungsknopf.

## Listen

- Ein einfacher Punkt
- Noch einer
  - Drück Tab, um eine Zeile einzurücken
    - Und noch einmal

1. Ein nummerierter Schritt
2. Ein zweiter Schritt
3. Füg irgendwo einen Schritt ein, und die Nummern korrigieren sich selbst

- [x] Ein Kästchen, das du abgehakt hast

- [ ] Kästchen

  - [ ] Drück Tab, um eine Aufgabe einzurücken

  - [ ] Hak das Kästchen ab und sieh dir die Animation an

- [ ] Drück Umschalt und Tab, um die Einrückung zu verringern

## Tabellen

| Region | Notizen | Anteil |
| --- | :---: | ---: |
| Europa | 1.204 | 48 % |
| Amerika | 902 | 36 % |
| Asien | 401 | 16 % |

Die mittlere Spalte ist zentriert, die letzte rechtsbündig. Zieh an einer Spaltenkante, um sie breiter zu machen.

## Hinweisboxen

Eine Hinweisbox ist ein farbiger Kasten für etwas, das niemand übersehen darf.

> [!tip]+ Tipp
> Klick auf das Symbol, um sie zuzuklappen.

> [!warning]+ Warnung
> Jede Art hat ihre eigene Farbe und ihr eigenes Symbol.

> [!danger]+ Achtung
> Es gibt viele Arten. Das Menü **Einfügen** listet sie auf.

> [!fold]- Aufklappbar
> Kein Kasten, keine Farbe: nur Text, der nicht stört, bis du ihn aufklappst.

## Zitate

> Ein Zitat rückt vom Rand ein und bekommt einen farbigen Strich an der Seite.

## Fußnoten

Eine Fußnote hält eine Quelle oder eine Randbemerkung aus dem Text heraus.[^1] Tippe `[^1]` nach einem Wort oder wähle **Fußnote** im Menü **Einfügen**. Klicke auf die kleine Zahl, um zur Notiz zu springen.

## Code

Code behält seine Abstände und wird nach Sprache eingefärbt. Der Name oben im Block ist seine Sprache: Klick darauf, um eine andere zu wählen.

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

Ein langer Block öffnet sich zugeklappt, damit der Rest der Notiz nah bleibt. Der Button darunter zeigt alle Zeilen.

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

Ein kurzes Stück Code mitten im Satz sieht stattdessen so aus: `dies hier`.

## Mathe

Mathe kann im Satz stehen, etwa $a^2 + b^2 = c^2$, oder in einer eigenen Zeile:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Bilder

![Der Fuji hinter Kirschblüten.](/onboarding/fuji.webp){width=50 align=center}

Zieh ein Bild in eine Notiz oder füg es ein. Klick es einmal an, um seine Größe zu ändern oder es nach links, in die Mitte oder nach rechts zu rücken. Das oben ist halb so breit und mittig.

## Links

Es gibt zwei Arten, und sie sehen absichtlich verschieden aus.

- Ein Web-Link öffnet eine Seite: [privacynotes.app](https://privacynotes.app/de)
- Ein Notiz-Link öffnet eine andere deiner Notizen: [[Wie deine Notizen geschützt sind]]

Beide haben einen Knopf in der Leiste. Die Kette macht einen Web-Link. Die Klammern machen einen Notiz-Link: Sie listen deine Notizen auf, und du wählst die gemeinte aus. `[[` zu tippen macht dasselbe.

Ein Notiz-Link muss nicht wie der Titel der Notiz lauten. Tipp den Titel, einen senkrechten Strich und dann die Wörter, die auf der Seite stehen sollen: [[Wie deine Notizen geschützt sind|diese Wörter]] öffnen diese Notiz.

Ein Notiz-Link kann eine Notiz auch an einer ihrer Überschriften öffnen. Tipp ein `#` nach dem Titel und wähl die Überschrift: [[Wie deine Notizen geschützt sind#Wer deinen Schlüssel hat]] öffnet diese Notiz bei ihrem Abschnitt über den Schlüssel. Das Link-Symbol an einer Überschrift in der Gliederung kopiert so einen Link für dich.

---

*Wenn du schon Markdown schreibst, tipp es einfach, und es formatiert sich beim Schreiben. Den rohen Text hinter jeder Notiz siehst du mit **Markdown anzeigen** unten rechts in dieser Notiz.*

[^1]: Das ist die Notiz. Der Pfeil daneben bringt dich zurück nach oben.
