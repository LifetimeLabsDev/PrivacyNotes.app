---
id: 3d0c
title: Allt markdown kan här
---

Allt nedanför gjordes med fältet högst upp i den här anteckningen. Inga inställningar, inga tillägg. Markera text så jobbar fältet på den. Klicka på en tom rad så börjar det något nytt.

## Ord

Du kan göra ett ord **fett**, eller *kursivt*, eller ***båda***. Du kan stryka över det, ~~så här~~. Du kan <u>stryka under</u> det. Finstilt går i <sub>nedsänkt</sub> och potenser i <sup>upphöjt</sup>.

Text kan vara <span style="color: #e03131">röd</span>, <span style="color: #1971c2">blå</span>, <span style="color: #2f9e44">grön</span> eller någon av nio färger.

Den kan vara ==överstruken i gult== eller <mark style="background-color: rgba(64, 192, 87, 0.35)">i grönt</mark>.

Knappen **Aa** ändrar storlek och typsnitt. Text kan vara <span style="font-size: 0.85em">liten</span>, normal eller <span style="font-size: 1.6em">stor</span>. Den kan vara <span style="font-family: ui-sans-serif, system-ui, sans-serif">enkel</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">med seriffer</span> eller <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">med fast bredd</span>.

## Var orden sitter

<p style="text-align: center;">Det här stycket är centrerat.</p>

<p style="text-align: right;">Det här är skjutet åt höger.</p>

Justering flyttar ett helt stycke, aldrig ett enda ord. Sätt markören i stycket och använd justeringsknappen.

## Listor

- En vanlig punkt
- En till
  - Tryck Tab för att dra in en rad
    - Och en gång till

1. Ett numrerat steg
2. Ett andra steg
3. Lägg in ett steg var som helst så rättar sig siffrorna själva

- [x] En ruta du har bockat i

- [ ] Ruta

  - [ ] Tryck Tab för att dra in en uppgift

  - [ ] Bocka i rutan och titta på animationen

- [ ] Tryck Skift och Tab för att minska indraget

## Tabeller

| Region | Anteckningar | Andel |
| --- | :---: | ---: |
| Europa | 1 204 | 48 % |
| Amerika | 902 | 36 % |
| Asien | 401 | 16 % |

Mittenkolumnen är centrerad och den sista högerställd. Dra i en kolumnkant för att göra den bredare.

## Rutor

En ruta är en färgad låda för något en läsare inte får missa.

> [!tip]+ Tips
> Klicka på rubriken i en ruta för att fälla ihop den.

> [!warning]+ Varning
> Varje sort har sin egen färg och sin egen ikon.

> [!danger]+ Fara
> Det finns nio sorter. Menyn **Infoga** listar dem.

## Citat

> Ett citat kliver in från marginalen och får en färgad linje längs sidan.

## Kod

Kod behåller sina mellanrum och färgas efter språk.

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

En kort kodsnutt mitt i en mening ser ut så här i stället: `den här`.

## Matematik

Matematik kan sitta i en mening, som $a^2 + b^2 = c^2$, eller stå på egen rad:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Bilder

![Fuji bakom körsbärsblom.](/onboarding/fuji.webp){width=50 align=center}

Dra in en bild i en anteckning, eller klistra in den. Klicka på den en gång för att ändra storlek, eller för att flytta den åt vänster, mitten eller höger. Den ovanför är halv bredd och centrerad.

## Länkar

Det finns två sorter, och de ser olika ut med flit.

- En webblänk öppnar en sida: [privacynotes.app](https://privacynotes.app/sv)
- En anteckningslänk öppnar en annan av dina anteckningar: [[Hur dina anteckningar skyddas]]

Båda har en knapp i fältet. Kedjan gör en webblänk. Knappen bredvid listar dina anteckningar, och du väljer den du menar.

---

*Skriver du redan markdown, skriv det bara så formateras det medan du går. Rå text bakom vilken anteckning som helst ser du med **Visa markdown** längst ned till höger i den här anteckningen.*
