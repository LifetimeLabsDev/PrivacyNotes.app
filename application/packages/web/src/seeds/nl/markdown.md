---
id: 3d0c
title: Alles wat markdown hier kan
---

Alles hieronder is gemaakt met de balk boven aan deze notitie. Geen instellingen, geen plugins. Selecteer tekst en de balk werkt erop. Klik op een lege regel en hij begint iets nieuws.

## Woorden

Je kunt een woord **vet** maken, of *cursief*, of ***allebei***. Je kunt er een streep door zetten, ~~zoals hier~~. Je kunt het <u>onderstrepen</u>. Kleine letters gaan in <sub>subscript</sub> en machten in <sup>superscript</sup>.

Tekst kan <span style="color: #e03131">rood</span>, <span style="color: #1971c2">blauw</span>, <span style="color: #2f9e44">groen</span> of een van negen kleuren zijn.

Hij kan ==geel gemarkeerd== zijn of <mark style="background-color: rgba(64, 192, 87, 0.35)">groen</mark>.

De knop **Aa** verandert grootte en lettertype. Tekst kan <span style="font-size: 0.85em">klein</span>, normaal of <span style="font-size: 1.6em">groot</span> zijn. Hij kan <span style="font-family: ui-sans-serif, system-ui, sans-serif">gewoon</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">met schreef</span> of <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">monospace</span> zijn.

## Waar de woorden staan

<p style="text-align: center;">Deze alinea staat in het midden.</p>

<p style="text-align: right;">Deze is naar rechts geduwd.</p>

Uitlijnen verplaatst een hele alinea, nooit één woord. Zet de cursor in de alinea en gebruik de uitlijnknop.

## Lijsten

- Een gewoon bolletje
- Nog een
  - Druk op Tab om een regel in te springen
    - En nog eens

1. Een genummerde stap
2. Een tweede stap
3. Voeg ergens een stap toe en de nummers verbeteren zichzelf

- [x] Een vakje dat je hebt afgevinkt

- [ ] Vakje

  - [ ] Druk op Tab om een taak in te springen

  - [ ] Vink het vakje aan en kijk naar de animatie

- [ ] Druk op Shift en Tab om minder in te springen

## Tabellen

| Regio | Notities | Aandeel |
| --- | :---: | ---: |
| Europa | 1.204 | 48 % |
| Amerika | 902 | 36 % |
| Azië | 401 | 16 % |

De middelste kolom staat gecentreerd en de laatste rechts. Sleep aan de rand van een kolom om hem breder te maken.

## Kaders

Een kader is een gekleurd vak voor iets dat een lezer niet mag missen.

> [!tip]+ Tip
> Klik op de titel van een kader om het dicht te klappen.

> [!warning]+ Let op
> Elk soort heeft zijn eigen kleur en icoon.

> [!danger]+ Gevaar
> Er zijn er negen. Het menu **Invoegen** somt ze op.

## Citaten

> Een citaat springt in vanaf de kantlijn en krijgt een gekleurde streep aan de zijkant.

## Code

Code houdt zijn spaties en wordt gekleurd per taal.

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

Een kort stukje code midden in een zin ziet er zo uit: `dit`.

## Wiskunde

Wiskunde kan in een zin staan, zoals $a^2 + b^2 = c^2$, of op een eigen regel:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Afbeeldingen

![De Fuji achter kersenbloesem.](/onboarding/fuji.webp){width=50 align=center}

Sleep een afbeelding in een notitie, of plak er een. Klik erop om de grootte te veranderen, of om hem links, in het midden of rechts te zetten. Die hierboven is halve breedte en gecentreerd.

## Links

Er zijn twee soorten, en ze zien er met opzet anders uit.

- Een weblink opent een site: [privacynotes.app](https://privacynotes.app/nl)
- Een notitielink opent een andere notitie van jou: [[Hoe je notities beschermd zijn]]

Allebei hebben een knop in de balk. De ketting maakt een weblink. De knop ernaast somt je notities op, en jij kiest welke je bedoelt.

---

*Schrijf je al markdown, typ het dan gewoon en het maakt zichzelf op. De ruwe tekst achter een notitie zie je met **Markdown tonen** rechtsonder in deze notitie.*
