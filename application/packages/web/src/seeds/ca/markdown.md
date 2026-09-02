---
id: 3d0c
title: Tot el que el markdown pot fer aquí
---

Tot el que hi ha a sota s'ha fet amb la barra de dalt d'aquesta nota. Sense configuració, sense connectors. Selecciona text i la barra hi actua. Fes clic en una línia buida i comença una cosa nova.

## Paraules

Pots posar una paraula en **negreta**, o en *cursiva*, o ***totes dues***. La pots ratllar, ~~com aquesta~~. La pots <u>subratllar</u>. La lletra petita va en <sub>subíndex</sub> i les potències en <sup>superíndex</sup>.

El text pot ser <span style="color: #e03131">vermell</span>, <span style="color: #1971c2">blau</span>, <span style="color: #2f9e44">verd</span> o d'un de nou colors.

Pot anar ==ressaltat en groc== o <mark style="background-color: rgba(64, 192, 87, 0.35)">en verd</mark>.

El botó **Aa** canvia la mida i la tipografia. El text pot ser <span style="font-size: 0.85em">petit</span>, normal o <span style="font-size: 1.6em">gran</span>. Pot ser <span style="font-family: ui-sans-serif, system-ui, sans-serif">senzill</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">amb serifa</span> o <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">monoespaiat</span>.

## On seuen les paraules

<p style="text-align: center;">Aquest paràgraf està centrat.</p>

<p style="text-align: right;">Aquest està empès a la dreta.</p>

L'alineació mou un paràgraf sencer, mai una sola paraula. Posa el cursor al paràgraf i fes servir el botó d'alineació.

## Llistes

- Un pic senzill
- Un altre
  - Prem Tab per endinsar una línia
    - I un altre cop

1. Un pas numerat
2. Un segon pas
3. Insereix un pas on vulguis i els números es corregeixen sols

- [x] Una casella que has marcat

- [ ] Casella

  - [ ] Prem Tab per endinsar una tasca

  - [ ] Marca la casella i mira l'animació

- [ ] Prem Maj i Tab per reduir el sagnat

## Taules

| Regió | Notes | Quota |
| --- | :---: | ---: |
| Europa | 1.204 | 48 % |
| Amèrica | 902 | 36 % |
| Àsia | 401 | 16 % |

La columna del mig està centrada i l'última alineada a la dreta. Arrossega la vora d'una columna per eixamplar-la.

## Requadres

Un requadre és una caixa de color per a una cosa que ningú no ha de perdre's.

> [!tip]+ Consell
> Fes clic al títol d'un requadre per plegar-lo.

> [!warning]+ Atenció
> Cada mena té el seu color i la seva icona.

> [!danger]+ Perill
> N'hi ha nou. El menú **Insereix** les llista.

## Cites

> Una cita s'endinsa des del marge i porta una línia de color al costat.

## Codi

El codi manté els espais i es pinta segons el llenguatge.

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

Un tros curt de codi dins d'una frase es veu així: `això`.

## Matemàtiques

Les matemàtiques poden anar dins d'una frase, com ara $a^2 + b^2 = c^2$, o en una línia pròpia:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Imatges

![El mont Fuji darrere les flors de cirerer.](/onboarding/fuji.webp){width=50 align=center}

Arrossega una imatge a una nota, o enganxa-la. Fes-hi clic un cop per canviar-ne la mida, o per moure-la a l'esquerra, al centre o a la dreta. La de dalt està a mitja amplada i centrada.

## Enllaços

N'hi ha de dues menes, i es veuen diferents a propòsit.

- Un enllaç web obre un lloc: [privacynotes.app](https://privacynotes.app/ca)
- Un enllaç de nota obre una altra nota teva: [[Com estan protegides les teves notes]]

Tots dos tenen botó a la barra. La cadena fa un enllaç web. Els claudàtors fan un enllaç de nota: llisten les teves notes i tries la que vols. Escriure `[[` fa el mateix.

---

*Si ja escrius markdown, escriu-lo i es formata sobre la marxa. Per veure el text en brut darrere de qualsevol nota, fes clic a **Mostra el markdown** a baix a la dreta d'aquesta nota.*
