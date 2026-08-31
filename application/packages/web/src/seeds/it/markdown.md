---
id: 3d0c
title: Tutto quello che markdown sa fare qui
---

Tutto quello che segue è stato fatto con la barra in cima a questa nota. Nessuna impostazione, nessun plugin. Seleziona del testo e la barra agisce su di esso. Clicca in una riga vuota e inizia qualcosa di nuovo.

## Le parole

Puoi rendere una parola **grassetto**, o *corsivo*, o ***entrambi***. Puoi barrarla, ~~come questa~~. Puoi <u>sottolinearla</u>. Il testo piccolo va in <sub>pedice</sub> e le potenze in <sup>apice</sup>.

Il testo può essere <span style="color: #e03131">rosso</span>, <span style="color: #1971c2">blu</span>, <span style="color: #2f9e44">verde</span> o uno di nove colori.

Può essere ==evidenziato in giallo== o <mark style="background-color: rgba(64, 192, 87, 0.35)">in verde</mark>.

Il pulsante **Aa** cambia dimensione e carattere. Il testo può essere <span style="font-size: 0.85em">piccolo</span>, normale o <span style="font-size: 1.6em">grande</span>. Può essere <span style="font-family: ui-sans-serif, system-ui, sans-serif">semplice</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">con grazie</span> o <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">a spaziatura fissa</span>.

## Dove stanno le parole

<p style="text-align: center;">Questo paragrafo è centrato.</p>

<p style="text-align: right;">Questo è spinto a destra.</p>

L'allineamento sposta un intero paragrafo, mai una parola sola. Metti il cursore nel paragrafo e usa il pulsante di allineamento.

## Elenchi

- Un punto semplice
- Un altro
  - Premi Tab per rientrare di una riga
    - E ancora

1. Un passo numerato
2. Un secondo passo
3. Inserisci un passo dove vuoi e i numeri si correggono da soli

- [x] Una casella che hai spuntato

- [ ] Casella

  - [ ] Premi Tab per rientrare un'attività

  - [ ] Spunta la casella e guarda l'animazione

- [ ] Premi Maiusc e Tab per ridurre il rientro

## Tabelle

| Regione | Note | Quota |
| --- | :---: | ---: |
| Europa | 1.204 | 48 % |
| Americhe | 902 | 36 % |
| Asia | 401 | 16 % |

La colonna centrale è centrata e l'ultima allineata a destra. Trascina il bordo di una colonna per allargarla.

## Riquadri

Un riquadro è una scatola colorata per qualcosa che nessuno deve perdersi.

> [!tip]+ Suggerimento
> Clicca sul titolo di un riquadro per chiuderlo.

> [!warning]+ Attenzione
> Ogni tipo ha il suo colore e la sua icona.

> [!danger]+ Pericolo
> Ce ne sono nove. Il menu **Inserisci** li elenca.

## Citazioni

> Una citazione rientra dal margine e prende una riga colorata sul lato.

## Codice

Il codice mantiene la spaziatura e viene colorato per linguaggio.

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

Un pezzo breve di codice dentro una frase si vede così: `questo`.

## Matematica

La matematica può stare dentro una frase, come $a^2 + b^2 = c^2$, o su una riga propria:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Immagini

![Il monte Fuji dietro i fiori di ciliegio.](/onboarding/fuji.webp){width=50 align=center}

Trascina un'immagine in una nota, oppure incollala. Cliccala una volta per cambiarne la dimensione, o per spostarla a sinistra, al centro o a destra. Quella sopra è a metà larghezza e centrata.

## Link

Ce ne sono due tipi, e sono diversi di proposito.

- Un link web apre un sito: [privacynotes.app](https://privacynotes.app/it)
- Un link di nota apre un'altra delle tue note: [[Come sono protette le tue note]]

Entrambi hanno un pulsante nella barra. La catena fa un link web. Quello accanto elenca le tue note e scegli quella che vuoi.

---

*Se scrivi già in markdown, scrivilo e si formatta man mano. Per vedere il testo grezzo dietro una nota, clicca **Mostra markdown** in basso a destra in questa nota.*
