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
> Clicca sulla sua icona per chiuderlo.

> [!warning]+ Attenzione
> Ogni tipo ha il suo colore e la sua icona.

> [!danger]+ Pericolo
> Ce ne sono molti. Il menu **Inserisci** li elenca.

> [!fold]- Comprimibile
> Niente riquadro né colore: solo testo che resta da parte finché non lo apri.

## Citazioni

> Una citazione rientra dal margine e prende una riga colorata sul lato.

## Note a piè di pagina

Una nota a piè di pagina tiene una fonte o un inciso fuori dal testo.[^1] Scrivi `[^1]` dopo una parola, o scegli **Nota a piè di pagina** nel menu **Inserisci**. Fai clic sul numerino per andare alla nota.

## Codice

Il codice mantiene la spaziatura e viene colorato per linguaggio. Il nome in alto in un blocco è il suo linguaggio: cliccalo per sceglierne un altro.

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

Un blocco lungo si apre chiuso, così il resto della nota resta vicino. Il pulsante sotto mostra tutte le righe.

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
- Un collegamento fra note apre un'altra delle tue note: [[Come sono protette le tue note]]

Entrambi hanno un pulsante nella barra. La catena fa un link web. Le parentesi quadre fanno un link a una nota: elencano le tue note e scegli quella che vuoi. Digitare `[[` fa la stessa cosa.

Un collegamento fra note non deve per forza mostrare il titolo della nota. Scrivi il titolo, una barra verticale, poi le parole che vuoi vedere nella pagina: [[Come sono protette le tue note|queste parole]] aprono quella nota.

Un collegamento fra note può anche aprire una nota a uno dei suoi titoli. Scrivi un `#` dopo il titolo e scegli il titolo della sezione: [[Come sono protette le tue note#Chi ha la tua chiave]] apre quella nota alla sezione sulla chiave. L'icona del link su un titolo nella struttura copia un collegamento così per te.

---

*Se scrivi già in markdown, scrivilo e si formatta man mano. Per vedere il testo grezzo dietro una nota, clicca **Mostra markdown** in basso a destra in questa nota.*

[^1]: Questa è la nota. La freccia accanto ti riporta su.
