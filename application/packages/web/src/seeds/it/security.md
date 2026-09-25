---
id: 5ec1
title: Come sono protette le tue note
---

> [!info]- Ogni nota viene cifrata sul tuo dispositivo, prima di essere salvata da qualsiasi parte.
> &nbsp;

![La tabella delle note nel nostro database reale. Ogni nota è un lungo blocco di testo illeggibile.](/onboarding/database.webp)

Quello è il nostro database vero a Zurigo, non un disegno. La tua nota finisce nella colonna `ciphertext`. Byte cifrati è tutto ciò che conserviamo, qualunque opzione tu scelga qui sotto.

## Cosa succede quando scrivi una nota

1. La tua frase di 12 parole diventa una chiave. Succede sul tuo dispositivo.
2. La nota viene cifrata con quella chiave, sul tuo dispositivo. È così che viene salvata sul tuo disco, ed è così che arriva a noi.
3. Riceviamo la nota cifrata e la conserviamo. L'immagine sopra è com'è fatta.
4. Qualsiasi dispositivo con la stessa frase ricrea la stessa chiave e apre la nota.

## Chi ha la tua chiave

Ogni opzione tiene le tue note cifrate sul tuo dispositivo. Cambia solo dove vive la tua frase.

| Opzione | Dove vive la tua frase | Cosa ti dà |
| --- | --- | --- |
| **Accesso, chiave da noi** | Sul nostro server, cifrata | Un dispositivo nuovo entra col solo account |
| **Accesso, chiave sul tuo dispositivo** | Da te, in nessun altro posto | Accedi con Google, Apple o GitHub e tieni comunque la chiave |
| **Solo frase, nessun accesso** | Da te, in nessun altro posto | Niente email, niente nome, nessun account |

Con le ultime due non potremmo leggere una nota nemmeno se ci costringessero. La prima scambia questo con la comodità: la tua frase sta sul nostro server sotto una chiave nostra, così a un dispositivo nuovo basta il tuo account. Se il nostro server venisse mai violato, quella chiave potrebbe essere esposta.

Accesso con Google, Apple o GitHub? Più avanti puoi passare dall'una all'altra delle prime due, in **Impostazioni > Sicurezza > La tua frase**. Con un account di sola frase, la frase resta sempre con te.

> [!warning] Tieni una tua copia della frase
> La tua frase apre le tue note. Se la perdi, nessuno può recuperarla, noi compresi. <span style="color: #e03131">Scrivila su carta oggi.</span>

## Controlla di persona

[Istruzioni dettagliate per la verifica su GitHub](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Apri la scheda di rete del browser, poi modifica una nota. Guarda cosa riceviamo: un blocco di testo illeggibile.
- [ ] Leggi il codice di cifratura. È pubblico e abbastanza corto da finirlo in una sola volta.

| Cosa | Dove |
| --- | --- |
| La cifratura vera e propria | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| Cosa riceve il nostro server | [VERIFY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md#tier-1-one-minute-no-tools) |
| Cosa può e non può fare un attaccante | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Come segnalare una falla | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Una sola serratura copre tutto
> Note, voci di diario, segnalibri, voci della cassaforte e allegati sono cifrati allo stesso modo. [[Il trasloco]] mostra come portare qui ognuno di essi.
