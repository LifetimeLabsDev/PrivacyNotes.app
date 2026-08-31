---
id: 5ec1
title: Com estan protegides les teves notes
---

> [!info]- Cada nota es xifra al teu dispositiu, abans de desar-se enlloc.
> &nbsp;

![La taula de notes de la nostra base de dades real. Cada nota és un bloc llarg de text illegible.](/onboarding/database.webp)

Aquesta és la nostra base de dades de debò a Zuric, no un dibuix. La teva nota va a la columna `ciphertext`. Bytes xifrats és tot el que guardem, triïs l'opció que triïs a sota.

## Què passa quan escrius una nota

1. La teva frase de 12 paraules es converteix en una clau. Això passa al teu dispositiu.
2. La nota es xifra amb aquesta clau, al teu dispositiu. Així es desa al teu propi disc, i així viatja fins a nosaltres.
3. Rebem la nota xifrada i la guardem. La imatge de dalt és l'aspecte que té.
4. Qualsevol dispositiu amb la mateixa frase fa la mateixa clau i obre la nota.

## Qui té la teva clau

Totes les opcions mantenen les teves notes xifrades d'extrem a extrem. Es diferencien en on viu la teva frase.

| Opció | On viu la teva frase | Què t'aporta |
| --- | --- | --- |
| **Inici de sessió, clau amb nosaltres** | Al nostre servidor, xifrada | Un dispositiu nou entra només amb aquest compte |
| **Inici de sessió, clau al teu dispositiu** | Amb tu, enlloc més | Entra amb Google, Apple o GitHub i conserva la clau |
| **Només la frase, sense inici de sessió** | Amb tu, enlloc més | Sense correu, sense nom, sense cap compte |

Amb les dues últimes no podríem llegir una nota ni que ens hi obliguessin. La primera ho canvia per comoditat: la teva frase és al nostre servidor sota una clau nostra, així que un dispositiu nou no necessita res més que el teu compte. Si algun dia atacaven el nostre servidor, aquesta clau podria quedar exposada.

No estàs lligat a la tria que has fet. Canvia-la a **Configuració > Seguretat > La teva frase**.

> [!warning] Guarda la teva pròpia còpia de la frase
> La teva frase obre les teves notes. Si la perds, ningú no la pot recuperar, nosaltres inclosos. <span style="color: #e03131">Escriu-la en paper avui.</span>

## Comprova-ho tu mateix

[Instruccions detallades de verificació a GitHub](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Obre la pestanya de xarxa del navegador i després edita una nota. Mira què ens arriba: un bloc de text illegible.
- [ ] Llegeix el codi del xifratge. És públic i prou curt per acabar-lo d'una tirada.

| Què | On |
| --- | --- |
| El xifratge mateix | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| L'estructura de la base de dades | [schema.sql](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/schema/schema.sql) |
| Què pot i què no pot fer un atacant | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Com informar d'un forat | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Un sol pany ho cobreix tot
> Notes, entrades de diari, marcadors, elements de la caixa forta i adjunts es xifren igual. [[La mudança]] mostra com portar-hi cadascun.
