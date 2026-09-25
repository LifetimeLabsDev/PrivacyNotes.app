---
id: 5ec1
title: Comment tes notes sont protégées
---

> [!info]- Chaque note est chiffrée sur ton appareil, avant d'être stockée où que ce soit.
> &nbsp;

![La table des notes dans notre vraie base de données. Chaque note est un long bloc de texte illisible.](/onboarding/database.webp)

Voilà notre vraie base de données à Zurich, pas un dessin. Ta note va dans la colonne `ciphertext`. Des octets chiffrés, c'est tout ce que nous stockons, quelle que soit l'option choisie plus bas.

## Ce qui se passe quand tu écris une note

1. Ta phrase de 12 mots devient une clé. Cela se passe sur ton appareil.
2. La note est chiffrée avec cette clé, sur ton appareil. C'est ainsi qu'elle est enregistrée sur ton propre disque, et ainsi qu'elle voyage jusqu'à nous.
3. Nous recevons la note chiffrée et la stockons. L'image ci-dessus montre à quoi cela ressemble.
4. N'importe quel appareil avec la même phrase refabrique la même clé et ouvre la note.

## Qui détient ta clé

Toutes les options gardent tes notes chiffrées sur ton appareil. Elles diffèrent par l'endroit où vit ta phrase.

| Option | Où vit ta phrase | Ce que ça t'apporte |
| --- | --- | --- |
| **Connexion, clé chez nous** | Sur notre serveur, chiffrée | Un nouvel appareil se connecte avec ce seul compte |
| **Connexion, clé sur ton appareil** | Chez toi, nulle part ailleurs | Connexion Google, Apple ou GitHub, et tu gardes la clé |
| **Phrase seule, sans connexion** | Chez toi, nulle part ailleurs | Pas d'e-mail, pas de nom, pas de compte |

Avec les deux dernières, nous ne pourrions pas lire une note même si on nous y contraignait. La première échange cela contre du confort : ta phrase est sur notre serveur sous une clé à nous, donc un nouvel appareil n'a besoin que de ton compte. Si notre serveur était un jour compromis, cette clé pourrait être exposée.

Connecté avec Google, Apple ou GitHub ? Tu peux basculer entre les deux premières plus tard, dans **Paramètres > Sécurité > Ta phrase**. Avec un compte à phrase seule, la phrase reste toujours avec toi.

> [!warning] Garde ta propre copie de la phrase
> Ta phrase ouvre tes notes. Si tu la perds, personne ne peut la retrouver, nous compris. <span style="color: #e03131">Écris-la sur du papier aujourd'hui.</span>

## Vérifie par toi-même

[Instructions de vérification détaillées sur GitHub](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Ouvre l'onglet réseau de ton navigateur, puis modifie une note. Regarde ce que nous recevons : un bloc de texte illisible.
- [ ] Lis le code de chiffrement. Il est public, et assez court pour être lu d'une traite.

| Quoi | Où |
| --- | --- |
| Le chiffrement lui-même | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| Ce que reçoit notre serveur | [VERIFY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md#tier-1-one-minute-no-tools) |
| Ce qu'un attaquant peut et ne peut pas faire | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Comment signaler une faille | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Une seule serrure couvre tout
> Notes, entrées de journal, signets, éléments du coffre et pièces jointes sont chiffrés de la même façon. [[L'emménagement]] montre comment faire venir chacun d'eux.
