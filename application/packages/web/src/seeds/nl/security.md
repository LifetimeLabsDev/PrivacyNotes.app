---
id: 5ec1
title: Hoe je notities beschermd zijn
---

> [!info]- Elke notitie wordt op je apparaat versleuteld, voordat hij ergens wordt opgeslagen.
> &nbsp;

![De notitietabel in onze echte database. Elke notitie is één lang blok onleesbare tekst.](/onboarding/database.webp)

Dat is onze echte database in Zürich, geen tekening ervan. Je notitie komt in de kolom `ciphertext`. Versleutelde bytes zijn alles wat wij bewaren, welke optie je hieronder ook kiest.

## Wat er gebeurt als je een notitie schrijft

1. Je herstelzin van 12 woorden wordt een sleutel. Dat gebeurt op je apparaat.
2. De notitie wordt met die sleutel versleuteld, op je apparaat. Zo wordt hij op je eigen schijf bewaard, en zo reist hij naar ons.
3. Wij krijgen de versleutelde notitie en bewaren hem. De afbeelding hierboven laat zien hoe dat eruitziet.
4. Elk apparaat met dezelfde zin maakt dezelfde sleutel en opent de notitie.

## Wie je sleutel heeft

Elke optie houdt je notities end-to-end versleuteld. Ze verschillen in waar je zin ligt.

| Optie | Waar je zin ligt | Wat je ermee wint |
| --- | --- | --- |
| **Login, sleutel bij ons** | Op onze server, versleuteld | Een nieuw apparaat komt binnen met alleen dat account |
| **Login, sleutel op je apparaat** | Bij jou, nergens anders | Inloggen met Google, Apple of GitHub en toch de sleutel houden |
| **Alleen herstelzin, geen login** | Bij jou, nergens anders | Geen e-mail, geen naam, helemaal geen account |

Bij de onderste twee zouden wij een notitie niet kunnen lezen, ook niet als we ertoe gedwongen werden. De eerste ruilt dat in voor gemak: je zin staat op onze server onder een sleutel van ons, dus een nieuw apparaat heeft niets meer nodig dan je account. Als onze server ooit gekraakt wordt, kan die sleutel bloot komen te liggen.

Je zit niet vast aan je keuze. Verander hem bij **Instellingen > Beveiliging > Je herstelzin**.

> [!warning] Houd zelf een kopie van de zin
> Je zin opent je notities. Raak je hem kwijt, dan kan niemand hem terughalen, wij ook niet. <span style="color: #e03131">Schrijf hem vandaag op papier.</span>

## Controleer het zelf

[Uitgebreide controle-instructies op GitHub](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Open het netwerktabblad van je browser en pas dan een notitie aan. Kijk wat wij binnenkrijgen: één blok onleesbare tekst.
- [ ] Lees de versleutelingscode. Hij is openbaar, en kort genoeg om in één keer uit te lezen.

| Wat | Waar |
| --- | --- |
| De versleuteling zelf | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| De opbouw van de database | [schema.sql](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/schema/schema.sql) |
| Wat een aanvaller wel en niet kan | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Hoe je een lek meldt | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Eén slot dekt alles
> Notities, dagboekstukken, bladwijzers, kluisitems en bijlagen worden op dezelfde manier versleuteld. [[De verhuizing]] laat zien hoe je ze stuk voor stuk hierheen haalt.
