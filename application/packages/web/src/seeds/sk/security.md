---
id: 5ec1
title: Ako sú tvoje poznámky chránené
tags: privacy, encryption
folder: Security
order: 3
---

> [!info]- Každá poznámka je zašifrovaná na tvojom zariadení, skôr než sa niekde uloží.
> &nbsp;

![Tabuľka poznámok v našej živej databáze. Telo každej poznámky je jeden dlhý blok nečitateľného textu.](/onboarding/database.webp)

Toto je naša živá databáza v Zürichu, nie jej nákres. Tvoja poznámka ide do stĺpca `ciphertext`. Ukladáme iba zašifrované bajty, nech si nižšie vyberieš ktorúkoľvek možnosť.

## Čo sa stane, keď napíšeš poznámku

1. Z tvojej frázy z 12 slov sa stane kľúč. Deje sa to na tvojom zariadení.
2. Poznámka sa týmto kľúčom zašifruje na tvojom zariadení. Takto sa ukladá na tvoj vlastný disk a takto putuje k nám.
3. Zašifrovanú poznámku prijmeme a uložíme. Snímka obrazovky vyššie ukazuje, ako to vyzerá.
4. Ktorékoľvek zariadenie s rovnakou frázou vytvorí rovnaký kľúč a poznámku otvorí.

## Kto drží tvoj kľúč

Každá možnosť udržiava tvoje poznámky zašifrované na tvojom zariadení. Líšia sa v tom, kde je uložená tvoja fráza.

| Možnosť | Kde je tvoja fráza | Čo tým získaš |
| --- | --- | --- |
| **Prihlásenie, kľúč uložený u nás** | Na našom serveri, zašifrovaná | Nové zariadenie sa prihlási iba týmto prihlásením |
| **Prihlásenie, kľúč na tvojom zariadení** | U teba, nikde inde | Prihlás sa cez Google, Apple alebo GitHub a kľúč zostane u teba |
| **Iba fráza, bez prihlásenia** | U teba, nikde inde | Žiadny e-mail, žiadne meno, žiadne prihlásenie |

Pri spodných dvoch by sme poznámku nedokázali prečítať, ani keby nás k tomu niekto prinútil. Prvá možnosť to vymieňa za pohodlie: tvoja fráza leží na našom serveri pod naším kľúčom, takže novému zariadeniu stačí tvoje prihlásenie. Ak by niekto niekedy prelomil náš server, ten kľúč by mohol byť odhalený.

Prihlasuješ sa cez Google, Apple alebo GitHub? Medzi prvými dvoma možnosťami môžeš neskôr prepnúť v **Nastavenia > Účet > Správa kľúča**. Pri účte iba s frázou zostáva fráza vždy u teba.

> [!warning] Maj vlastnú kópiu frázy
> Tvoja fráza otvára tvoje poznámky. Ak ju stratíš, nikto ti ju neobnoví, ani my. <span style="color: #e03131">Napíš si ju ešte dnes na papier.</span>

## Over si to na vlastné oči

[Podrobný návod na overenie na GitHube](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Otvor v prehliadači kartu Sieť a potom uprav poznámku. Sleduj, čo dostávame: jeden blok nečitateľného textu.
- [ ] Prečítaj si šifrovací kód. Je verejný a dosť krátky na to, aby sa dal prečítať na jedno posedenie.

| Čo | Kde |
| --- | --- |
| Samotné šifrovanie | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| Čo dostáva náš server | [VERIFY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md#tier-1-one-minute-no-tools) |
| Čo útočník môže a čo nie | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Ako nahlásiť dieru | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Jeden zámok pokrýva všetko
> Poznámky, záznamy v denníku, záložky, položky trezoru aj prílohy sa šifrujú rovnako. [[Sťahovanie]] ukazuje, ako sem každú z týchto vecí preniesť.
