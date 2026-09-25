---
id: 5ec1
title: Hur dina anteckningar skyddas
---

> [!info]- Varje anteckning krypteras på din enhet, innan den lagras någonstans.
> &nbsp;

![Anteckningstabellen i vår riktiga databas. Varje anteckning är ett långt block oläslig text.](/onboarding/database.webp)

Det där är vår riktiga databas i Zürich, inte en teckning av den. Din anteckning hamnar i kolumnen `ciphertext`. Krypterade bytes är allt vi lagrar, vilket alternativ du än väljer nedan.

## Vad som händer när du skriver en anteckning

1. Din fras på 12 ord blir en nyckel. Det sker på din enhet.
2. Anteckningen krypteras med den nyckeln, på din enhet. Så sparas den på din egen disk, och så färdas den till oss.
3. Vi tar emot den krypterade anteckningen och lagrar den. Bilden ovan är hur det ser ut.
4. Vilken enhet som helst med samma fras gör samma nyckel och öppnar anteckningen.

## Vem som har din nyckel

Alla alternativ håller dina anteckningar krypterade på din enhet. De skiljer sig i var din fras bor.

| Alternativ | Var din fras bor | Vad du får ut av det |
| --- | --- | --- |
| **Inloggning, nyckeln hos oss** | På vår server, krypterad | En ny enhet loggar in med bara det kontot |
| **Inloggning, nyckeln på din enhet** | Hos dig, ingen annanstans | Logga in med Google, Apple eller GitHub och behåll ändå nyckeln |
| **Bara fras, ingen inloggning** | Hos dig, ingen annanstans | Ingen e-post, inget namn, inget konto alls |

Med de två nedersta kunde vi inte läsa en anteckning ens om vi tvingades. Det första byter bort det mot bekvämlighet: din fras ligger på vår server under en nyckel som är vår, så en ny enhet behöver inget mer än ditt konto. Om vår server någonsin bröts in i kunde den nyckeln bli blottad.

Inloggad med Google, Apple eller GitHub? Du kan byta mellan de två första senare, under **Inställningar > Säkerhet > Din fras**. Med ett fraskonto stannar frasen alltid hos dig.

> [!warning] Ha en egen kopia av frasen
> Din fras öppnar dina anteckningar. Tappar du bort den kan ingen hämta tillbaka den, inte vi heller. <span style="color: #e03131">Skriv ner den på papper idag.</span>

## Kolla själv

[Utförliga instruktioner för granskning på GitHub](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Öppna webbläsarens nätverksflik och ändra sedan en anteckning. Titta på vad vi tar emot: ett block oläslig text.
- [ ] Läs krypteringskoden. Den är offentlig, och kort nog att läsa ut i ett svep.

| Vad | Var |
| --- | --- |
| Själva krypteringen | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| Vad vår server tar emot | [VERIFY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md#tier-1-one-minute-no-tools) |
| Vad en angripare kan och inte kan | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Hur man rapporterar ett hål | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Ett lås täcker allt
> Anteckningar, dagboksinlägg, bokmärken, valvposter och bilagor krypteras på samma sätt. [[Flytten]] visar hur du tar med dig var och en av dem.
