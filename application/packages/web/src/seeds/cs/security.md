---
id: 5ec1
title: Jak jsou tvoje poznámky chráněné
---

> [!info]- Každá poznámka se zašifruje na tvém zařízení, ještě než se kamkoli uloží.
> &nbsp;

![Tabulka poznámek v naší skutečné databázi. Každá poznámka je dlouhý blok nečitelného textu.](/onboarding/database.webp)

Tohle je naše opravdová databáze v Curychu, ne kresba. Tvoje poznámka jde do sloupce `ciphertext`. Zašifrované bajty jsou všechno, co uchováváme, ať si dole vybereš kteroukoli možnost.

## Co se stane, když napíšeš poznámku

1. Tvoje fráze z 12 slov se změní v klíč. Děje se to na tvém zařízení.
2. Poznámka se tím klíčem zašifruje, na tvém zařízení. Tak se ukládá na tvůj vlastní disk a tak putuje k nám.
3. Dostaneme zašifrovanou poznámku a uložíme ji. Obrázek nahoře ukazuje, jak to vypadá.
4. Jakékoli zařízení se stejnou frází vyrobí stejný klíč a poznámku otevře.

## Kdo má tvůj klíč

U každé možnosti se tvoje poznámky šifrují na tvém zařízení. Liší se tím, kde tvoje fráze leží.

| Možnost | Kde tvoje fráze leží | Co ti to dá |
| --- | --- | --- |
| **Přihlášení, klíč u nás** | Na našem serveru, zašifrovaný | Nové zařízení se přihlásí jen tím účtem |
| **Přihlášení, klíč na tvém zařízení** | U tebe, nikde jinde | Přihlas se přes Google, Apple nebo GitHub a klíč si nech |
| **Jen fráze, žádné přihlášení** | U tebe, nikde jinde | Bez e-mailu, bez jména, bez účtu |

U spodních dvou bychom poznámku nepřečetli, ani kdyby nás k tomu donutili. První to mění za pohodlí: tvoje fráze leží na našem serveru pod naším klíčem, takže novému zařízení stačí tvůj účet. Kdyby náš server někdy prolomili, ten klíč by se mohl dostat ven.

Přihlašuješ se přes Google, Apple nebo GitHub? Mezi prvními dvěma možnostmi můžeš později přepnout v **Nastavení > Zabezpečení > Tvoje fráze**. U účtu jen s frází zůstává fráze vždycky u tebe.

> [!warning] Měj vlastní kopii fráze
> Tvoje fráze otevírá tvoje poznámky. Když ji ztratíš, nikdo ti ji neobnoví, my taky ne. <span style="color: #e03131">Napiš si ji dnes na papír.</span>

## Ověř si to sám

[Podrobný návod k ověření na GitHubu](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Otevři v prohlížeči záložku Síť a pak uprav poznámku. Podívej se, co k nám dorazí: blok nečitelného textu.
- [ ] Přečti si kód šifrování. Je veřejný a dost krátký na to, abys ho dočetl najednou.

| Co | Kde |
| --- | --- |
| Samotné šifrování | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| Co dostává náš server | [VERIFY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md#tier-1-one-minute-no-tools) |
| Co útočník může a nemůže | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Jak nahlásit díru | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Jeden zámek pokrývá všechno
> Poznámky, deníkové zápisy, záložky, položky trezoru i přílohy se šifrují stejně. [[Stěhování]] ukazuje, jak sem každou z těch věcí dostat.
