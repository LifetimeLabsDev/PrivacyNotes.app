---
id: 5ec1
title: Jak chronione są twoje notatki
---

> [!info]- Każda notatka jest szyfrowana na twoim urządzeniu, zanim gdziekolwiek zostanie zapisana.
> &nbsp;

![Tabela notatek w naszej prawdziwej bazie danych. Każda notatka to długi blok nieczytelnego tekstu.](/onboarding/database.webp)

To nasza prawdziwa baza danych w Zurychu, nie rysunek. Twoja notatka trafia do kolumny `ciphertext`. Zaszyfrowane bajty to wszystko, co przechowujemy, którąkolwiek opcję niżej wybierzesz.

## Co się dzieje, gdy piszesz notatkę

1. Twoja fraza z 12 słów staje się kluczem. Dzieje się to na twoim urządzeniu.
2. Notatka jest szyfrowana tym kluczem, na twoim urządzeniu. Tak zapisuje się na twoim własnym dysku i tak podróżuje do nas.
3. Dostajemy zaszyfrowaną notatkę i przechowujemy ją. Obrazek wyżej pokazuje, jak to wygląda.
4. Dowolne urządzenie z tą samą frazą tworzy ten sam klucz i otwiera notatkę.

## Kto ma twój klucz

W każdej opcji twoje notatki są szyfrowane na twoim urządzeniu. Różnią się tym, gdzie leży twoja fraza.

| Opcja | Gdzie leży twoja fraza | Co ci to daje |
| --- | --- | --- |
| **Logowanie, klucz u nas** | Na naszym serwerze, zaszyfrowany | Nowe urządzenie loguje się samym kontem |
| **Logowanie, klucz na Twoim urządzeniu** | U ciebie, nigdzie indziej | Zaloguj się przez Google, Apple albo GitHub i nadal trzymaj klucz |
| **Sama fraza, bez logowania** | U ciebie, nigdzie indziej | Bez e-maila, bez nazwiska, bez konta |

Przy dwóch ostatnich nie odczytalibyśmy notatki, nawet gdyby nas zmuszono. Pierwsza wymienia to na wygodę: twoja fraza leży na naszym serwerze pod naszym kluczem, więc nowemu urządzeniu wystarczy twoje konto. Gdyby nasz serwer kiedyś padł ofiarą włamania, ten klucz mógłby wyciec.

Logujesz się przez Google, Apple albo GitHub? Między dwiema pierwszymi opcjami możesz później przełączać się w **Ustawienia > Bezpieczeństwo > Twoja fraza**. Przy koncie opartym na samej frazie fraza zawsze zostaje u ciebie.

> [!warning] Miej własną kopię frazy
> Twoja fraza otwiera twoje notatki. Jeśli ją zgubisz, nikt jej nie odzyska, my też nie. <span style="color: #e03131">Zapisz ją dziś na papierze.</span>

## Sprawdź to sam

[Szczegółowa instrukcja weryfikacji na GitHubie](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Otwórz w przeglądarce kartę Sieć, a potem zmień notatkę. Zobacz, co do nas dociera: blok nieczytelnego tekstu.
- [ ] Przeczytaj kod szyfrowania. Jest publiczny i dość krótki, żeby przeczytać go za jednym razem.

| Co | Gdzie |
| --- | --- |
| Samo szyfrowanie | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| Co dostaje nasz serwer | [VERIFY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md#tier-1-one-minute-no-tools) |
| Co napastnik może, a czego nie | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Jak zgłosić lukę | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Jeden zamek obejmuje wszystko
> Notatki, wpisy dziennika, zakładki, wpisy sejfu i załączniki są szyfrowane tak samo. [[Przeprowadzka]] pokazuje, jak przenieść każde z nich.
