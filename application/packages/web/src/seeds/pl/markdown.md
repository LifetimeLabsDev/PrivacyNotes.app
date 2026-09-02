---
id: 3d0c
title: Wszystko, co markdown tu potrafi
---

Wszystko poniżej powstało za pomocą paska u góry tej notatki. Żadnych ustawień, żadnych wtyczek. Zaznacz tekst, a pasek na niego działa. Kliknij w pustą linijkę, a zacznie coś nowego.

## Słowa

Słowo możesz **pogrubić**, dać *kursywą* albo ***jedno i drugie***. Możesz je przekreślić, ~~tak jak to~~. Możesz je <u>podkreślić</u>. Drobny druk idzie w <sub>indeks dolny</sub>, a potęgi w <sup>górny</sup>.

Tekst może być <span style="color: #e03131">czerwony</span>, <span style="color: #1971c2">niebieski</span>, <span style="color: #2f9e44">zielony</span> albo w jednym z dziewięciu kolorów.

Może być ==podświetlony na żółto== albo <mark style="background-color: rgba(64, 192, 87, 0.35)">na zielono</mark>.

Przycisk **Aa** zmienia rozmiar i krój. Tekst może być <span style="font-size: 0.85em">mały</span>, zwykły albo <span style="font-size: 1.6em">duży</span>. Może być <span style="font-family: ui-sans-serif, system-ui, sans-serif">bezszeryfowy</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">szeryfowy</span> albo <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">o stałej szerokości</span>.

## Gdzie stoją słowa

<p style="text-align: center;">Ten akapit jest wyśrodkowany.</p>

<p style="text-align: right;">Ten jest przesunięty w prawo.</p>

Wyrównanie przesuwa cały akapit, nigdy pojedyncze słowo. Postaw kursor w akapicie i użyj przycisku wyrównania.

## Listy

- Zwykły punkt
- Kolejny
  - Naciśnij Tab, żeby wciąć linijkę
    - I jeszcze raz

1. Ponumerowany krok
2. Drugi krok
3. Wstaw krok gdziekolwiek, a numery poprawią się same

- [x] Pole, które zaznaczyłeś

- [ ] Pole

  - [ ] Naciśnij Tab, żeby wciąć zadanie

  - [ ] Zaznacz pole i zobacz animację

- [ ] Naciśnij Shift i Tab, żeby zmniejszyć wcięcie

## Tabele

| Region | Notatki | Udział |
| --- | :---: | ---: |
| Europa | 1204 | 48 % |
| Ameryki | 902 | 36 % |
| Azja | 401 | 16 % |

Środkowa kolumna jest wyśrodkowana, a ostatnia wyrównana do prawej. Przeciągnij krawędź kolumny, żeby ją poszerzyć.

## Ramki

Ramka to kolorowe pudełko na coś, czego czytelnik nie może przegapić.

> [!tip]+ Wskazówka
> Kliknij tytuł ramki, żeby ją zwinąć.

> [!warning]+ Uwaga
> Każdy rodzaj ma swój kolor i swoją ikonę.

> [!danger]+ Niebezpieczeństwo
> Jest ich dziewięć. Menu **Wstaw** je wymienia.

## Cytaty

> Cytat odsuwa się od marginesu i dostaje kolorową kreskę z boku.

## Kod

Kod zachowuje odstępy i dostaje kolory zależnie od języka.

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

Krótki kawałek kodu w środku zdania wygląda tak: `to`.

## Matematyka

Matematyka może siedzieć w zdaniu, jak $a^2 + b^2 = c^2$, albo stać w osobnej linijce:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Obrazy

![Góra Fudżi za kwiatami wiśni.](/onboarding/fuji.webp){width=50 align=center}

Przeciągnij obraz do notatki albo go wklej. Kliknij raz, żeby zmienić rozmiar, albo przesunąć go w lewo, na środek lub w prawo. Ten wyżej ma połowę szerokości i jest wyśrodkowany.

## Linki

Są dwa rodzaje i celowo wyglądają inaczej.

- Link internetowy otwiera stronę: [privacynotes.app](https://privacynotes.app/pl)
- Link do notatki otwiera inną twoją notatkę: [[Jak chronione są twoje notatki]]

Oba mają przycisk na pasku. Łańcuch robi link internetowy. Nawiasy kwadratowe robią link do notatki: wypisują twoje notatki, a ty wybierasz tę, o którą ci chodzi. Wpisanie `[[` działa tak samo.

---

*Jeśli już piszesz w markdownie, po prostu pisz, a formatuje się w locie. Surowy tekst za dowolną notatką zobaczysz przez **Pokaż markdown** na dole po prawej w tej notatce.*
