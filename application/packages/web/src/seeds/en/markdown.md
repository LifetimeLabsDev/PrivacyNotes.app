---
id: 3d0c
title: Everything markdown can do here
tags:
folder: Markdown
order: 2
---

Everything below was made with the toolbar at the top of this note. No settings, no plugins. Select some text and the toolbar acts on it. Click in an empty line and it starts something new.

## Words

You can make a word **bold**, or *italic*, or ***both***. You can put a line through it, like ~~this one~~. You can <u>underline</u> it. Small print goes in <sub>subscript</sub> and powers go in <sup>superscript</sup>.

Text can be <span style="color: #e03131">red</span>, <span style="color: #1971c2">blue</span>, <span style="color: #2f9e44">green</span> or any of nine colours.

It can be ==highlighted in yellow== or <mark style="background-color: rgba(64, 192, 87, 0.35)">in green</mark>.

The **Aa** button changes size and font. Text can be <span style="font-size: 0.85em">small</span>, normal, or <span style="font-size: 1.6em">large</span>. It can be <span style="font-family: ui-sans-serif, system-ui, sans-serif">plain</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">serif</span>, or <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">monospace</span>.

## Where the words sit

<p style="text-align: center;">This paragraph is centred.</p>

<p style="text-align: right;">This one is pushed to the right.</p>

Alignment moves a whole paragraph, never a single word. Put the cursor in the paragraph and use the alignment button.

## Lists

- A plain bullet
- Another one
  - Press Tab to move a line in
    - And again

1. A numbered step
2. A second step
3. Insert a step anywhere and the numbers correct themselves

- [x] A box you have ticked

- [ ] Checkbox

  - [ ] Press Tab to indent a Task

  - [ ] Check the box to see the animation

- [ ] Press Shift and Tab to decrease indent

## Tables

| Region | Notes | Share |
| --- | :---: | ---: |
| Europe | 1,204 | 48% |
| Americas | 902 | 36% |
| Asia | 401 | 16% |

The middle column is centred and the last one is right-aligned. Click a column edge and drag to make it wider.

## Callouts

A callout is a coloured box for something a reader must not miss.

> [!tip]+ Tip
> Click the title of a callout to fold it shut.

> [!warning]+ Warning
> Each kind has its own colour and its own icon.

> [!danger]+ Danger
> There are nine kinds. The **Insert** menu lists them.

## Quotes

> A quote steps in from the margin and takes a coloured line down its side.

## Code

Code keeps its spacing and gets coloured by language.

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

A short piece of code inside a sentence looks like `this` instead.

## Maths

Maths can sit inside a sentence, like $a^2 + b^2 = c^2$, or stand on its own line:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Images

![Mount Fuji behind cherry blossom.](/onboarding/fuji.webp){width=50 align=center}

Drag an image into a note, or paste it. Click it once to change its size, or to move it left, centre or right. The one above is half width and centred.

## Links

There are two kinds, and they look different on purpose.

- A web link opens a site: [privacynotes.app](https://privacynotes.app/en)
- A note-link opens another of your notes: [[How your notes are protected]]

Both have a toolbar button. The chain makes a web link. The brackets make a note-link: they list your notes, and you pick the one you mean. Typing `[[` does the same thing.

---

*If you already write markdown, type it and it formats as you go. To see the raw text behind any note, click on **Show markdown** at the bottom right of this note.*