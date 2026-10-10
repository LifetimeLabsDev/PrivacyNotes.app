---
id: 3d0c
title: Markdownでここまでできます
---

下にあるものはすべて、このノートの上のツールバーで作りました。設定もプラグインもいりません。文字を選ぶとツールバーがそこに効きます。空の行をクリックすると、新しいものが始まります。

## 文字

語を**太字**にも、*斜体*にも、***両方***にもできます。~~このように~~取り消し線も引けます。<u>下線</u>も引けます。小さな文字は<sub>下付き</sub>に、指数は<sup>上付き</sup>になります。

文字は<span style="color: #e03131">赤</span>、<span style="color: #1971c2">青</span>、<span style="color: #2f9e44">緑</span>、ほか全9色から選べます。

==黄色でハイライト==することも、<mark style="background-color: rgba(64, 192, 87, 0.35)">緑で</mark>することもできます。

**Aa**ボタンで大きさとフォントが変わります。文字は<span style="font-size: 0.85em">小さく</span>も、標準にも、<span style="font-size: 1.6em">大きく</span>もできます。<span style="font-family: ui-sans-serif, system-ui, sans-serif">ゴシック</span>、<span style="font-family: ui-serif, Georgia, Cambria, serif">明朝</span>、<span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">等幅</span>から選べます。

## 文字の位置

<p style="text-align: center;">この段落は中央に寄せてあります。</p>

<p style="text-align: right;">こちらは右に寄せてあります。</p>

配置は段落ごと動きます。1語だけ動かすことはできません。段落にカーソルを置いて、配置ボタンを使ってください。

## リスト

- ふつうの箇条書き
- もうひとつ
  - Tabキーで1段下げられます
    - もう一度

1. 番号のついた手順
2. 2つめの手順
3. 途中に手順を足しても、番号はひとりでに直ります

- [x] チェックを入れた項目

- [ ] チェック項目

  - [ ] Tabキーでタスクを下げられます

  - [ ] チェックを入れてアニメーションを見てください

- [ ] ShiftとTabで下げた分を戻せます

## 表

| 地域 | ノート | 割合 |
| --- | :---: | ---: |
| ヨーロッパ | 1,204 | 48% |
| 南北アメリカ | 902 | 36% |
| アジア | 401 | 16% |

真ん中の列は中央寄せ、最後の列は右寄せです。列の端をドラッグすると幅が広がります。

## コールアウト

コールアウトは、読み手に見落としてほしくないことを入れる色つきの箱です。

> [!tip]+ ヒント
> アイコンをクリックすると閉じられます。

> [!warning]+ 注意
> 種類ごとに色とアイコンが違います。

> [!danger]+ 危険
> 種類はたくさんあります。**挿入**メニューに一覧があります。

> [!fold]- 折りたたみ
> 枠も色もなく、開くまで邪魔にならないテキストです。

## 引用

> 引用は余白から一段入って、横に色つきの線がつきます。

## 脚注

脚注を使うと、出典や補足を本文の外に置けます。[^1] 単語のあとに `[^1]` と入力するか、**挿入**メニューで**脚注**を選びます。小さな番号をクリックすると脚注に移動します。

## コード

コードは字下げがそのまま残り、言語ごとに色がつきます。ブロックの上にある名前がその言語です。クリックすると別の言語を選べます。

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

長いブロックは折りたたまれた状態で開くので、ノートの続きがすぐそこにあります。下のボタンを押すと全行が表示されます。

```js
const WORDS_PER_MINUTE = 200;

export function readingStats(markdown) {
  const text = markdown
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[#*_~`>|-]/g, ' ');

  const words = text.split(/\s+/).filter(Boolean);
  const headings = markdown.match(/^#{1,6} /gm) ?? [];
  const tasks = markdown.match(/^\s*- \[[ x]\] /gm) ?? [];
  const done = tasks.filter((task) => task.includes('[x]'));

  return {
    words: words.length,
    minutes: Math.max(1, Math.round(words.length / WORDS_PER_MINUTE)),
    headings: headings.length,
    tasks: tasks.length,
    done: done.length,
  };
}

export function summary(stats) {
  const parts = [`${stats.words} words`, `${stats.minutes} min read`];
  if (stats.headings > 0) {
    parts.push(`${stats.headings} sections`);
  }
  if (stats.tasks > 0) {
    parts.push(`${stats.done} of ${stats.tasks} tasks done`);
  }
  return parts.join(' · ');
}

export function isLongRead(stats) {
  return stats.minutes >= 10;
}
```

文中の短いコードは、代わりにこう見えます: `これ`。

## 数式

数式は文の中にも書けますし（$a^2 + b^2 = c^2$ のように）、独立した行にも置けます。

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## 画像

![桜の向こうに見える富士山。](/onboarding/fuji.webp){width=50 align=center}

画像はノートにドラッグするか、貼り付けてください。一度クリックすると大きさを変えたり、左・中央・右に寄せたりできます。上の画像は幅を半分にして中央に寄せてあります。

## リンク

2種類あり、見た目はわざと変えてあります。

- ウェブリンクはサイトを開きます: [privacynotes.app](https://privacynotes.app/ja)
- ノートリンクは自分の別のノートを開きます: [[ノートはどう守られているか]]

どちらもツールバーにボタンがあります。鎖のアイコンがウェブリンクです。角かっこのボタンはノートリンクで、ノートの一覧を出すので、そこから選びます。`[[` と入力しても同じです。

ノートリンクに表示する文字は、ノートのタイトルでなくてもかまいません。タイトル、縦線、ページに表示したい言葉の順に入力します: [[ノートはどう守られているか|この言葉]] でそのノートが開きます。

ノートリンクは、ノートを見出しの位置で開くこともできます。タイトルの後に `#` を入力して見出しを選びます: [[ノートはどう守られているか#鍵を誰が持つか]] は、そのノートを鍵の節で開きます。アウトラインの見出しにあるリンクアイコンで、このリンクをコピーすることもできます。

---

*すでにMarkdownを書いているなら、そのまま打てば打ちながら整います。どのノートでも、右下の**Markdownを表示**から元のテキストを見られます。*

[^1]: これが脚注です。横の矢印で上に戻れます。
