---
id: 3d0c
title: Markdown 在這裡能做的一切
---

下面每一樣，都是用這則筆記上方那排工具做出來的。沒有設定，沒有外掛。選取文字，工具就作用在它身上。點一下空白行，它就開始新的東西。

## 文字

你可以把一個詞變 **粗體**、*斜體*，或是 ***兩個都要***。可以畫掉，~~像這樣~~。可以 <u>加底線</u>。小字放 <sub>下標</sub>，次方放 <sup>上標</sup>。

文字可以是 <span style="color: #e03131">紅</span>、<span style="color: #1971c2">藍</span>、<span style="color: #2f9e44">綠</span>，或九種顏色的任何一種。

可以 ==用黃色標起來==，也可以 <mark style="background-color: rgba(64, 192, 87, 0.35)">用綠色</mark>。

**Aa** 按鈕會改變大小和字體。文字可以 <span style="font-size: 0.85em">小</span>、正常，或 <span style="font-size: 1.6em">大</span>。可以是 <span style="font-family: ui-sans-serif, system-ui, sans-serif">黑體</span>、<span style="font-family: ui-serif, Georgia, Cambria, serif">襯線</span> 或 <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">等寬</span>。

## 文字站在哪裡

<p style="text-align: center;">這一段是置中的。</p>

<p style="text-align: right;">這一段被推到右邊。</p>

對齊搬的是整個段落，不會只搬一個詞。把游標放進段落，再用對齊按鈕。

## 清單

- 一個普通的項目
- 再一個
  - 按 Tab 可以把一行往內縮
    - 再一次

1. 有編號的步驟
2. 第二個步驟
3. 在任何位置插入一步，編號會自己更正

- [x] 你打過勾的方框

- [ ] 方框

  - [ ] 按 Tab 可以把一項待辦往內縮

  - [ ] 打勾看看動畫

- [ ] 按 Shift 加 Tab 可以往外退一層

## 表格

| 地區 | 筆記 | 佔比 |
| --- | :---: | ---: |
| 歐洲 | 1,204 | 48% |
| 美洲 | 902 | 36% |
| 亞洲 | 401 | 16% |

中間那欄置中，最後一欄靠右。拖曳欄位邊界就能把它拉寬。

## 提示框

提示框是一個彩色方塊，用來放讀者不能錯過的東西。

> [!tip]+ 小提示
> 點一下提示框的標題就能把它收起來。

> [!warning]+ 注意
> 每一種都有自己的顏色和圖示。

> [!danger]+ 危險
> 一共有九種。**插入** 選單裡有完整清單。

## 引用

> 引用會從邊界往內縮，旁邊帶一條彩色的線。

## 程式碼

程式碼會保留原本的空白，並依語言上色。

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

句子中間的一小段程式碼，看起來會是這樣：`像這個`。

## 數學

數學可以放在句子裡，例如 $a^2 + b^2 = c^2$，也可以自己占一行：

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## 圖片

![櫻花後方的富士山。](/onboarding/fuji.webp){width=50 align=center}

把圖片拖進筆記，或直接貼上。點一下就能改大小，或把它移到靠左、置中、靠右。上面那張是一半寬度並置中。

## 連結

有兩種，而且刻意長得不一樣。

- 網頁連結會打開一個網站：[privacynotes.app](https://privacynotes.app/tw)
- 筆記連結會打開你的另一則筆記：[[你的筆記如何受到保護]]

兩種在工具列都有按鈕。鎖鏈圖示做的是網頁連結。旁邊那顆會列出你的筆記，你挑要指向哪一則。

---

*如果你本來就寫 Markdown，直接打就好，邊打邊套用格式。想看任何一則筆記背後的原始文字，點這則筆記右下角的 **顯示 Markdown**。*
