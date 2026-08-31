---
id: 5ec1
title: 你的筆記如何受到保護
---

> [!info]- 每則筆記在存到任何地方之前，就已經在你的裝置上加密。
> &nbsp;

![我們正式資料庫裡的筆記資料表。每則筆記的內容都是一長串讀不懂的文字。](/onboarding/database.webp)

那是我們在蘇黎世的真正資料庫，不是示意圖。你的筆記會進到 `ciphertext` 這一欄。不管你在下面選哪一種做法，我們存下來的都只有加密後的位元組。

## 你寫一則筆記時，發生了什麼

1. 你的 12 個字助憶詞會變成一把鑰匙。這件事在你的裝置上完成。
2. 筆記用那把鑰匙在你的裝置上加密。它就以這個樣子存在你自己的磁碟上，也以這個樣子送到我們這裡。
3. 我們收到加密後的筆記並存起來。上面那張圖就是它的樣子。
4. 任何一台有相同助憶詞的裝置，都能做出同一把鑰匙，把筆記打開。

## 誰握有你的鑰匙

每一種做法都讓筆記維持端對端加密。差別只在助憶詞放在哪裡。

| 做法 | 助憶詞放在哪 | 你得到什麼 |
| --- | --- | --- |
| **登入，金鑰由我們保管** | 在我們的伺服器上，加密存放 | 新裝置只靠那組登入就能進來 |
| **登入，金鑰留在你的裝置** | 只在你手上，別的地方沒有 | 用 Google、Apple 或 GitHub 登入，鑰匙仍然歸你 |
| **只用助憶詞，不必登入** | 只在你手上，別的地方沒有 | 不用電子郵件、不用姓名、完全不用登入 |

下面兩種做法，就算有人逼我們，我們也讀不到筆記。第一種把這件事換成方便：你的助憶詞放在我們的伺服器上，由我們的一把鑰匙保護，所以新裝置只需要你的登入。萬一我們的伺服器被入侵，那把鑰匙就有可能外洩。

你不會被自己選過的做法綁住。到 **設定 > 安全性 > 你的助憶詞** 就能換。

> [!warning] 自己也留一份助憶詞
> 助憶詞能打開你的筆記。弄丟了就沒有人救得回來，我們也不行。<span style="color: #e03131">今天就抄在紙上。</span>

## 自己查證

[GitHub 上的完整查證步驟](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] 打開瀏覽器的網路分頁，然後編輯一則筆記。看看我們收到什麼：一團讀不懂的文字。
- [ ] 讀一讀加密的程式碼。它是公開的，而且短到可以一次讀完。

| 內容 | 位置 |
| --- | --- |
| 加密本身 | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| 資料庫結構 | [schema.sql](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/schema/schema.sql) |
| 攻擊者做得到與做不到的事 | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| 怎麼回報漏洞 | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] 同一把鎖罩住全部
> 筆記、日誌紀錄、書籤、保險庫項目和附件，都用同樣的方式加密。[[搬家]] 會示範怎麼把每一種搬過來。
