---
id: 3d0c
title: Markdown'ın burada yapabildiği her şey
---

Aşağıdaki her şey bu notun üstündeki çubukla yapıldı. Ayar yok, eklenti yok. Bir metni seçin, çubuk onun üzerinde çalışsın. Boş bir satıra tıklayın, yeni bir şey başlatsın.

## Kelimeler

Bir kelimeyi **kalın** yapabilirsiniz, ya da *italik*, ya da ***ikisi birden***. Üstünü çizebilirsiniz, ~~şunun gibi~~. <u>Altını çizebilirsiniz</u>. Küçük yazı <sub>alt simge</sub>, üsler <sup>üst simge</sup> olur.

Metin <span style="color: #e03131">kırmızı</span>, <span style="color: #1971c2">mavi</span>, <span style="color: #2f9e44">yeşil</span> ya da dokuz renkten biri olabilir.

==Sarıyla vurgulanabilir== ya da <mark style="background-color: rgba(64, 192, 87, 0.35)">yeşille</mark>.

**Aa** düğmesi boyutu ve yazı tipini değiştirir. Metin <span style="font-size: 0.85em">küçük</span>, normal ya da <span style="font-size: 1.6em">büyük</span> olabilir. <span style="font-family: ui-sans-serif, system-ui, sans-serif">Düz</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">tırnaklı</span> ya da <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">eş aralıklı</span> olabilir.

## Kelimeler nerede durur

<p style="text-align: center;">Bu paragraf ortalanmış.</p>

<p style="text-align: right;">Bu ise sağa itilmiş.</p>

Hizalama bir paragrafın tamamını taşır, tek bir kelimeyi asla. İmleci paragrafa koyun ve hizalama düğmesini kullanın.

## Listeler

- Düz bir madde
- Bir tane daha
  - Bir satırı içeri almak için Tab'a basın
    - Ve bir kez daha

1. Numaralı bir adım
2. İkinci bir adım
3. Araya bir adım ekleyin, numaralar kendini düzeltsin

- [x] İşaretlediğiniz bir kutu

- [ ] Kutu

  - [ ] Bir görevi içeri almak için Tab'a basın

  - [ ] Kutuyu işaretleyin ve animasyona bakın

- [ ] Girintiyi azaltmak için Shift ve Tab'a basın

## Tablolar

| Bölge | Notlar | Pay |
| --- | :---: | ---: |
| Avrupa | 1.204 | %48 |
| Amerika | 902 | %36 |
| Asya | 401 | %16 |

Ortadaki sütun ortalanmış, sonuncusu sağa hizalanmış. Bir sütunun kenarını sürükleyerek genişletin.

## Bilgi kutuları

Bilgi kutusu, okuyucunun kaçırmaması gereken bir şey için renkli bir kutudur.

> [!tip]+ İpucu
> Bir bilgi kutusunu kapatmak için başlığına tıklayın.

> [!warning]+ Uyarı
> Her türün kendi rengi ve kendi simgesi vardır.

> [!danger]+ Tehlike
> Dokuz tür var. **Ekle** menüsü hepsini listeler.

## Alıntılar

> Bir alıntı kenar boşluğundan içeri girer ve yanında renkli bir çizgi taşır.

## Kod

Kod boşluklarını korur ve dile göre renklenir.

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

Cümlenin içindeki kısa bir kod parçası bunun yerine şöyle görünür: `bu`.

## Matematik

Matematik bir cümlenin içinde durabilir, örneğin $a^2 + b^2 = c^2$, ya da kendi satırında:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Görseller

![Kiraz çiçeklerinin arkasında Fuji Dağı.](/onboarding/fuji.webp){width=50 align=center}

Bir görseli nota sürükleyin ya da yapıştırın. Boyutunu değiştirmek ya da sola, ortaya veya sağa taşımak için bir kez tıklayın. Yukarıdaki yarım genişlikte ve ortalanmış.

## Bağlantılar

İki tür var ve bilerek farklı görünürler.

- Web bağlantısı bir siteyi açar: [privacynotes.app](https://privacynotes.app/tr)
- Not bağlantısı başka bir notunuzu açar: [[Notlarınız nasıl korunuyor]]

İkisinin de çubukta düğmesi var. Zincir web bağlantısı yapar. Köşeli parantezler not bağlantısı yapar: notlarınızı listeler, siz de kastettiğinizi seçersiniz. `[[` yazmak da aynı şeyi yapar.

---

*Zaten markdown yazıyorsanız yazın, yazdıkça biçimlenir. Herhangi bir notun arkasındaki ham metni görmek için bu notun sağ altındaki **Markdown'ı göster** bağlantısına tıklayın.*
