---
id: 5ec1
title: Notlarınız nasıl korunuyor
---

> [!info]- Her not, herhangi bir yere kaydedilmeden önce cihazınızda şifrelenir.
> &nbsp;

![Gerçek veritabanımızdaki not tablosu. Her not okunamayan uzun bir metin bloğu.](/onboarding/database.webp)

Bu bizim Zürih'teki gerçek veritabanımız, çizimi değil. Notunuz `ciphertext` sütununa gider. Aşağıdaki seçeneklerden hangisini seçerseniz seçin, sakladığımız tek şey şifreli baytlardır.

## Bir not yazdığınızda ne olur

1. 12 kelimelik ifadeniz bir anahtara dönüşür. Bu, cihazınızda olur.
2. Not, o anahtarla cihazınızda şifrelenir. Kendi diskinize de böyle kaydedilir, bize de böyle ulaşır.
3. Şifreli notu alır ve saklarız. Yukarıdaki görsel bunun nasıl göründüğüdür.
4. Aynı ifadeye sahip herhangi bir cihaz aynı anahtarı üretir ve notu açar.

## Anahtarınız kimde

Her seçenekte notlarınız cihazınızda şifrelenir. Aralarındaki fark, ifadenizin nerede durduğudur.

| Seçenek | İfadeniz nerede durur | Size ne kazandırır |
| --- | --- | --- |
| **Giriş, anahtar bizde** | Sunucumuzda, şifreli | Yeni bir cihaz yalnızca o hesapla girer |
| **Giriş, anahtar cihazınızda** | Sizde, başka hiçbir yerde | Google, Apple ya da GitHub ile girin, anahtar yine sizde kalsın |
| **Yalnızca ifade, giriş yok** | Sizde, başka hiçbir yerde | E-posta yok, ad yok, hesap yok |

Alttaki ikisinde, zorlansak bile bir notu okuyamayız. İlki bunu rahatlığa takas eder: ifadeniz bizim bir anahtarımızın altında sunucumuzda durur, böylece yeni bir cihaza hesabınızdan başka bir şey gerekmez. Sunucumuz bir gün ele geçirilirse o anahtar açığa çıkabilir.

Google, Apple veya GitHub ile mi giriş yaptınız? İlk ikisi arasında daha sonra **Ayarlar > Güvenlik > Kurtarma ifadeniz** altından geçiş yapabilirsiniz. Yalnızca ifadeyle açılmış bir hesapta ifade her zaman sizde kalır.

> [!warning] İfadenin kendi kopyanızı saklayın
> İfadeniz notlarınızı açar. Kaybederseniz kimse geri getiremez, biz de dahil. <span style="color: #e03131">Bugün kâğıda yazın.</span>

## Kendiniz kontrol edin

[GitHub'da ayrıntılı doğrulama talimatları](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Tarayıcınızın ağ sekmesini açın, sonra bir notu düzenleyin. Bize ne ulaştığına bakın: okunamayan bir metin bloğu.
- [ ] Şifreleme kodunu okuyun. Herkese açık ve tek oturuşta bitirecek kadar kısa.

| Ne | Nerede |
| --- | --- |
| Şifrelemenin kendisi | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| Sunucumuzun aldıkları | [VERIFY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md#tier-1-one-minute-no-tools) |
| Bir saldırganın yapabildikleri ve yapamadıkları | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Bir açığı nasıl bildirirsiniz | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Tek bir kilit hepsini kapsar
> Notlar, günlük kayıtları, yer imleri, kasa öğeleri ve dosya ekleri aynı şekilde şifrelenir. [[Taşınma]] her birini nasıl getireceğinizi gösterir.
