### Makale İncelemesi: [DES Şifresi İçin Doğrusal Kriptanaliz Yöntemi, Mitsuru Matsui](https://www.cs.bgu.ac.il/~beimel/Courses/crypto2001/Matsui.pdf)
---
**Yöntemin özeti:**
- **S-box'taki doğrusallık:** DES şifresindeki tek doğrusal olmayan, yani güvenliği sağlayan bölüm S-box bölümüdür. Bu bölümdeki zafiyet kullanılarak, doğruluğu rastgeleden farklı bir doğrusal denklem oluşturulabilinir.
- **1 bitlik avantaj:** Elde edilen denklemle, açık ve şifreli metin çiftlerini ve algoritma I'i kullanarak anahtarın 1 bitini yüksek olasılıkla bulabiliriz.
- **Bilinen açık metinle saldırı (KPA):** Elde edilen denklemi edilen denklemden, içinde alt anahtarın olduğu yeni bir denklem oluşturup, açık ve şifreli metin çiftlerini ve algoritma II'yi kullanarak, alt anahtarın belli bölümünü yüksek olasılıkla tespit edip, anahtarın geri kalanını kaba kuvvetle bulabiliriz.
- **Sadece şifreli metinle saldırı (COA):** Elimizde açık metinler olmasa bile, bu metinlerin rastgele olmamasından yararlanıp, şifreli metinler ve algoritma II'yi kullanarak anahtarı bulabiliriz.
---
