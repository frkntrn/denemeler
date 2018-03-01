### Makale İncelemesi: [DES Şifresi İçin Doğrusal Kriptanaliz Yöntemi, Mitsuru Matsui](https://www.cs.bgu.ac.il/~beimel/Courses/crypto2001/Matsui.pdf)
---
**Yöntemin özeti:**
- **S-box'taki doğrusallık:** DES şifresindeki tek doğrusal olmayan, yani güvenliği sağlayan bölüm S-box bölümüdür. Bu bölümdeki zafiyeti kullanarak, doğruluğu rastgeleden farklı bir doğrusal denklem oluşturabiliriz.
- **DES şifresindeki doğrusallık:** Elde edilen denklemle, açık ve şifreli metin çiftlerini ve algoritma I'i kullanarak anahtarın 1 bitini yüksek olasılıkla bulabiliriz.
- **Bilinen açık metinle saldırı (KPA):** Elde edilen denklemden, içinde alt anahtarın olduğu yeni bir denklem oluşturup, açık ve şifreli metin çiftlerini ve algoritma II'yi kullanarak, alt anahtarın belli bölümünü yüksek olasılıkla tespit edip, anahtarın geri kalanını kaba kuvvetle bulabiliriz.
- **Sadece şifreli metinle saldırı (COA):** Elimizde açık metinler olmasa bile, bu metinlerin rastgele olmamasından yararlanıp, şifreli metinler ve algoritma II'yi kullanarak anahtarı yüksek olasılıkla bulabiliriz.
---
**16 Turluk DES Şifresi**</br>

![des](https://github.com/frkntrn/kriptanaliz/blob/master/ss/des.png)</br>

**Uygulaması**</br>

```python
#altiliyi ikiliye donustur
altiki= lambda x: "".join(["{:04b}".format(int(i,16)) for i in x])
#ikiliden altiliya donustur
ikialti = lambda b: "".join(["%X"%int(b[i:i+4],2) for i in range(0,len(b),4)])

#bir metni listeyle karmak icin fonksiyon
kar = lambda m,l: "".join(map(lambda x: m[x-1], l))

#xor fonksiyonu
xor = lambda x,y: "".join([str(int(x[i])^int(y[i])) for i in range(len(x))])

#6 bitten 4 bite kucultmek ve degistirmek icin liste (S-box)
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]], [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]], [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]], [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]], [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]], [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]], [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]], [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
#metni kucultmek icin fonksiyon
mengene = lambda m: "".join(["{:04b}".format(sbox[i][int(a[0]+a[-1],2)][int(a[1:-1],2)]) for i,a in enumerate([m[i:i+6] for i in range(0,len(m),6)])])

#sozde rastgele fonksiyon
def f(metin, anahtar):
  #genisletme listesi
  g = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
  #metni 32'den 48 bite genislet
  genis = kar(metin, g)
  #xorlanmis metin
  xorlanmis = xor(genis, anahtar)
  #48 bitten 32'i bite sikistir
  sikisik = mengene(xorlanmis)
  #sikistirdiktan sonra karma listesi
  fk = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
  #sikisik metni kar
  return kar(sikisik,fk)
  
#ana anahtardan butun anahtarlari uret
def cilingir(anahtar):
  #1. anahtar karma listesi
  ak1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
  #anahtari karip 0. anahtari olustur
  a0 = kar(anahtar, ak1)
  #anahtarlari olusturmak icin kaydirma miktarlarini iceren liste
  kizak = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
  #0. anahtarin iki yarisini olustur
  sol_ = a0[:len(a0)/2]; sag_ = a0[len(a0)/2:]
  #anahtarligi olustur
  anahtarlik = []; sol = sol_; sag = sag_
  for i in kizak:
    sol = sol[i:] + sol[:i]
    sag = sag[i:] + sag[:i]
    anahtarlik += [sol+sag]
  #2. anahtar karma listesi
  ak2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
  #anahtarlari bu listeden gecirip son hallerini olustur
  return map(lambda x: kar(x,ak2),anahtarlik)
      
def sifrele(metin, anahtar):
  #1. metin karma listesi
  mk1 = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
  m = kar(altiki(metin), mk1)
  #anahtarligi olustur
  anahtarlik = cilingir(altiki(anahtar))
  #baslangic sag ve sol degerlerini olustur
  sol = m[:len(m)/2]; sag = m[len(m)/2:]
  #16 asamadan gecirip sifrele
  for anahtar in anahtarlik: sol, sag = sag, xor(sol, f(sag, anahtar))
  #2. metin karma listesi
  mk2 = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
  #bu listeyle kar
  return ikialti(kar(sag+sol, mk2)).
```
**Not:** Kodlarda hızdan çok anlaşılabilirlik ön plandadır.

---
**S-box'taki Doğrusallık**</br>

![sboxtaki_doğrusallık](https://github.com/frkntrn/kriptanaliz/blob/master/ss/sboxtaki_dogrusallik.png)

Bu tanımla Sbox'a giren giren 6 bit ve çıkan 4 bit arasında bir korelasyon bulunmaya çalışılmış. 
- α ve β maskeleriyle, giren ve çıkan (a. S-box'tan geçirilmiş girdi) parçalardan istenilen bitler seçilmiş. 
- Parçalar xor'dan  geçirildikten sonra kıyaslanmış. Xor 2'lik tabanda toplama olduğundan doğrusal ve etkisiz elemanı 0'dır.
- Bu sayı, 64/2 = 32'den ne kadar uzaksa, rastgelelikten de o kadar uzak olduğunu ve, giren ve çıkan bitler arasında korelasyon olduğunu söyleyebiliriz

```python
#Bir parçanın bitlerini xor yap
kendine_xor = lambda p: reduce(lambda x,y:x^y, p)

#6 bitlik parcayi alip a. sboxa sok
sboxla = lambda p,a: "{:04b}".format(sbox[a-1][int(p[0]+p[-1],2)][int(p[1:-1],2)])

#maskele
maskele = lambda x,y: [int(x[i]) and int(y[i]) for i in range(len(x))]

#a. sbox, alfa, beta için skor bul
skor = lambda a,alfa,beta: sum([kendine_xor(maskele(x,"{:06b}".format(alfa))) == kendine_xor(maskele(sboxla(x,a),"{:04b}".format(beta))) for x in ["{:06b}".format(i) for i in range(64)]])

#skorların listesi
skor_listesi = [[a, alfa, beta, skor(a,alfa,beta)] for a in range(1,9) for alfa in range(1,64) for beta in range(1,16)]

#32'den en buyuk sapma yapani bul
print(max(skor_listesi,key = lambda x: abs(32-x[-1])))
```
**[5, 16, 15, 12]** </br>
sonucunu elde ettik. Yani en büyük sapmayı sağlayan değerler 12/64=0.19 olasılıkla:</br></br>
![](https://latex.codecogs.com/gif.latex?N_{5}(16,15)=12) </br>
Şimdi bu bağıntıyı kullanarak F fonksiyonuna giren ve çıkan metni, ve alt anahtarı içeren bir denklem yazabiliriz. 

```python
#ikilik tabanda 16=(010000), 15=(1111)
#S-box'a giren metin 48 bit ve bağıntı 5. S-box'ta olduğundan, giren metninde etkilenen bit 4*6+2 = 26. 
#S-box'tan giren metin 32 bit ve bağıntı 5. S-box'ta olduğundan, çıkan metninde etkilenen bitler 4*4+1 - 4*4+4 arası, yani 17-20 arası bitler
yukari = 26; asagi = range(17,21)

#Ama Matsui DES notasyonun aksine işlemci bit sırasını kullanmış, bizimde bit sırasını ters çevirmemiz lazım. https://crypto.stackexchange.com/questions/25305/matsuis-linear-attack-on-des-p-box
#Giren metin, anahtar ve X'in genisletilmeden önceki halinin xor'u oldugundan, anahtarın etkilenen bitini bulmuş olduk, şimdi X'i bulalım
K = 48 - yukari
g = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
X = 32-g[yukari-1]

#Çıkan metin bir karma işleminden geçmeli
fk = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
F = sorted(map(lambda i: 31-fk.index(i) , asagi))

print("Etkilenen bitler: X:" + str(X) + " F:" + ",".join(map(str,F)) + " K:" + str(K))
```
**Etkilenen bitler: X:15 F:7,18,24,29 K:22**</br>
Böylece aşağıdaki denklem 0.19 olasılıkla doğru olur.</br></br>
![](https://latex.codecogs.com/gif.latex?X[15]\oplus&space;F(X,K)[7,18,24,29]\oplus&space;K[22]=0)

---
**DES Şifresindeki Doğrusallık**</br></br>
3 turluk DES için bir denklem kurmaya çalışalım. Yukarıda elde ettiğimizde denklemden faydalabiliriz.</br>

![](https://latex.codecogs.com/gif.latex?X_{2}\oplus&space;P_{H}&space;=&space;F(X_{1},K_{1}),X_{2}\oplus&space;C_{H}&space;=&space;F(X_{3},K_{3}))</br></br>
doğru olduğundan aşağıdaki denklemlere ulaşabiliriz.</br></br>

![](https://latex.codecogs.com/gif.latex?X_{2}[7,18,24,29]\oplus&space;P_{H}[7,18,24,29]\oplus&space;P_{L}[15]\oplus&space;K_{1}[22]=0)</br></br>

![](https://latex.codecogs.com/gif.latex?X_{2}[7,18,24,29]\oplus&space;C_{H}[7,18,24,29]\oplus&space;C_{L}[15]\oplus&space;K_{3}[22]=0)</br></br>

İki denkleminde gerçekleşme olasılığı p = 0.19. Bu iki denklemden de istediğimiz sonuca varabiliriz.</br></br>

![](https://latex.codecogs.com/gif.latex?P_{H}[7,18,24,29]\oplus&space;C_{H}[7,18,24,29]\oplus&space;P_{L}[15]\oplus&space;C_{L}[15]\oplus&space;K_{1}[22]&space;\oplus&space;K_{3}[22]=0)</br></br>

Bu denklem, önceki iki denklemin ikisi de 0 veya 1 ise 0 olur. Yani olasılığı </br></br>

![](https://latex.codecogs.com/gif.latex?p^{2}+(1-p)^{2})</br></br>

sinden 0.7 çıkar. Şimdi açık ve şifreli metinleri topladıkça, bu sapmayı sömürecek bir algoritma lazım.</br></br>

![](https://github.com/frkntrn/kriptanaliz/blob/master/ss/algoritma1.png)</br></br>

Bu algoritmanın başarı oranı N ve |p-1/2| arttıkça artıcak. Bu algoritmanın başarı oranını hesaplayabiliriz.</br></br>

![](https://github.com/frkntrn/kriptanaliz/blob/master/ss/basari_orani1.png)</br></br>

p > 1/2 ve p < 1/2 durumları simetrik olduğundan p > 1/2 olsun. Açık metinler rastgele olduğundan, T rastgele değişkeninin dağılımının Merkezi Limit Theoreminden dolayı normal olduğunu söyleyebiliriz. T'nin beklenen değerini ve standart sapmasını hesaplayabiliriz.

![](https://latex.codecogs.com/gif.latex?\mu&space;=Np,\&space;p=\frac{1}{2}&plus;\varepsilon,&space;\&space;\sigma^{2}=Np(1-p)\cong&space;\frac{N}{4})

Açık metinlerin beklenen değeri N/2 olacak, T'nin bu değerden büyük olmasını istiyoruz. Φ standart normal CDF olsun. O zaman olasılık fonksiyonu aşağıdaki gibi olur.

![](https://latex.codecogs.com/gif.latex?\Phi&space;(\frac{\frac{N}{2}-Np}{\sqrt{\frac{N}{4}}})&space;=&space;\Phi(-2\sqrt{N}|p-\frac{1}{2}|))</br></br>

Şimdi 5 turluk DES'e bakalım.</br></br>

![](https://latex.codecogs.com/gif.latex?NS_{1}(27,4)=22)</br></br>

Bu eşitliği ve öncekini kullanarak aşağıdaki denkleme ulaşabiliriz.</br></br>

![](https://latex.codecogs.com/gif.latex?P_{H}[15]\oplus&space;P_{L}[7,18,24,27,28,29,30,31]\oplus&space;C_{H}[15]\oplus&space;C_{L}[7,18,24,27,28,29,30,31]=&space;K_{1}[42,43,45,46]\oplus&space;K_{2}[22]\oplus&space;K_{4}[22]\oplus&space;K_{5}[42,43,45,46])</br></br>

Denklemin olasığını hesaplamak için pratik bir yöntem:</br></br>

![](https://github.com/frkntrn/kriptanaliz/blob/master/ss/pilingup.png)

Tümevarımla kolayca kanıtlanabilir. Bu yöntemi olasığı bulmak için kullanabiriz.</br></br>

![](https://latex.codecogs.com/gif.latex?\frac{1}{2}+2^{3}(\frac{1}{2}-\frac{22}{64})^{2}(\frac{1}{2}-\frac{12}{64})^{2}=0.519)</br></br>

![](https://latex.codecogs.com/gif.latex?\left&space;|&space;0.519-\frac{1}{2}&space;\right&space;|^{-2}=2800)</br></br>

2800 açık ve şifreli metinle %97.7 başarı oranına ulaşılabilir.

---
**Bilinen açık metinle saldırı (KPA)**</br></br>

Şimdi alt anahtarı dahil edip, daha etkili bir denklem oluşturmaya çalışalım. İlk örnek 8 turluk DES olacak. <br><br>

![](https://latex.codecogs.com/gif.latex?C_{H}\oplus&space;F(C_{L},K_{8})=X_{7})<br><br>

Olduğundan, bu eşitliği denkleme uyguladığımızda son basamağın bir bölümünü deşifre etmiş oluruz. Böylece denklemin doğruluğunun doğru alt anahtar için daha çok olmasını bekleriz.<br><br>

![](https://github.com/frkntrn/kriptanaliz/blob/master/ss/bilinen8.png)</br>

Bu denklem, anahtarın 6 bitini etkilediği, bu 6 bit için 64 sayaç gerekir. 1. tura da aynı işlemi uygulayabileceğimizden
toplamda 2*(6+1) = 14 biti elde edebiliriz ve geri kalan 42 biti kaba kuvvetle bulabiliriz. Açık ve şifreli metin çiftlerini topladıkça olasılığı artıracak algoritma bulmamız lazım.</br>

![](https://github.com/frkntrn/kriptanaliz/blob/master/ss/algoritma2.png)</br>

Algoritma, en büyük sapmanın, doğru anahtardan geleceğini söylüyor. Algoritmanın başarı oranına bakalım.

![](https://github.com/frkntrn/kriptanaliz/blob/master/ss/basari_orani2.png)</br>

Yukarıdaki iki denklemi xorladığımızda doğru olmayan bir anahtar için gereken denklemi buluruz. Doğru anahtarın denklemi sağlama olasığı p ve denklem 14'ün gerçekleşme olasılığı q olduğu için, doğru olmayan bir anahtarın denklemi sağlama olasılığı.</br></br>

![](https://latex.codecogs.com/gif.latex?a=pq&plus;(1-p)(1-q)=2pq-p-q&plus;1)

T doğru olan, t doğru olmayan herhangi bir anahtarın rastgele değişkeni olsun. O zaman,<br><br>

![](https://latex.codecogs.com/gif.latex?E(T)=np,E(t)=na,Var(T)\cong&space;Var(t)\cong&space;\frac{N}{4})<br><br>

olur. Algoritma 2'nin başarı oranını hesaplayabiliriz. Yine p > 1/2 olsun.</br></br>

![](https://latex.codecogs.com/gif.latex?T-\frac{N}{2}&space;>\left&space;|&space;t-\frac{N}{2}&space;\right&space;|)</br>

![](https://latex.codecogs.com/gif.latex?T>t>N-T)</br>

Şimdi değişkenleri standartlaştırmalıyız. Yeni değişkenlerin adı S ve s olsun.</br></br>

![](https://latex.codecogs.com/gif.latex?\frac{T-np}{\sqrt{\frac{N}{4}}}+\frac{Np-Na}{\sqrt{\frac{N}{4}}}>\frac{t-Na}{\sqrt{\frac{N}{4}}}>-\frac{T-np}{\sqrt{\frac{N}{4}}}-\frac{N-Np-Na}{\sqrt{\frac{N}{4}}})</br>

![](https://latex.codecogs.com/gif.latex?S+2\sqrt{N}(p-a)>s>-S-2\sqrt{N}(1-p-a))</br>

![](https://latex.codecogs.com/gif.latex?S+4\sqrt{N}(p-\frac{1}{2})(1-q)>s>-S-4\sqrt{N}(p-\frac{1}{2})q)</br>

![](https://github.com/frkntrn/kriptanaliz/blob/master/ss/bilinen16.png)</br>























  


  
  
  
  
  
  
  
  
