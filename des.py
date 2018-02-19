#kaynak: http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm

def des(metin, anahtar):

#altiliyi ikiliye donustur
altiki= lambda x: "".join(["{:04b}".format(int(i,16)) for i in x])

#bir metni listeyle karmak için fonksiyon
kar = lambda m,l: "".join(map(lambda x: m[x-1], l))

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
  return anahtarlik
      

