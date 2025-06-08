# 🕵️‍♂️ Ariva İnstagram Osint (Advanced Tool) (Termux Edition)

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux-success)
![License](https://img.shields.io/badge/Legal%20Use%20Only-%F0%9F%9A%AB-red)

## 📌 Açıklama

Bu araç, **Instagram kullanıcıları** hakkında **kapsamlı OSINT (Açık Kaynak İstihbarat)** analizi yapar. `Termux` üzerinde çalışacak şekilde optimize edilmiştir. Gelişmiş analiz başlıkları şunlardır:

- Profil Bilgisi
- Ağ Analizi (takipçi, takip edilen, karşılıklı)
- Dijital Ayak İzi (e-posta, telefon, dış bağlantılar)
- Güvenlik ve Mahremiyet Analizi
- Davranışsal ve İçerik Analizi
- HTML ve JSON formatında rapor üretimi

> ❗ Araç yalnızca **yasal OSINT** araştırmaları içindir. Kötüye kullanımdan kullanıcı sorumludur.

---

## ⚙️ Kurulum

Termux ya da Linux tabanlı bir sistemde aşağıdaki adımları izleyin:

### 1. Python ve pip kurulumları

```bash
pkg update && pkg upgrade
pkg install python git -y
pip install --upgrade pip
pip install instaloader aiohttp beautifulsoup4 dnspython python-whois requests
```

klonlama:
```
git clone https://github.com/Sametxx1/IgOsintAriva.git
cd IgOsintAriva
```

Çalıştırma:

```bash
python arivaigosint.py kullanıcıadı
```
```
örnek kullanım: python arivaigosint.py nasa
```
YASAL ÇERÇEVE İÇİNDE KULLANINIZ!
