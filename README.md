#  AI Link Security

Modern AI destekli phishing ve zararlı link analiz sistemi.

## Özellikler

* AI Risk Analizi
* VirusTotal API Entegrasyonu
* Google Safe Browsing
* SSL Kontrolü
* Domain Yaşı Kontrolü
* Şüpheli Kelime Tespiti
* Şüpheli TLD Analizi
* IP Address Detection
* @ Attack Detection
* Modern Responsive UI
* Animated Rain Background

---

#  Gereksinimler

* Python 3.10+
* pip

---

# Kurulum

##  Projeyi Klonla

```bash
git clone https://github.com/mermean/ai-link-security.git
```

---

##  Backend Klasörüne Gir

```bash
cd ai-link-security/backend
```

---

##  Gerekli Paketleri Kur

```bash
pip install -r requirements.txt
```

---

##  .env Dosyası Oluştur

backend klasörüne `.env` oluştur:

```env
VIRUSTOTAL_API_KEY=YOUR_API_KEY
GOOGLE_SAFE_BROWSING_API_KEY=YOUR_API_KEY
```

---

##  Backend’i Başlat

```bash
python app.py
```

Backend:

```text
http://127.0.0.1:5000
```

adresinde çalışacaktır.

---

#  Frontend Başlatma

Yeni terminal aç:

```bash
cd ai-link-security/frontend
```

Sonra:

```bash
python -m http.server 5500
```

Tarayıcıdan aç:

```text
http://localhost:5500
```

---

#  Test Linkleri

## Safe

```text
https://www.blender.org
```

## Suspicious

```text
http://secure-login-check.net
```

## Dangerous

```text
http://paypal-account-security-verification-bonus.xyz
```

---

# Uyarı

API keylerinizi paylaşmayın.


---

#  Developer

Barış Yıldırım

GitHub:
https://github.com/mermean
