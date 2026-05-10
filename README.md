# AI Link Security

AI Link Security, Python ve JavaScript kullanılarak geliştirilmiş phishing ve zararlı bağlantı analiz sistemidir.

Sistem, bağlantıları farklı güvenlik kontrolleri ve AI tabanlı analiz yöntemleri ile değerlendirir.

---

# Özellikler

* AI tabanlı URL risk analizi
* VirusTotal API entegrasyonu
* Google Safe Browsing entegrasyonu
* SSL sertifika kontrolü
* Domain yaşı analizi
* Şüpheli kelime tespiti
* Şüpheli TLD analizi
* IP adresi ile oluşturulmuş URL tespiti
* @ attack detection
* Responsive modern arayüz
* Gerçek zamanlı risk skorlama sistemi

---

# Proje Yapısı

```text id="m4x8q1"
ai-link-security/
│
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── .env
│
├── frontend/
│   └── index.html
│
├── dataset/
│   └── malicious_phish.csv
│
├── training/
│   ├── advanced_test.py
│   ├── advanced_train.py
│   ├── test_ai.py
│   ├── train_model.py
│   └── ultimate_train.py
│
└── .gitignore
```

---

# Gereksinimler

* Python 3.10 veya üzeri
* Git
* İnternet bağlantısı

---

# Projeyi İndirme

## 1. Repoyu Klonlayın

```bash id="p7v2k5"
git clone https://github.com/mermean/ai-link-security.git
```

---

## 2. Proje Klasörüne Girin

```bash id="x1m9q4"
cd ai-link-security
```

---

# Backend Kurulumu

## 1. Backend Klasörüne Girin

```bash id="r5k8v1"
cd backend
```

---

## 2. Gerekli Paketleri Kurun

```bash id="u2x7m4"
python -m pip install -r requirements.txt
```

Eğer pip çalışmıyorsa:

```bash id="v8m1q2"
py -m pip install -r requirements.txt
```

---

# API Anahtarlarını Alma

## VirusTotal API Key

1. Aşağıdaki siteye girin:

```text id="q4m8x1"
https://www.virustotal.com
```

2. Hesap oluşturun veya giriş yapın.

3. Sağ üstte bulunan profil kısmına girin.

4. "API Key" bölümünden anahtarınızı kopyalayın.

---

## Google Safe Browsing API Key

### 1. Google Cloud Console'a Girin

```text id="r7v2k5"
https://console.cloud.google.com
```

---

### 2. Yeni Proje Oluşturun

* Select Project
* New Project

---

### 3. Safe Browsing API'yi Aktif Edin

Aşağıdaki bağlantıya gidin:

```text id="t1x9m4"
https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
```

"Enable" butonuna tıklayın.

---

### 4. API Key Oluşturun

* Sol menüden "Credentials"
* "Create Credentials"
* "API Key"

adımlarını takip edin.

---

## Whois API Key Alma

Domain yaşı analiz sisteminin çalışabilmesi için WhoisXMLAPI anahtarı gereklidir.

1. Siteye Girin
   
 ```text id="t1x9m4"
   https://whoisxmlapi.com
```

2. Hesap Oluşturun
Sign Up butonuna tıklayın.
Hesabınızı oluşturun.

3. E-posta doğrulamasını tamamlayın.

4. API Paneline Girin

Giriş yaptıktan sonra dashboard paneline girin.

5. API Key'i Kopyalayın

Dashboard içerisinde size özel API anahtarı görüntülenecektir.

Örnek:

at_XXXXXXXXXXXXXXXX



# .env Dosyası Oluşturma

Backend klasörü içerisinde `.env` dosyası oluşturun.

İçerisine kendi API anahtarlarınızı ekleyin:

```env id="w5m2q8"
VIRUSTOTAL_API_KEY=YOUR_VIRUSTOTAL_KEY
GOOGLE_SAFE_BROWSING_API_KEY=YOUR_GOOGLE_KEY
WHOIS_API_KEY=YOUR_WHOIS_API_KEY
```

---

# Dataset Kurulumu

Dataset dosyası güvenlik ve boyut nedeniyle repoya dahil edilmemiştir. Aşağıya bıraktığım link üzerinden indirilmesi gerekmektedir.

```  https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset?resource=download  ```

## 1. dataset Klasörü Oluşturun

Ana proje klasörü içerisinde:

```text id="k8v1m5"
dataset
```

isimli klasör oluşturun.

---

## 2. Dataset Dosyasını Ekleyin

Dataset dosyasını şu konuma yerleştirin:

```text id="m2x7q4"
dataset/malicious_phish.csv
```

---

# Model Eğitme

Model dosyası repoya dahil edilmemiştir.

Model oluşturmak için training klasörü içerisindeki scriptleri kullanabilirsiniz.

## Training Klasörüne Girin

```bash id="n7v4q2"
cd training
```

---

## Modeli Eğitin

```bash id="p4x8m1"
python ultimate_train.py
```

Model eğitimi tamamlandıktan sonra `.pkl` dosyası oluşacaktır.

---

# Backend'i Çalıştırma

Backend klasörü içerisinde:

```bash id="h6v2q9"
python app.py
```

Backend aşağıdaki adreste çalışacaktır:

```text id="b5x1m7"
http://127.0.0.1:5000
```

---

# Frontend'i Çalıştırma

Yeni terminal açın.

Frontend klasörüne girin:

```bash id="f3k8q2"
cd frontend
```

---

## Yerel Sunucuyu Başlatın

```bash id="c9m4x1"
python -m http.server 5500
```

---

## Tarayıcıdan Açın

```text id="1rfyn8"
http://localhost:5500
```

---

# Test Linkleri

## Güvenli Bağlantı

```text id="iiotwq"
https://www.blender.org
```

---

## Şüpheli Bağlantı

```text id="8az1qi"
http://secure-login-check.net
```

---

## Tehlikeli Bağlantı

```text id="31o7xl"
http://paypal-account-security-verification-bonus.xyz
```

---

# Önemli Notlar

* `.env` dosyasını GitHub'a yüklemeyin.
* API anahtarlarınızı gizli tutun.
* Büyük model dosyaları repoya dahil edilmemiştir.
* Dataset dosyası manuel olarak eklenmelidir.

---

# Kullanılan Teknolojiler

* Python
* Flask
* JavaScript
* HTML/CSS
* VirusTotal API
* Google Safe Browsing API
* Scikit-learn

---

# Geliştirici

Barış Yıldırım

GitHub:
https://github.com/mermean
