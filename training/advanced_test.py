import joblib
import re

from urllib.parse import urlparse

# Güvenilir domainler
SAFE_DOMAINS = [
    "google.com",
    "youtube.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "openai.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "linkedin.com",
    "sahibinden.com",
    "gemini.com",
    "chatgpt.com"
]

# Model yükle
model = joblib.load("model/advanced_model.pkl")

# Özellik çıkarma
def extract_features(url):

    parsed = urlparse(url)

    features = []

    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('/'))
    features.append(1 if parsed.scheme == "https" else 0)
    features.append(len(parsed.netloc))
    features.append(1 if re.search(r'\d', url) else 0)
    features.append(1 if '@' in url else 0)

    return features

# Link al
url = input("Link gir: ")

# Domain al
domain = urlparse(url).netloc.replace("www.", "")

# Whitelist kontrolü
if domain in SAFE_DOMAINS:

    print("Sonuç: safe")

else:

    features = extract_features(url)

    prediction = model.predict([features])

    print("Sonuç:", prediction[0])