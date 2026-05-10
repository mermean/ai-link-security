import pandas as pd
import numpy as np
import re
import math
import joblib

from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

print("Dataset yükleniyor...")

df = pd.read_csv("dataset/malicious_phish.csv")

# Etiketler
df['type'] = df['type'].apply(
    lambda x: 0 if x == 'benign' else 1
)

# Şüpheli TLD
SUSPICIOUS_TLDS = [
    ".xyz",
    ".tk",
    ".ru",
    ".cn",
    ".top",
    ".gq"
]

# Entropy hesaplama
def entropy(text):

    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]

    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    return entropy

# Feature extraction
def extract_features(url):

    parsed = urlparse(url)

    domain = parsed.netloc

    features = []

    # URL length
    features.append(len(url))

    # Domain length
    features.append(len(domain))

    # Dot count
    features.append(url.count('.'))

    # Hyphen count
    features.append(url.count('-'))

    # Slash count
    features.append(url.count('/'))

    # HTTPS
    features.append(1 if parsed.scheme == "https" else 0)

    # Digits
    features.append(sum(c.isdigit() for c in url))

    # Special chars
    features.append(len(re.findall(r'[?=&@%]', url)))

    # Subdomain count
    features.append(domain.count('.'))

    # Entropy
    features.append(entropy(url))

    # IP address usage
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    features.append(
        1 if re.match(ip_pattern, domain) else 0
    )

    # Suspicious TLD
    suspicious_tld = 0

    for tld in SUSPICIOUS_TLDS:

        if domain.endswith(tld):
            suspicious_tld = 1

    features.append(suspicious_tld)

    # Suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "free",
        "bonus",
        "gift",
        "paypal",
        "crypto",
        "wallet"
    ]

    keyword_score = 0

    lower_url = url.lower()

    for word in suspicious_words:

        if word in lower_url:
            keyword_score += 1

    features.append(keyword_score)

    return features

print("Feature extraction...")

X = np.array([
    extract_features(url)
    for url in df['url']
])

y = df['type']

print("Train/Test split...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

print("AI training...")

model = RandomForestClassifier(
    n_estimators=400,
    max_depth=25,
    random_state=42
)

model.fit(X_train, y_train)

print("Testing...")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print(f"Accuracy: %{accuracy * 100:.2f}")

joblib.dump(model, "model/ultimate_model.pkl")

print("Ultimate AI model saved.")