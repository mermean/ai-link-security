import pandas as pd
import numpy as np
import re
import joblib

from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

print("Dataset yükleniyor...")

df = pd.read_csv("dataset/malicious_phish.csv")

# Özellik çıkarma
def extract_features(url):

    parsed = urlparse(url)

    features = []

    # URL uzunluğu
    features.append(len(url))

    # Nokta sayısı
    features.append(url.count('.'))

    # Tire sayısı
    features.append(url.count('-'))

    # Slash sayısı
    features.append(url.count('/'))

    # HTTPS var mı
    features.append(1 if parsed.scheme == "https" else 0)

    # Domain uzunluğu
    features.append(len(parsed.netloc))

    # Sayı içeriyor mu
    features.append(1 if re.search(r'\d', url) else 0)

    # @ işareti var mı
    features.append(1 if '@' in url else 0)

    return features

print("Özellikler çıkarılıyor...")

X = np.array([extract_features(url) for url in df['url']])

y = df['type']

print("Veriler bölünüyor...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

print("AI eğitiliyor...")

model = RandomForestClassifier()

model.fit(X_train, y_train)

print("Test yapılıyor...")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print(f"Doğruluk: %{accuracy * 100:.2f}")

joblib.dump(model, "model/advanced_model.pkl")

print("Yeni model kaydedildi.")