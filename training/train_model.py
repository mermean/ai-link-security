import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import joblib

print("Dataset yükleniyor...")

# CSV dosyasını oku
df = pd.read_csv("dataset/malicious_phish.csv")

print(df.head())

# URL sütunu
X = df['url']

# Etiket sütunu
y = df['type']

print("Veriler hazırlanıyor...")

# URL'leri sayısal veriye çevir
vectorizer = TfidfVectorizer()

X_vectorized = vectorizer.fit_transform(X)

print("Eğitim başlıyor...")

# Eğitim ve test verisi ayır
X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized,
    y,
    test_size=0.2,
    random_state=42
)

# AI modeli oluştur
model = LogisticRegression(max_iter=1000)

# Eğit
model.fit(X_train, y_train)

print("Test yapılıyor...")

# Tahmin
predictions = model.predict(X_test)

# Doğruluk oranı
accuracy = accuracy_score(y_test, predictions)

print(f"Doğruluk oranı: %{accuracy * 100:.2f}")

# Modeli kaydet
joblib.dump(model, "model/url_model.pkl")

# Vectorizer kaydet
joblib.dump(vectorizer, "model/vectorizer.pkl")

print("Model başarıyla kaydedildi.")