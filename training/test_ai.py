import joblib

# Model yükle
model = joblib.load("model/url_model.pkl")

# Vectorizer yükle
vectorizer = joblib.load("model/vectorizer.pkl")

# Kullanıcıdan link al
url = input("Link gir: ")

# AI için hazırla
url_vector = vectorizer.transform([url])

# Tahmin yap
prediction = model.predict(url_vector)

print("Sonuç:", prediction[0])