from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import joblib
import re
import whois
import socket
import ssl
import math
import requests
import os


from dotenv import load_dotenv
from urllib.parse import urlparse
from datetime import datetime



VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

GOOGLE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

WHOIS_API_KEY = os.getenv("VT_API_KEY")

# ==========================================
# FLASK
# ==========================================

load_dotenv()
app = Flask(__name__)
CORS(app)

# ==========================================
# AI MODEL
# ==========================================

model = joblib.load("../model/ultimate_model.pkl")

# ==========================================
# SAFE DOMAINS
# ==========================================

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
    "amazon.com",
    "netflix.com",
    "reddit.com",
    "kaggle.com",
    "wikipedia.org",
    "python.org",
    "mozilla.org",
    "docker.com",
    "ubuntu.com"
]

# ==========================================
# TRUSTED KEYWORDS
# ==========================================

TRUSTED_KEYWORDS = [
    "google",
    "microsoft",
    "nasa",
    "mozilla",
    "cloudflare",
    "github",
    "openai",
    "stackoverflow",
    "amazon",
    "reddit",
    "wikipedia",
    "python",
    "docker",
    "ubuntu",
    "linux",
    "intel",
    "amd",
    "oracle",
    "adobe",
    "spotify",
    "steam"
]

# ==========================================
# SUSPICIOUS KEYWORDS
# ==========================================

SUSPICIOUS_KEYWORDS = [
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
    "wallet",
    "signin",
    "confirm",
    "account"
]

# ==========================================
# SUSPICIOUS TLDS
# ==========================================

SUSPICIOUS_TLDS = [
    ".xyz",
    ".tk",
    ".ru",
    ".cn",
    ".top",
    ".gq"
]

# ==========================================
# ENTROPY
# ==========================================

def entropy(text):

    prob = [
        float(text.count(c)) / len(text)
        for c in dict.fromkeys(list(text))
    ]

    entropy = - sum([
        p * math.log(p) / math.log(2.0)
        for p in prob
    ])

    return entropy

# ==========================================
# FEATURE EXTRACTION
# ==========================================

def extract_features(url):

    parsed = urlparse(url)

    domain = parsed.netloc

    features = []

    features.append(len(url))

    features.append(len(domain))

    features.append(url.count('.'))

    features.append(url.count('-'))

    features.append(url.count('/'))

    features.append(
        1 if parsed.scheme == "https" else 0
    )

    features.append(
        sum(c.isdigit() for c in url)
    )

    features.append(
        len(re.findall(r'[?=&@%]', url))
    )

    features.append(
        domain.count('.')
    )

    features.append(
        entropy(url)
    )

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    features.append(
        1 if re.match(ip_pattern, domain) else 0
    )

    suspicious_tld = 0

    for tld in SUSPICIOUS_TLDS:

        if domain.endswith(tld):
            suspicious_tld = 1

    features.append(suspicious_tld)

    keyword_score = 0

    lower_url = url.lower()

    for word in SUSPICIOUS_KEYWORDS:

        if word in lower_url:
            keyword_score += 1

    features.append(keyword_score)

    return features

# ==========================================
# SSL CHECK
# ==========================================

def check_ssl(domain):

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ):

                return True

    except:

        return False



# ==========================================
# IP CHECK
# ==========================================

def is_ip_address(domain):

    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    return re.match(pattern, domain)

# ==========================================
# ANALYZE API
# ==========================================


def check_google_safe_browsing(url):

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

    payload = {

        "client": {
            "clientId": "ai-link-security",
            "clientVersion": "1.0"
        },

        "threatInfo": {

            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],

            "platformTypes": [
                "ANY_PLATFORM"
            ],

            "threatEntryTypes": [
                "URL"
            ],

            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:

        response = requests.post(
            endpoint,
            json=payload
        )

        data = response.json()

        if "matches" in data:

            return True

        return False

    except:

        return False



def check_virustotal(url):

    endpoint = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        response = requests.post(

            endpoint,

            headers=headers,

            data={"url": url}

        )

        data = response.json()

        analysis_id = data["data"]["id"]

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        time.sleep(3)

        result = requests.get(
            analysis_url,
            headers=headers
        )

        result_data = result.json()

        stats = result_data["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)

        suspicious = stats.get("suspicious", 0)

        return {
            "malicious": malicious,
            "suspicious": suspicious
        }

    except:

        return {
            "malicious": 0,
            "suspicious": 0
        }




@app.route('/analyze', methods=['POST'])

def analyze():

    data = request.json

    url = data.get("url")

    if not url:

        return jsonify({
            "error": "URL gerekli"
        }), 400

    # HTTPS ekle
    if not url.startswith("http://") and not url.startswith("https://"):

        url = "https://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.replace("www.", "")

    # ==========================================
    # SAFE DOMAIN FAST RETURN
    # ==========================================

    if domain in SAFE_DOMAINS:

        return jsonify({

            "url": url,
            "status": "safe",
            "risk_score": 0,
            "prediction": "safe",
            "domain": domain,
            "ssl_valid": True,
            "domain_age_days": "Trusted",
            "reasons": [
                "Güvenilir domain listesinde bulundu"
            ]

        })

    # ==========================================
    # INITIAL
    # ==========================================

    risk_score = 0
    age = None
    reasons = []

    # ==========================================
    # AI ANALYSIS
    # ==========================================

    features = extract_features(url)

    prediction = int(
        model.predict([features])[0]
    )

    prediction_label = "low"

    if prediction == 1:

        prediction_label = "low"

        for keyword in TRUSTED_KEYWORDS:

            if domain == keyword + ".com" \
            or domain == keyword + ".org":

                prediction_label = "low"




    # ==========================================
    # SUSPICIOUS KEYWORDS
    # ==========================================

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url.lower():

            risk_score += 20

            reasons.append(
                f"Şüpheli kelime bulundu: {keyword}"
            )

    





    # ==========================================
    # AI SCORING
    # ==========================================

    trusted = False

    for keyword in TRUSTED_KEYWORDS:

        if domain == keyword + ".com" \
        or domain == keyword + ".org" \
        or domain.endswith("." + keyword + ".com") \
        or domain.endswith("." + keyword + ".org"):

            trusted = True


    if prediction == 1:

        risk_score += 5

    
    # ==========================================
    # HTTPS CHECK
    # ==========================================

    if parsed.scheme != "https":

        risk_score += 20

        reasons.append(
            "HTTPS kullanılmıyor"
        )

    # ==========================================
    # SSL CHECK
    # ==========================================

    ssl_valid = check_ssl(domain)

    if not ssl_valid:

        risk_score += 25

        reasons.append(
            "SSL sertifikası doğrulanamadı"
        )


    # ==========================================
    # @ ATTACK DETECTION
    # ==========================================

    if '@' in url:

        risk_score += 50

        reasons.append(
            "@ karakteri içeriyor"
        )



    # ==========================================
    # GOOGLE SAFE BROWSING
    # ==========================================

    google_flagged = check_google_safe_browsing(url)

    if google_flagged:

        risk_score += 100

        reasons.append(
            "Google Safe Browsing sistemi bu URL'yi tehlikeli işaretledi"
        )

    # ==========================================
    # VIRUSTOTAL
    # ==========================================

    vt_result = check_virustotal(url)

    vt_malicious = vt_result["malicious"]

    vt_suspicious = vt_result["suspicious"]

    if vt_malicious > 0:

        risk_score += 100

        reasons.append(
            f"VirusTotal {vt_malicious} antivirüs motoru tarafından zararlı işaretledi"
        )

    elif vt_suspicious > 0:

        risk_score += 40

        reasons.append(
            f"VirusTotal {vt_suspicious} motor tarafından şüpheli bulundu"
        )

    # ==========================================
    # DOMAIN AGE
    # ==========================================

    def get_domain_age(domain):

        try:

            info = whois.whois(domain)

            creation_date = info.creation_date

            if isinstance(creation_date, list):

                creation_date = creation_date[0]

            if not creation_date:

                return None

            now = datetime.now(creation_date.tzinfo)

            age_days = (
                now - creation_date
            ).days

            return age_days

        except Exception as e:

            print("WHOIS ERROR:", e)

            return None

    age = get_domain_age(domain)

    print("DOMAIN AGE:", age)

    # ==========================================
    # IP ADDRESS CHECK
    # ==========================================

    if is_ip_address(domain):

        risk_score += 40

        reasons.append(
            "IP adresi kullanılıyor"
        )

        # ==========================================
        # SUSPICIOUS KEYWORDS
        # ==========================================

        lower_url = url.lower()

        suspicious_count = 0

        for word in SUSPICIOUS_KEYWORDS:

            if word in lower_url:
                suspicious_count += 1

        if suspicious_count > 0:

            risk_score += suspicious_count * 8

            reasons.append(
                "Şüpheli kelimeler bulundu"
            )

        for tld in SUSPICIOUS_TLDS:

            if domain.endswith(tld):

                risk_score += 25

                reasons.append(
                    "Şüpheli domain uzantısı kullanılıyor"
                )


        # ==========================================
        # URL LENGTH
        # ==========================================

        if len(url) > 120:

            risk_score += 15

            reasons.append(
                "URL çok uzun"
            )

        # ==========================================
        # @ CHARACTER
        # ==========================================

        if '@' in url:

            risk_score += 50

            reasons.append(
                "@ karakteri içeriyor"
            )

    if risk_score >= 70:

        prediction_label = "high"

    elif risk_score >= 40:

        prediction_label = "medium"

    else:

        prediction_label = "low"

    # ==========================================
    # FINAL STATUS
    # ==========================================

    status = "safe"

    if google_flagged or vt_malicious > 0:

        status = "dangerous"

    elif risk_score >= 50:

        status = "dangerous"

    elif risk_score >= 40:

        status = "suspicious"

    # ==========================================
    # RESPONSE
    # ==========================================

    response_data = {

        "url": url,
        "status": status,
        "risk_score": risk_score,
        "prediction": prediction_label,
        "domain": domain,
        "ssl_valid": ssl_valid,
        "google_flagged": google_flagged,
        "virustotal_malicious": vt_malicious,
        "virustotal_suspicious": vt_suspicious,
        "domain_age_days": age,
        "reasons": reasons

    }

    return jsonify(response_data)

# ==========================================
# START SERVER
# ==========================================

if __name__ == '__main__':

    app.run(debug=False)