import joblib

# Load trained model
rf_model = joblib.load("dns_rf_model.pkl")

LABELS = {
    0: "Benign",
    1: "DGA",
    2: "Fast-Flux",
    3: "Suspicious"
}

import pandas as pd

FEATURE_NAMES = [
    "domain_length",
    "entropy",
    "digit_ratio",
    "subdomain_depth",
    "ttl",
    "unique_ip_count",
    "query_rate"
]

def ai_predict(features):
    df = pd.DataFrame([features], columns=FEATURE_NAMES)
    pred = rf_model.predict(df)[0]
    confidence = max(rf_model.predict_proba(df)[0])
    return LABELS[pred], round(confidence, 2)

