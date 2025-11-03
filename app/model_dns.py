import joblib
import numpy as np
from app.preprocess_dns_tunneling import preprocess_dns

scaler = joblib.load("models/dns_tunneling/scaler.pkl")
model_if = joblib.load("models/dns_tunneling/IF/if_dns_tunneling.pkl")
model_lof = joblib.load("models/dns_tunneling/LOF/lof_dns_tunneling.pkl")
threshold_if = 0.21859294808767954  # change this
threshold_lof = 1444425086796.0696

def predict_dns(raw_features: dict):
    X = preprocess_dns(raw_features)
    X_scaled = scaler.transform([X])
    score_if = -model_if.decision_function(X_scaled)[0]  # hoặc model.score_samples(X_scaled)[0] tùy lib
    label_if = "malicious" if score_if > threshold_if else "benign"


    if label_if == "benign":
        X_scaled = np.clip(X_scaled, -10, 10)
        score_lof = -model_lof.score_samples(X_scaled)[0]
        label_lof = "malicious" if score_lof > threshold_lof else "benign"
        
        final_label = label_lof
        used_model = "IF→LOF"
        final_score = score_lof
        threshold_used = threshold_lof
    else:
        final_label = label_if
        used_model = "IF"
        final_score = score_if
        threshold_used = threshold_if
        score_lof = None

    result_log ={
        **raw_features,
        "ai_type": "dns",
        "used_model": used_model,
        "score_if": float(score_if),
        "score_lof": float(score_lof) if score_lof is not None else None,
        "threshold_if": float(threshold_if),
        "threshold_lof": float(threshold_lof),
        "final_score": float(final_score),
        "threshold_used": float(threshold_used),
        "ai_label": final_label
    }

    return result_log