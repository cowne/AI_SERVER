import joblib
import numpy as np
from app.preprocess_beaconing import preprocess_flow

# === Load models & scaler ===
scaler_flow = joblib.load("models/beaconing/scaler.pkl")
model_if = joblib.load("models/beaconing/IF/if_beaconing.pkl")
model_lof = joblib.load("models/beaconing/LOF/lof_beaconing.pkl")

# === Thresholds ===
threshold_if = 0.14137276274753283
threshold_lof = 0.048860168875982435

def predict_flow(raw_features: dict):
    # Tiền xử lý dữ liệu
    X = preprocess_flow(raw_features)
    X_scaled = scaler_flow.transform([X])

    # Isolation Forest predict
    score_if = -model_if.decision_function(X_scaled)[0]
    label_if = "malicious" if score_if > threshold_if else "benign"

    # Nếu IF cho là benign → LOF refine
    if label_if == "benign":
        score_lof = -model_lof.decision_function(X_scaled)[0]
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

    # Gắn kết quả trực tiếp vào log gốc
    result_log = {
        **raw_features,                    # giữ nguyên dữ liệu gốc
        "ai_type": "flow",                 # loại dữ liệu (flow log)
        "used_model": used_model,          # IF hoặc IF→LOF
        "score_if": float(score_if),
        "score_lof": float(score_lof) if score_lof is not None else None,
        "threshold_if": float(threshold_if),
        "threshold_lof": float(threshold_lof),
        "final_score": float(final_score),
        "threshold_used": float(threshold_used),
        "ai_label": final_label            # nhãn cuối cùng
    }

    return result_log
