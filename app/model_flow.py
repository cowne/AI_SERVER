import joblib
import numpy as np
from app.preprocess_beaconing import preprocess_beaconing

# === Load models & scaler ===
scaler = joblib.load("models/beaconing/scaler.pkl")
model_if = joblib.load("models/beaconing/IF/if_beaconing.pkl")
model_lof = joblib.load("models/beaconing/LOF/lof_beaconing.pkl")

# === Thresholds ===
threshold_if = 0.14137276274753283
threshold_lof = 0.048860168875982435

# === Thứ tự các features khi training ===
FEATURE_ORDER = [
    "flow_duration",
    "flow_bytes_per_s",
    "flow_pkts_per_s",
    "down_up_ratio",
    "average_packet_size",
    "time_diff",
    "time_diff_std",
    "repetition_rate"
]

def predict_flow(raw_features: dict):
    """
    Dự đoán log flow có dấu hiệu beaconing hay không.
    Input:
        raw_features: dict log Suricata (full_log hoặc dict)
    Output:
        result_log: dict chứa kết quả AI predict
    """
    # 1️⃣ Xử lý log → trích xuất đặc trưng
    X_dict = preprocess_beaconing(raw_features)

    # 2️⃣ Chuyển dict → list theo đúng thứ tự features
    X = [X_dict[feature] for feature in FEATURE_ORDER]

    # 3️⃣ Scale dữ liệu
    X_scaled = scaler.transform([X])

    # 4️⃣ Chạy Isolation Forest
    score_if = -model_if.decision_function(X_scaled)[0]
    label_if = "malicious" if score_if > threshold_if else "benign"

    # 5️⃣ Nếu IF benign → dùng LOF refine
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

    # 6️⃣ Tổng hợp kết quả
    result_log = {
        **X_dict,
        "ai_type": "flow",
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
