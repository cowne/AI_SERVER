import joblib
import numpy as np
from app.preprocess_dns_tunneling import preprocess_dns_tunneling

# Tải model và scaler
scaler = joblib.load("models/dns_tunneling/scaler.pkl")
model_if = joblib.load("models/dns_tunneling/IF/if_dns_tunneling.pkl")
model_lof = joblib.load("models/dns_tunneling/LOF/lof_dns_tunneling.pkl")

threshold_if = 0.21859294808767954
threshold_lof = 1444425086796.0696

FEATURE_ORDER = [
    "subdomain_length", "upper", "lower", "numeric", "entropy",
    "special", "labels", "labels_max", "labels_average",
    "longest_word", "len", "subdomain"
]

def predict_dns(raw_features: dict):
    # 1️⃣ Xử lý log → trích xuất đặc trưng
    X_dict = preprocess_dns_tunneling(raw_features)
    
    # 2️⃣ Chuyển dict → list theo đúng thứ tự features
    X = [X_dict[feature] for feature in FEATURE_ORDER]

    # 3️⃣ Scale dữ liệu
    X_scaled = scaler.transform([X])

    # 4️⃣ Chạy Isolation Forest
    score_if = -model_if.decision_function(X_scaled)[0]
    label_if = "malicious" if score_if > threshold_if else "benign"

    # 5️⃣ Nếu IF benign → dùng LOF kiểm tra tiếp
    if label_if == "benign":
        # ❌ Bỏ clip: giữ nguyên giá trị scale thật
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

    # 6️⃣ Tổng hợp kết quả
    result_log = {
        **X_dict,
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
