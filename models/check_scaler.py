import joblib
import numpy as np

# === 1️⃣ Load model và scaler ===
lof_model = joblib.load("models/dns_tunneling/LOF/lof_dns_tunneling.pkl")
scaler = joblib.load("models/dns_tunneling/scaler.pkl")

print("✅ Model và Scaler đã load thành công.")
print("Sklearn LOF params:", lof_model.get_params())

# === 2️⃣ Kiểm tra tình trạng lrd_ (mật độ cục bộ) ===
try:
    print("\n=== 🔍 Kiểm tra LRD (Local Reachability Density) ===")
    print("Mean of lrd_:", np.mean(lof_model._lrd))
    print("Min of lrd_:", np.min(lof_model._lrd))
    print("Max of lrd_:", np.max(lof_model._lrd))
except Exception as e:
    print("⚠️ Không thể đọc _lrd_:", e)

# === 3️⃣ Kiểm tra dữ liệu huấn luyện đã lưu trong model ===
try:
    fitX = lof_model._fit_X
    print("\n=== 🔍 Kiểm tra _fit_X (dữ liệu train mà LOF lưu lại) ===")
    print("Shape:", fitX.shape)
    print("Min:", np.min(fitX), "Max:", np.max(fitX))
    print("Mean:", np.mean(fitX), "Std:", np.std(fitX))
    print("First 5 rows:\n", fitX[:5])
except Exception as e:
    print("⚠️ Không thể đọc _fit_X:", e)

# === 4️⃣ Test một sample benign xem score có nổ không ===
print("\n=== 🔬 Kiểm tra predict mẫu test ===")
# (Thay giá trị dưới đây bằng 1 mẫu benign mà anh đang test)
X_test = np.array([[10, 0, 10, 11, 2.767194748898957, 6, 6, 7, 3.6, 2.0, 14, 1]], dtype=np.float64)

X_scaled = scaler.transform(X_test)
print("Scaled min/max:", np.min(X_scaled), np.max(X_scaled))

try:
    score = -lof_model.score_samples(X_scaled)[0]
    print("LOF score (offline):", score)
except Exception as e:
    print("❌ Lỗi khi tính LOF score:", e)

# === 5️⃣ Kiểm tra thêm 3 mẫu đầu tiên trong _fit_X (để so sánh) ===
try:
    print("\n=== 🔍 Test thử 3 dòng trong _fit_X ===")
    for i in range(3):
        test_score = -lof_model.score_samples([fitX[i]])[0]
        print(f"Row {i} score:", test_score)
except Exception as e:
    print("⚠️ Không thể test trên _fit_X:", e)

print("Unique LRD values:", np.unique(lof_model._lrd))


print("\n=== ✅ Kiểm tra hoàn tất ===")
