import numpy as np
from datetime import datetime
from redis import Redis
import json
import os
# Redis lưu lịch sử flow để tính 3 feature động
r = Redis(host=os.getenv("REDIS_HOST", "localhost"), port=6379, db=0)

def preprocess_beaconing(raw_log):
    """
    Xử lý log flow trực tiếp từ Suricata (full_log hoặc dict flow event):
    - Tính 6 feature tĩnh: flow_duration (age), flow_bytes_per_s, flow_pkts_per_s,
      down_up_ratio, average_packet_size
    - Tính 3 feature động: time_diff, time_diff_std, repetition_rate (qua Redis)
    """

    # ---- Đọc dữ liệu flow ----
    try:
        # Nếu log là chuỗi JSON thì parse, nếu là dict thì dùng luôn
        data = json.loads(raw_log) if isinstance(raw_log, str) else raw_log
        src_ip = data.get("src_ip")
        dst_ip = data.get("dest_ip")
        flow = data.get("flow", {})
        flow_start = flow.get("start", "")
    except Exception:
        return {}

    # ---- Tính feature tĩnh ----
    try:
        flow_duration = float(flow.get("age", 0.0))
        bytes_toserver = float(flow.get("bytes_toserver", 0))
        bytes_toclient = float(flow.get("bytes_toclient", 0))
        pkts_toserver = float(flow.get("pkts_toserver", 0))
        pkts_toclient = float(flow.get("pkts_toclient", 0))

        total_bytes = bytes_toserver + bytes_toclient
        total_pkts = pkts_toserver + pkts_toclient

        flow_bytes_per_s = total_bytes / flow_duration if flow_duration > 0 else 0.0
        flow_pkts_per_s = total_pkts / flow_duration if flow_duration > 0 else 0.0
        down_up_ratio = bytes_toclient / bytes_toserver if bytes_toserver > 0 else 0.0
        average_packet_size = total_bytes / total_pkts if total_pkts > 0 else 0.0
    except Exception:
        flow_duration = flow_bytes_per_s = flow_pkts_per_s = 0.0
        down_up_ratio = average_packet_size = 0.0

    # ---- Tính feature động ----
    time_diff, time_diff_std, repetition_rate = _calc_dynamic_features(src_ip, dst_ip, flow_start)

    # ---- Đóng gói kết quả ----
    features = {
        "flow_duration": flow_duration,
        "flow_bytes_per_s": flow_bytes_per_s,
        "flow_pkts_per_s": flow_pkts_per_s,
        "down_up_ratio": down_up_ratio,
        "average_packet_size": average_packet_size,
        "time_diff": time_diff,
        "time_diff_std": time_diff_std,
        "repetition_rate": repetition_rate
    }

    return features


# -----------------------------
# 🧮 Hàm phụ: tính feature động
# -----------------------------
def _calc_dynamic_features(src, dst, flow_start_str):
    """
    Lưu 10 timestamp gần nhất của từng cặp (src,dst) vào Redis để tính:
    - time_diff: chênh lệch thời gian giữa 2 flow gần nhất
    - time_diff_std: độ lệch chuẩn của các time_diff
    - repetition_rate: tỷ lệ time_diff nằm trong ±3s quanh mean_diff
    """
    if not src or not dst or not flow_start_str:
        return 0.0, 0.0, 0.0

    key = f"{src}|{dst}"

    try:
        ts = datetime.fromisoformat(flow_start_str.replace("Z", "+00:00"))
    except Exception:
        return 0.0, 0.0, 0.0

    try:
        # Lấy lịch sử timestamp từ Redis
        history = json.loads(r.get(key) or "[]")
        history.append(ts.isoformat())
        if len(history) > 10:
            history = history[-10:]

        # Lưu lại vào Redis, TTL 30 phút
        r.set(key, json.dumps(history), ex=1800)

        # Nếu chỉ có 1 timestamp → chưa đủ dữ liệu
        if len(history) < 2:
            return 0.0, 0.0, 0.0

        # Tính khoảng cách thời gian giữa các flow
        times = [datetime.fromisoformat(t) for t in history]
        diffs = np.diff([t.timestamp() for t in times])

        if len(diffs) == 0:
            return 0.0, 0.0, 0.0

        time_diff = float(diffs[-1])
        time_diff_std = float(np.std(diffs))

        mean_diff = np.mean(diffs)
        repeated = np.sum(np.abs(diffs - mean_diff) <= 3)
        repetition_rate = float(repeated / len(diffs))

        return time_diff, time_diff_std, repetition_rate

    except Exception:
        return 0.0, 0.0, 0.0
