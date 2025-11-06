import re
import math

def shannon_entropy(s: str) -> float:
    """Tính entropy Shannon của chuỗi."""
    if not s:
        return 0.0
    s = str(s)
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def preprocess_dns_tunneling(raw_log):
    """
    Xử lý log DNS trực tiếp từ Suricata full_log (eve.json):
    - Nếu có grouped.CNAME → gộp tất cả CNAME lại thành chuỗi
    - Nếu có grouped.A hoặc grouped.AAAA → giữ nguyên rrname (không gộp IP)
    - Nếu không có grouped → dùng dns.rrname
    """
    dns_data = raw_log.get("dns", {})
    domain = ""

    try:
        # ---- Ưu tiên CNAME chain ----
        if "grouped" in dns_data:
            grouped = dns_data["grouped"]

            if "CNAME" in grouped:
                cname_list = grouped["CNAME"]
                if isinstance(cname_list, list) and len(cname_list) > 0:
                    # Gộp toàn bộ chuỗi CNAME lại
                    domain = "-".join(cname_list)
                else:
                    domain = dns_data.get("rrname", "")

            elif "A" in grouped or "AAAA" in grouped:
                # Trường hợp grouped chỉ chứa IP, giữ nguyên rrname
                domain = dns_data.get("rrname", "")
            else:
                domain = dns_data.get("rrname", "")
        else:
            domain = dns_data.get("rrname", "")

    except Exception:
        domain = ""

    # ---- Chuẩn hóa domain ----
    if isinstance(domain, (dict, list)):
        domain = str(domain)

    domain = domain.strip()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]

    # ---- Tách labels ----
    labels = [lbl for lbl in domain.split(".") if lbl]

    # ---- Tính toán các đặc trưng ----
    subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""
    sub_len = len(subdomain)
    upper = sum(1 for c in domain if c.isupper())
    lower = sum(1 for c in domain if c.islower())
    numeric = sum(1 for c in domain if c.isdigit())
    special = sum(1 for c in domain if not c.isalnum() and c != ".")
    entropy = shannon_entropy(domain)
    labels_count = len(labels)
    labels_len = [len(l) for l in labels]
    labels_max = max(labels_len) if labels_len else 0
    labels_avg = sum(labels_len) / labels_count if labels_count > 0 else 0
    longest_word = max((len(w) for w in re.findall(r"[a-zA-Z]+", domain)), default=0)
    total_len = len(domain)
    has_subdomain = 1 if len(labels) > 2 else 0

    # ---- Đóng gói kết quả ----
    features = {
        "subdomain_length": sub_len,
        "upper": upper,
        "lower": lower,
        "numeric": numeric,
        "entropy": entropy,
        "special": special,
        "labels": labels_count,
        "labels_max": labels_max,
        "labels_average": labels_avg,
        "longest_word": longest_word,
        "len": total_len,
        "subdomain": has_subdomain
    }

    return features
