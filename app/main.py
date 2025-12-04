from fastapi import FastAPI, Request
import json
# Đã bỏ import ipaddress theo yêu cầu
from app.model_dns import predict_dns
from app.model_flow import predict_flow

app = FastAPI(title="AI Anomaly Detection Server (Universal)")

RESULT_FILE = "/var/log/ai_results.json"

@app.post("/predict")
async def predict(request: Request):
    try:
        body = await request.json()
    except Exception:
        return {"error": "Invalid JSON body"}

    # --- BƯỚC 1: CHUẨN HÓA DỮ LIỆU ĐẦU VÀO ---
    logs_to_process = []

    # Case 1: Gửi 1 log đơn lẻ
    if isinstance(body, dict):
        if "_source" in body:
            raw_data = body["_source"]
        else:
            raw_data = body
        logs_to_process.append(raw_data)
        
    # Case 2: Gửi 1 list log
    elif isinstance(body, list):
        for item in body:
            if "_source" in item:
                logs_to_process.append(item["_source"])
            else:
                logs_to_process.append(item)

    processed = []

    for log_entry in logs_to_process:
        # --- BƯỚC 2: TÌM DỮ LIỆU CỐT LÕI ---
        if "data" in log_entry and isinstance(log_entry["data"], dict):
            core_data = log_entry["data"]
        elif "event_type" in log_entry:
            core_data = log_entry
        elif "full_log" in log_entry and isinstance(log_entry["full_log"], str):
            try:
                core_data = json.loads(log_entry["full_log"])
            except:
                continue
        else:
            continue

        # --- BƯỚC 2.5: LỌC BỎ IPV6 ---
        src_ip = core_data.get("src_ip")
        dest_ip = core_data.get("dest_ip")

        if src_ip and isinstance(src_ip, str) and ":" in src_ip:
            continue
            
        if dest_ip and isinstance(dest_ip, str) and ":" in dest_ip:
            continue

        # --- BƯỚC 3: LỌC EVENT TYPE VÀ DỰ ĐOÁN ---
        event_type = core_data.get("event_type")
        
        if event_type not in ["flow", "dns"]:
            continue

        try:
            if event_type == "flow":
                result = predict_flow(core_data) 
            else:
                result = predict_dns(core_data)
        except Exception as e:
            print(f"Model prediction error: {e}")
            continue

        # --- BƯỚC 4: GHI FILE KẾT QUẢ (ĐÃ SỬA LOGIC LỌC ĐIỂM CAO) ---
        ai_score = result.get("final_score", 0) # Lấy điểm ra biến riêng
        ai_label = result.get("ai_label")

        # LOGIC MỚI: Chỉ xử lý nếu là malicious VÀ điểm <= 2
        # Điểm > 2 được coi là nhiễu hệ thống (System Noise) -> Bỏ qua
        if ai_label == "malicious" and ai_score <= 2:
            
            minimal = {
                "timestamp": core_data.get("timestamp"),
                "app_name": "ai_ids",
                "src_ip": src_ip,   
                "dest_ip": dest_ip, 
                "suri_flow_id": core_data.get("flow_id"),
                "log_category": event_type,
                "ai_score": ai_score,
                "ai_label": ai_label,
                "alert_type": result.get("alert_type", "unknown"),
            }
            
            with open(RESULT_FILE, "a") as f:
                f.write(json.dumps(minimal) + "\n")

        # Thêm vào response trả về (để debug nếu cần)
        processed.append({
            "flow_id": core_data.get("flow_id"),
            "type": event_type,
            "ai_label": ai_label,
            "ai_score": ai_score,
            "status": "logged" if (ai_label == "malicious" and ai_score <= 2) else "skipped_high_score" if ai_score > 2 else "clean"
        })

    if not processed:
        return {"status": "ignored", "reason": "no valid ipv4 flow/dns events found"}

    return {"status": "processed", "count": len(processed), "results": processed}