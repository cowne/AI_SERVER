from fastapi import FastAPI, Request
import json
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

    # --- BƯỚC 1: CHUẨN HÓA DỮ LIỆU ĐẦU VÀO (QUAN TRỌNG) ---
    # Mục tiêu: Dù gửi kiểu gì, ta cũng moi ra được list các log sạch
    
    logs_to_process = []

    # Case 1: Gửi 1 log đơn lẻ (từ Script Forwarder Python)
    if isinstance(body, dict):
        # Nếu có _source (kiểu Elastic cũ) -> bóc ra
        if "_source" in body:
            raw_data = body["_source"]
        else:
            raw_data = body # Đã là log sạch hoặc log archive
        
        logs_to_process.append(raw_data)
        
    # Case 2: Gửi 1 list log (Batch processing)
    elif isinstance(body, list):
        for item in body:
            if "_source" in item:
                logs_to_process.append(item["_source"])
            else:
                logs_to_process.append(item)

    processed = []

    for log_entry in logs_to_process:
        # --- BƯỚC 2: TÌM DỮ LIỆU CỐT LÕI (Suricata Data) ---
        
        # Ưu tiên 1: Dữ liệu nằm trong key 'data' (Log Archive gốc)
        if "data" in log_entry and isinstance(log_entry["data"], dict):
            core_data = log_entry["data"]
            # Đôi khi trong data lại có full_log dạng string, nếu cần thì parse, 
            # nhưng thường data đã đủ các trường rồi.
        
        # Ưu tiên 2: Log đã được bóc tách (Script Forwarder gửi cái này)
        elif "event_type" in log_entry:
            core_data = log_entry
            
        # Ưu tiên 3: Parse từ full_log string (Kiểu cũ của bạn)
        elif "full_log" in log_entry and isinstance(log_entry["full_log"], str):
            try:
                core_data = json.loads(log_entry["full_log"])
            except:
                continue
        else:
            continue # Không hiểu format này

        # --- BƯỚC 3: LỌC VÀ DỰ ĐOÁN ---
        event_type = core_data.get("event_type")
        
        if event_type not in ["flow", "dns"]:
            continue

        # Model của bạn cần dict, core_data giờ chắc chắn là dict
        try:
            if event_type == "flow":
                # Lưu ý: Đảm bảo core_data có đủ field mà model cần (flow_id, dest_ip...)
                result = predict_flow(core_data) 
            else:
                result = predict_dns(core_data)
        except Exception as e:
            print(f"Model prediction error: {e}")
            continue

        # --- BƯỚC 4: GHI FILE KẾT QUẢ ---
        if result.get("ai_label") == "malicious":
            minimal = {
                "timestamp": core_data.get("timestamp"),
                "app_name": "ai_ids",
                "src_ip": core_data.get("src_ip"),
                "dest_ip": core_data.get("dest_ip"),
                "suri_flow_id": core_data.get("flow_id"),
                "log_category": event_type,
                "ai_score": result["final_score"],
                "ai_label": result["ai_label"],
                "alert_type": result.get("alert_type", "unknown"),
            }
            
            # Ghi file (Append mode)
            with open(RESULT_FILE, "a") as f:
                f.write(json.dumps(minimal) + "\n")

        # Response API
        processed.append({
            "flow_id": core_data.get("flow_id"),
            "type": event_type,
            "ai_label": result.get("ai_label"),
            "ai_score": result.get("final_score"),
        })

    if not processed:
        return {"status": "ignored", "reason": "no valid flow/dns events found"}

    return {"status": "processed", "count": len(processed), "results": processed}