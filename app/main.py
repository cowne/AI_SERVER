from fastapi import FastAPI, Request
import json
from app.model_dns import predict_dns
from app.model_flow import predict_flow

app = FastAPI(title="AI Anomaly Detection Server (Multi-pipeline)")

RESULT_FILE = "/var/log/ai_results.json"  # mỗi log một dòng JSON

@app.post("/predict")
async def predict(request: Request):
    body = await request.json()

    # Nhận 1 log hoặc 1 list log
    if "_source" in body:
        logs = [body["_source"]]
    elif isinstance(body, list):
        logs = [b["_source"] for b in body if "_source" in b]
    else:
        return {"error": "Invalid log format"}

    processed = []

    for log in logs:

        data = log.get("data", {})
        event_type = data.get("event_type")

        # Chỉ nhận flow hoặc dns
        if event_type not in ["flow", "dns"]:
            continue

        # Parse Suricata raw JSON
        full_log_str = log.get("full_log")
        if not full_log_str:
            continue

        full_log = json.loads(full_log_str)

        # Dự đoán bằng model tương ứng
        if event_type == "flow":
            result = predict_flow(full_log)
        else:
            result = predict_dns(full_log)

        # Gắn thêm AI result để trả về API
        log["ai_score"] = result["final_score"]
        log["ai_label"] = result["ai_label"]

        # Nếu malicious → chỉ ghi thông tin giản lược (clean)
        if result["ai_label"] == "malicious":

            minimal = {
                "timestamp": full_log.get("timestamp"),
                "src_ip": full_log.get("src_ip"),
                "dest_ip": full_log.get("dest_ip"),
                "flow_id": full_log.get("flow_id"),
                "event_type": event_type,
                "ai_score": result["final_score"],
                "ai_label": result["ai_label"]
            }

            # Append JSON Lines
            with open(RESULT_FILE, "a") as f:
                f.write(json.dumps(minimal) + "\n")

        # Thông tin trả về API
        processed.append({
            "agent": log.get("agent", {}).get("name"),
            "type": event_type,
            "ai_label": log.get("ai_label"),
            "ai_score": log.get("ai_score"),
        })

    if not processed:
        return {"status": "ignored", "reason": "no flow/dns events"}

    return {"status": "processed", "count": len(processed), "results": processed}


@app.get("/health")
def health_check():
    return {"status": "ok"}
