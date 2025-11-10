from fastapi import FastAPI, Request
import json
from app.model_dns import predict_dns
from app.model_flow import predict_flow

app = FastAPI(title="AI Anomaly Detection Server (Multi-pipeline)")

RESULT_FILE = "/var/log/ai_results.json"  # mỗi log một dòng JSON

@app.post("/predict")
async def predict(request: Request):
    body = await request.json()

    # Trường hợp: nhận 1 log hoặc 1 list log
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

        # Lọc loại event
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
        elif event_type == "dns":
            result = predict_dns(full_log)
        else:
            continue

        # Gắn thêm kết quả AI vào log gốc
        log["ai_score"] = result["final_score"]
        log["ai_label"] = result["ai_label"]

        # Ghi log ra file JSON Lines
        with open(RESULT_FILE, "a") as f:
            f.write(json.dumps(log) + "\n")

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
