from fastapi import FastAPI, Request
from app.model_dns import predict_dns
from app.model_flow import predict_flow

app = FastAPI(title="AI Anomaly Dectection Server (Multi-pipeline)")
@app.post("/predict")
async def predict(request: Request):
    data = await request.json()
    data_type = data.get("type")
    features = data.get("data")

    if not data_type:
        return {"error": "Missing 'type' field in the request data."}
    
    if data_type == "flow":
        result = predict_flow(features)
    elif data_type == "dns":
        result = predict_dns(features)
    else:
        result = {"error": f"Unsupported data type: {data_type}. Supported types are 'flow' and 'dns'."}
    
    return result

@app.get("/health")
def health_check():
    return {"status": "ok"}