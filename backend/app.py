from fastapi import FastAPI
import pandas as pd
import numpy as np
import joblib
import os
import time
from pydantic import BaseModel

app = FastAPI()

# -------------------
# Load Models
# -------------------
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
models_path = os.path.join(base_dir, "backend", "models")

clf = joblib.load(os.path.join(models_path, "model_cls.pkl"))
anom_model = joblib.load(os.path.join(models_path, "model_anom.pkl"))

# -------------------
# Feature List (MUST MATCH TRAINING)
# -------------------
features = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'Fwd PSH Flags',
    'SYN Flag Count',
    'RST Flag Count',
    'ACK Flag Count',
    'Packet Length Variance'
]

# -------------------
# Input Schema
# -------------------
class NetworkEvent(BaseModel):
    data: dict


# -------------------
# Risk + Severity Logic (Upgraded)
# -------------------
def normalize_anomaly(anomaly_raw: float) -> float:
    """
    IsolationForest decision_function: higher = more normal, lower = more anomalous.
    Convert to 0..1 where 1 = highly anomalous.
    """
    p_normal = 1 / (1 + np.exp(-anomaly_raw))  # 0..1 (rough)
    anomaly = 1 - p_normal                     # invert => 1 means anomalous
    return float(anomaly)


def attack_boost(prediction: str) -> float:
    boosts = {
        "BENIGN": 0.00,
        "PORTSCAN": 0.10,
        "BRUTEFORCE": 0.12,
        "DOS_DDOS": 0.15
    }
    return boosts.get(prediction, 0.08)


def calculate_risk(anomaly_score_0_1: float, confidence_0_1: float, pred_label: str) -> int:
    base = (0.70 * anomaly_score_0_1) + (0.30 * confidence_0_1)
    boosted = min(1.0, base + attack_boost(pred_label))
    return int(round(boosted * 100))


def get_severity(risk_score: int) -> str:
    if risk_score >= 85:
        return "Critical"
    elif risk_score >= 65:
        return "High"
    elif risk_score >= 40:
        return "Medium"
    else:
        return "Low"


# -------------------
# Core predict function (shared)
# -------------------
def run_inference(event: NetworkEvent):
    df = pd.DataFrame([event.data])
    df = df[features]

    # Clean numeric issues
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(df.median(numeric_only=True), inplace=True)

    # Classification
    prediction = clf.predict(df)[0]
    proba = clf.predict_proba(df)[0]
    confidence = float(np.max(proba))

    # Anomaly score: 0..1 where 1 = more anomalous
    anomaly_raw = float(anom_model.decision_function(df)[0])
    anomaly_score = normalize_anomaly(anomaly_raw)

    risk_score = calculate_risk(anomaly_score, confidence, prediction)
    severity = get_severity(risk_score)

    return {
        "predicted_attack": prediction,
        "confidence": round(confidence, 3),
        "anomaly_score": round(anomaly_score, 3),
        "risk_score": risk_score,
        "severity": severity
    }


# -------------------
# Health Check
# -------------------
@app.get("/health")
def health():
    return {"status": "SentinelEdge AI running"}


# -------------------
# EDGE Prediction Endpoint
# -------------------
@app.post("/predict")
def predict(event: NetworkEvent):
    return run_inference(event)


# -------------------
# CLOUD Prediction Endpoint (Simulated latency)
# -------------------
@app.post("/predict_cloud")
def predict_cloud(event: NetworkEvent):
    # Simulate extra network round-trip latency (cloud)
    time.sleep(0.25)  # 250ms
    return run_inference(event)