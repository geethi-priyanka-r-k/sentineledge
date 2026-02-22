import pandas as pd
import requests
import time
import os

API_URL_EDGE = "http://127.0.0.1:8000/predict"
API_URL_CLOUD = "http://127.0.0.1:8000/predict_cloud"

# Absolute path handling
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
csv_path = os.path.join(base_dir, "data", "raw", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
out_path = os.path.join(base_dir, "data", "predictions_log.csv")

FEATURES = [
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

print("Loading CSV (this may take a bit)...")
df = pd.read_csv(csv_path)
df.columns = df.columns.str.strip()  # remove leading spaces

df = df[FEATURES]

# sample for smooth demo
df = df.sample(2000, random_state=42).reset_index(drop=True)

print("Streaming started... Sending 1 event/sec to EDGE and CLOUD endpoints")
logs = []

for i in range(len(df)):
    row = df.iloc[i].to_dict()
    payload = {"data": row}

    try:
        # EDGE call
        t0 = time.time()
        r_edge = requests.post(API_URL_EDGE, json=payload, timeout=10)
        edge_ms = round((time.time() - t0) * 1000, 2)

        # CLOUD call (simulated latency)
        t1 = time.time()
        r_cloud = requests.post(API_URL_CLOUD, json=payload, timeout=10)
        cloud_ms = round((time.time() - t1) * 1000, 2)

        if r_edge.status_code == 200:
            result = r_edge.json()
            result["edge_latency_ms"] = edge_ms
            result["cloud_latency_ms"] = cloud_ms

            logs.append(result)

            print(
                f"{i+1}/{len(df)} -> {result['predicted_attack']} | "
                f"Risk={result['risk_score']} | {result['severity']} | "
                f"Edge={edge_ms}ms | Cloud={cloud_ms}ms"
            )
        else:
            print("Edge error:", r_edge.status_code, r_edge.text)

    except Exception as e:
        print("Request failed:", e)

    # Save every 20 events
    if (i + 1) % 20 == 0 and logs:
        pd.DataFrame(logs).to_csv(out_path, index=False)

    time.sleep(1)

# Save final
if logs:
    pd.DataFrame(logs).to_csv(out_path, index=False)

print("✅ Streaming finished. Log saved to:", out_path)