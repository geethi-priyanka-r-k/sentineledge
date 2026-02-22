import pandas as pd
import numpy as np
import os
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split

# -----------------------
# Locate dataset properly
# -----------------------
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data_path = os.path.join(base_dir, "data", "raw")

file_path = os.path.join(data_path, "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

print("Loading dataset...")
df = pd.read_csv(file_path)

# -----------------------
# Clean column names (REMOVE SPACES)
# -----------------------
df.columns = df.columns.str.strip()

print("Columns cleaned.")

# -----------------------
# Select Features (NO leading spaces now)
# -----------------------
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

# Keep only needed columns
df = df[features + ['Label']]

# -----------------------
# Clean numeric problems
# -----------------------
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(df.median(numeric_only=True), inplace=True)

# -----------------------
# Simplify Labels
# -----------------------
def map_label(label):
    if label == 'BENIGN':
        return 'BENIGN'
    elif 'DoS' in label or 'DDoS' in label:
        return 'DOS_DDOS'
    elif 'PortScan' in label:
        return 'PORTSCAN'
    elif 'Patator' in label:
        return 'BRUTEFORCE'
    else:
        return 'OTHER'

df['Label'] = df['Label'].apply(map_label)

df = df[df['Label'] != 'OTHER']

print("Label mapping complete.")

# -----------------------
# Train/Test Split
# -----------------------
X = df[features]
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -----------------------
# Train Classifier
# -----------------------
print("Training RandomForest...")
clf = RandomForestClassifier(n_estimators=100)
clf.fit(X_train, y_train)

# -----------------------
# Train Anomaly Model (Benign only)
# -----------------------
print("Training IsolationForest...")
benign_data = X_train[y_train == 'BENIGN']
anom_model = IsolationForest(contamination=0.1)
anom_model.fit(benign_data)

# -----------------------
# Save Models
# -----------------------
models_dir = os.path.join(base_dir, "backend", "models")
os.makedirs(models_dir, exist_ok=True)

joblib.dump(clf, os.path.join(models_dir, "model_cls.pkl"))
joblib.dump(anom_model, os.path.join(models_dir, "model_anom.pkl"))

print("✅ Training complete. Models saved.")