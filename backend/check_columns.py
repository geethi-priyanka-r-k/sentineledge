import pandas as pd
import os

# Get absolute path safely
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
file_path = os.path.join(base_dir, "data", "raw", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

print("Reading file from:", file_path)

df = pd.read_csv(file_path, nrows=5)

print(df.columns.tolist())