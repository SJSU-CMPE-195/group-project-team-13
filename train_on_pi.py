"""
Trains the anomaly detection model on a baseline of normal traffic.

Workflow:
  1. Capture normal traffic with capture_to_csv.py
  2. Extract features with Model_Pipeline/extract_features.py
  3. Run this script to train and save the model

The idea is that you train on traffic you know is clean so the model learns
what "normal" looks like for your specific network. Anything that deviates
significantly from that baseline gets flagged as an anomaly at runtime.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import json
import sys

FEATURES_FILE = "features.csv"
MODEL_OUTPUT = "isolation_forest_model.pkl"
FEATURES_META_OUTPUT = "model_features.json"  # Saved separately so the detector knows which columns to use.

# These are the columns the model uses.
# They capture volume, diversity, and flag patterns in each time window.
FEATURE_COLS = [
    'packet_count',        # Total packets.
    'unique_src_ips',      # Distinct sources.
    'unique_dst_ips',      # Distinct destinations.
    'unique_src_ports',    # Source port variety.
    'unique_dst_ports',    # Destination port variety; high counts can mean scanning.
    'tcp_count',
    'udp_count',
    'syn_count',           # SYN-heavy traffic can point to a SYN flood.
    'ack_count',
    'rst_count',           # Lots of RSTs can mean refused connections or scanning.
    'fin_count',
    'avg_packet_len',
    'max_packet_len',
    'min_packet_len',
]

print(f"[LANGuard] Loading {FEATURES_FILE}...")
try:
    df = pd.read_csv(FEATURES_FILE)
except FileNotFoundError:
    print(f"[LANGuard] {FEATURES_FILE} not found.")
    print("[LANGuard] Run capture_to_csv.py first, then extract_features.py")
    sys.exit(1)

if df.empty:
    print("[LANGuard] features.csv is empty. Capture more traffic first.")
    sys.exit(1)

# Make sure every expected column is present before slicing the DataFrame.
missing = [c for c in FEATURE_COLS if c not in df.columns]
if missing:
    print(f"[LANGuard] Missing columns: {missing}")
    sys.exit(1)

# Replace NaN and infinity with 0 so the model gets clean numeric input.
X = df[FEATURE_COLS].fillna(0).replace([np.inf, -np.inf], 0)

print(f"[LANGuard] Training on {len(X)} windows with {len(FEATURE_COLS)} features...")

# Isolation Forest isolates unusual points in fewer splits than normal ones.
# contamination=0.05 gives the boundary some breathing room without making it too sensitive.
model = IsolationForest(
    n_estimators=100,      # More trees help stability, but gains taper off eventually.
    contamination=0.05,
    random_state=42,       # Fixed seed so results are reproducible.
    n_jobs=-1              # Use all CPU cores.
)
model.fit(X)

# Save the trained model and feature list for detector_runner.
joblib.dump(model, MODEL_OUTPUT)
with open(FEATURES_META_OUTPUT, 'w') as f:
    json.dump(FEATURE_COLS, f)

print(f"[LANGuard] Model saved to {MODEL_OUTPUT}")
print(f"[LANGuard] Feature list saved to {FEATURES_META_OUTPUT}")
print("[LANGuard] Training complete. You can now run app.py")
