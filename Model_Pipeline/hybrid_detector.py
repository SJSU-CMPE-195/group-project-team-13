import pandas as pd
import joblib
import json
import sys
from rule_detector import RuleDetector

INPUT_FILE = "features.csv"
MODEL_FILE = "isolation_forest_model.pkl"
FEATURES_META_FILE = "model_features.json"
AI_OUTPUT = "ai_results.csv"
RULE_OUTPUT = "rule_results.csv"
HYBRID_OUTPUT = "hybrid_results.csv"

print("[LANGuard HYBRID] Starting hybrid detection...")

# Load AI detector results
try:
    ai_results = pd.read_csv(AI_OUTPUT)
except FileNotFoundError:
    print(f"[LANGuard HYBRID] AI results not found, run ai_detector.py first")
    sys.exit(1)

# Load rule detector results
try:
    rule_results = pd.read_csv(RULE_OUTPUT)
except FileNotFoundError:
    print(f"[LANGuard HYBRID] Rule results not found, run rule_detector separately")
    rule_results = pd.DataFrame(columns=['Date', 'Alert_Name', 'Severity'])

# Merge results
hybrid_df = ai_results.copy()

# Add rule-based alerts to hybrid results
for _, rule_row in rule_results.iterrows():
    # Check if this time window has a rule alert
    matching_rows = hybrid_df[
        (hybrid_df['window_start'].astype(str) >= rule_row['Date']) &
        (hybrid_df['window_start'].astype(str) <= rule_row['Date'])
    ]
    if not matching_rows.empty:
        hybrid_df.loc[matching_rows.index, 'ai_status'] = 'ANOMALY'

hybrid_df.to_csv(HYBRID_OUTPUT, index=False)
print(f"[LANGuard HYBRID] Hybrid results saved to {HYBRID_OUTPUT}")
