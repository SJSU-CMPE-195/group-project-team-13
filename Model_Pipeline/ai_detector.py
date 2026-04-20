import pandas as pd
import joblib
import json
import sys

INPUT_FILE = "features.csv"
MODEL_FILE = "isolation_forest_model.pkl"
FEATURES_META_FILE = "model_features.json"
OUTPUT_FILE = "ai_results.csv"

try:
    model = joblib.load(MODEL_FILE)
except FileNotFoundError:
    print(f"[LANGuard] Model not found: {MODEL_FILE}")
    print("[LANGuard] Run train_model.py on normal traffic first.")
    sys.exit(1)

try:
    with open(FEATURES_META_FILE) as f:
        feature_cols = json.load(f)
except FileNotFoundError:
    print(f"[LANGuard] Feature metadata not found: {FEATURES_META_FILE}")
    print("[LANGuard] Re-run train_model.py to regenerate it.")
    sys.exit(1)

df = pd.read_csv(INPUT_FILE)

if df.empty:
    print("[LANGuard] features.csv is empty.")
    sys.exit(1)

missing = [c for c in feature_cols if c not in df.columns]
if missing:
    print(f"[LANGuard] Missing columns: {missing}")
    print("[LANGuard] Re-run extract_features.py or re-train the model.")
    sys.exit(1)

X = df[feature_cols]

scores = model.decision_function(X)
predictions = model.predict(X)

df["ai_status"] = ["ANOMALY" if p == -1 else "NORMAL" for p in predictions]
df["anomaly_score"] = scores.round(4)

print(f"\n{'window_start':<25} {'ai_status':<10} {'anomaly_score'}")
print("-" * 55)
for _, row in df.iterrows():
    flag = " <-- ANOMALY" if row["ai_status"] == "ANOMALY" else ""
    print(f"{str(row['window_start']):<25} {row['ai_status']:<10} {row['anomaly_score']:.4f}{flag}")

df.to_csv(OUTPUT_FILE, index=False)
print(f"\n[LANGuard] Results saved to {OUTPUT_FILE}")
