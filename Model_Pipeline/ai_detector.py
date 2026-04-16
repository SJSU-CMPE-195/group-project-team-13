"""
Standalone script for running the AI anomaly detector and printing results to the console.
Useful for manual testing or debugging outside of Flask.
For production use, detector_runner.py calls the model directly without going through this file.
"""

import pandas as pd
import joblib
import json
import sys

INPUT_FILE = "features.csv"
MODEL_FILE = "isolation_forest_model.pkl"
FEATURES_META_FILE = "model_features.json"
OUTPUT_FILE = "ai_results.csv"


def main(input_file=INPUT_FILE, model_file=MODEL_FILE,
         features_meta_file=FEATURES_META_FILE, output_file=OUTPUT_FILE):

    # Load the trained Isolation Forest model.
    try:
        model = joblib.load(model_file)
    except FileNotFoundError:
        print(f"[LANGuard] Model not found: {model_file}")
        print("[LANGuard] Run train_model.py on normal traffic first.")
        sys.exit(1)

    # Load the feature columns the model was trained on.
    # The order matters; mixing it up would lead to bad predictions.
    try:
        with open(features_meta_file) as f:
            feature_cols = json.load(f)
    except FileNotFoundError:
        print(f"[LANGuard] Feature metadata not found: {features_meta_file}")
        print("[LANGuard] Re-run train_model.py to regenerate it.")
        sys.exit(1)

    df = pd.read_csv(input_file)

    if df.empty:
        print("[LANGuard] features.csv is empty.")
        sys.exit(1)

    # Catch the case where extract_features.py produced unexpected columns.
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        print(f"[LANGuard] Missing columns: {missing}")
        print("[LANGuard] Re-run extract_features.py or re-train the model.")
        sys.exit(1)

    X = df[feature_cols]

    # decision_function returns a continuous score; more negative means more anomalous.
    # predict() turns that score into a label: -1 for anomaly, 1 for normal.
    scores = model.decision_function(X)
    predictions = model.predict(X)

    df["ai_status"] = ["ANOMALY" if p == -1 else "NORMAL" for p in predictions]
    df["anomaly_score"] = scores.round(4)

    # Print a quick summary so suspicious windows are easy to spot.
    print(f"\n{'window_start':<25} {'ai_status':<10} {'anomaly_score'}")
    print("-" * 55)
    for _, row in df.iterrows():
        flag = " <-- ANOMALY" if row["ai_status"] == "ANOMALY" else ""
        print(f"{str(row['window_start']):<25} {row['ai_status']:<10} {row['anomaly_score']:.4f}{flag}")

    df.to_csv(output_file, index=False)
    print(f"\n[LANGuard] Results saved to {output_file}")
    return df


if __name__ == "__main__":
    main()