"""
Orchestrates a full detection pass and writes the results to the database.
Called by the scheduler every 2 minutes and optionally by the /run_detection
admin endpoint for manual triggering.
"""

import pandas as pd
import json
from pathlib import Path
import joblib

from Model_Pipeline.rule_detector import RuleDetector


def run_detection_pipeline(db, app_context=None, features_csv_path="features.csv"):
    """
    Read the latest features.csv, run both detectors, and store any alerts
    in the database.
    """
    from user.models import Alerts
    from datetime import datetime

    def parse_dt(value):
        if value is None:
            return None
        try:
            return pd.to_datetime(value).to_pydatetime()
        except Exception:
            return datetime.now()

    if not Path(features_csv_path).exists():
        print(f"[LANGuard Flask] {features_csv_path} not found")
        return False

    try:
        features_df = pd.read_csv(features_csv_path)
    except Exception as e:
        print(f"[LANGuard Flask] Error reading features: {e}")
        return False

    if features_df.empty:
        print("[LANGuard Flask] Features file is empty")
        return False

    if Path("rule_results.csv").exists():
        Path("rule_results.csv").unlink()

    rule_detector = RuleDetector()

    for _, row in features_df.iterrows():
        try:
            rule_detector.evaluate(row)
        except Exception as e:
            print(f"[LANGuard Flask] Error evaluating rules: {e}")

    rule_results = {}

    if Path("rule_results.csv").exists():
        try:
            rule_df = pd.read_csv("rule_results.csv")

            for _, rule_row in rule_df.iterrows():
                key = str(rule_row.get("Date", ""))

                if key not in rule_results:
                    rule_results[key] = []

                rule_results[key].append({
                    "name": rule_row.get("Alert_Name", "Unknown"),
                    "severity": rule_row.get("Severity", "Low")
                })

        except Exception as e:
            print(f"[LANGuard Flask] Error reading rule results: {e}")

    ai_alerts = []

    try:
        MODEL_DIR = Path("Model_Pipeline")

        model = joblib.load(MODEL_DIR / "isolation_forest_model.joblib")

        with open(MODEL_DIR / "model_features.json") as f:
            feature_cols = json.load(f)

        for _, row in features_df.iterrows():
            try:
                X = pd.DataFrame([row[feature_cols]], columns=feature_cols)

                score = model.decision_function(X)[0]
                prediction = model.predict(X)[0]

                if prediction == -1:
                    ai_alerts.append({
                        "window_start": row["window_start"],
                        "score": float(score),
                        "is_anomaly": True
                    })
                
            except Exception as e:
                print(f"[LANGuard Flask] Error in AI detection: {e}")

    except FileNotFoundError as e:
        print(f"[LANGuard Flask] Model files not found, skipping AI detection: {e}")

    print("[LANGuard Flask] Storing results in database...")

    try:
        packet_counts = {}

        for _, row in features_df.iterrows():
            packet_counts[str(row["window_start"])] = int(row.get("packet_count", 0))

        for window, alerts_list in rule_results.items():
            for alert in alerts_list:
                new_alert = Alerts(
                    timestamp=datetime.now(),
                    severity=str(alert["severity"]).upper(),
                    status="OPEN",
                    score=1.0,
                    is_anomaly=True,
                    description=f"Rule Alert: {alert['name']}",
                    detection_type="RULE",
                    alert_name=alert["name"],
                    window_start=parse_dt(window),
                    anomaly_score=None,
                    packet_count=packet_counts.get(str(window), 0)
                )

                db.session.add(new_alert)

        for alert in ai_alerts:
            new_alert = Alerts(
                timestamp=datetime.now(),
                severity="MEDIUM",
                status="OPEN",
                score=abs(alert["score"]),
                is_anomaly=True,
                description=f"AI Anomaly Detected (score: {alert['score']:.4f})",
                detection_type="AI",
                alert_name="Anomaly",
                window_start=parse_dt(alert["window_start"]),
                anomaly_score=alert["score"],
                packet_count=packet_counts.get(str(alert["window_start"]), 0)
            )

            db.session.add(new_alert)

        db.session.commit()

        total_rule_alerts = sum(len(alerts_list) for alerts_list in rule_results.values())

        print(
            f"[LANGuard Flask] Stored {total_rule_alerts} rule alerts "
            f"and {len(ai_alerts)} AI alerts"
        )

        return True

    except Exception as e:
        print(f"[LANGuard Flask] Error storing results: {e}")
        db.session.rollback()
        return False