"""
Orchestrates a full detection pass and writes the results to the database.
"""

import pandas as pd
import json
import sys
from pathlib import Path
import io
from contextlib import redirect_stdout
from datetime import datetime

from Model_Pipeline.rule_detector import RuleDetector
import joblib


def run_detection_pipeline(db, app_context=None, features_csv_path="features.csv"):
    """
    Read the latest features.csv, run both detectors, and store any alerts
    in the database. Returns True on success and False when we should skip
    the database writes.
    """
    from user.models import Alerts

    print("[LANGuard Flask] Starting detection pipeline...")

    if not Path(features_csv_path).exists():
        print(f"[LANGuard Flask] {features_csv_path} not found")
        return False

    try:
        features_df = pd.read_csv(features_csv_path)
        features_df['window_start'] = pd.to_datetime(features_df['window_start'])
    except Exception as e:
        print(f"[LANGuard Flask] Error reading features: {e}")
        return False

    if features_df.empty:
        print("[LANGuard Flask] Features file is empty")
        return False

    print("[LANGuard Flask] Running rule-based detection...")

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
                key = str(rule_row.get('Date', ''))
                if key not in rule_results:
                    rule_results[key] = []
                rule_results[key].append({
                    'name': rule_row.get('Alert_Name', 'Unknown'),
                    'severity': rule_row.get('Severity', 'Low')
                })
        except Exception as e:
            print(f"[LANGuard Flask] Error reading rule results: {e}")

    print("[LANGuard Flask] Running AI-based detection...")
    ai_alerts = []
    try:
        model = joblib.load("isolation_forest_model.pkl")
        with open("model_features.json") as f:
            feature_cols = json.load(f)

        for _, row in features_df.iterrows():
            try:
                X = pd.DataFrame([row[feature_cols].values], columns=feature_cols)
                score = model.decision_function(X)[0]
                prediction = model.predict(X)[0]
                is_anomaly = prediction == -1

                if is_anomaly:
                    window_dt = pd.Timestamp(row['window_start']).to_pydatetime()
                    ai_alerts.append({
                        'window_start': window_dt,
                        'score': score,
                        'is_anomaly': True
                    })
            except Exception as e:
                print(f"[LANGuard Flask] Error in AI detection: {e}")

    except FileNotFoundError:
        print("[LANGuard Flask] Model files not found, skipping AI detection.")

    print("[LANGuard Flask] Storing results in database...")
    try:
        packet_counts = {}
        for _, row in features_df.iterrows():
            packet_counts[str(row['window_start'])] = int(row.get('packet_count', 0))

        window_lookup = {}
        for _, row in features_df.iterrows():
            window_str = str(row['window_start'])[:19]
            window_lookup[window_str] = pd.Timestamp(row['window_start']).to_pydatetime()

        for window, alerts_list in rule_results.items():
            for alert in alerts_list:
                window_str = str(window)[:19]
                window_dt = window_lookup.get(window_str, datetime.now())

                new_alert = Alerts(
                    timestamp=datetime.now(),
                    severity=alert['severity'],
                    status='OPEN',
                    score=1.0,
                    is_anomaly=True,
                    description=f"Rule Alert: {alert['name']}",
                    detection_type='RULE',
                    alert_name=alert['name'],
                    window_start=window_dt,
                    anomaly_score=None,
                    packet_count=packet_counts.get(window_str, 0)
                )
                db.session.add(new_alert)

        for alert in ai_alerts:
            new_alert = Alerts(
                timestamp=datetime.now(),
                severity='Medium',
                status='OPEN',
                score=abs(alert['score']),
                is_anomaly=True,
                description=f"AI Anomaly Detected (score: {alert['score']:.4f})",
                detection_type='AI',
                alert_name='Anomaly',
                window_start=alert['window_start'],
                anomaly_score=alert['score'],
                packet_count=0
            )
            db.session.add(new_alert)

        db.session.commit()
        print(f"[LANGuard Flask] Stored {len(rule_results)} rule alerts and {len(ai_alerts)} AI alerts")

        # Delete processed files so they don't get re-read next cycle
        for f in ["packets.csv", "features.csv", "rule_results.csv", "ai_results.csv"]:
            if Path(f).exists():
                Path(f).unlink()
        print("[LANGuard Flask] Cleaned up processed files")

    except Exception as e:
        print(f"[LANGuard Flask] Error storing results: {e}")
        db.session.rollback()
        return False

    return True