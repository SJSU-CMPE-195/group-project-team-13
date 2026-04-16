"""
Orchestrates a full detection pass and writes the results to the database.
Called by the scheduler every 2 minutes and optionally by the /run_detection
admin endpoint for manual triggering.
"""

import pandas as pd
import json
import sys
from pathlib import Path
import io
from contextlib import redirect_stdout

from Model_Pipeline.rule_detector import RuleDetector
import joblib


def run_detection_pipeline(db, app_context=None, features_csv_path="features.csv"):
    """
    Read the latest features.csv, run both detectors, and store any alerts
    in the database. Returns True on success and False when we should skip
    the database writes.
    """
    from user.models import Alerts
    from datetime import datetime

    print("[LANGuard Flask] Starting detection pipeline...")

    # There is nothing to analyze until feature extraction has produced data.
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

    # Run the rule-based detector first.
    print("[LANGuard Flask] Running rule-based detection...")

    # Clear stale rule output so we do not duplicate alerts from an earlier run.
    if Path("rule_results.csv").exists():
        Path("rule_results.csv").unlink()

    rule_detector = RuleDetector()

    # Check each time window against the threshold rules.
    for _, row in features_df.iterrows():
        try:
            rule_detector.evaluate(row)
        except Exception as e:
            print(f"[LANGuard Flask] Error evaluating rules: {e}")

    # Read the rule results back from the CSV the detector wrote.
    rule_results = {}
    if Path("rule_results.csv").exists():
        try:
            rule_df = pd.read_csv("rule_results.csv")
            for _, rule_row in rule_df.iterrows():
                # Group alerts by timestamp so the same window stays together.
                key = str(rule_row.get('Date', ''))
                if key not in rule_results:
                    rule_results[key] = []
                rule_results[key].append({
                    'name': rule_row.get('Alert_Name', 'Unknown'),
                    'severity': rule_row.get('Severity', 'Low')
                })
        except Exception as e:
            print(f"[LANGuard Flask] Error reading rule results: {e}")

    # Run the AI detector next.
    print("[LANGuard Flask] Running AI-based detection...")
    ai_alerts = []
    try:
        # Load the trained model and the feature list it expects.
        model = joblib.load("isolation_forest_model.pkl")
        with open("model_features.json") as f:
            feature_cols = json.load(f)

        for _, row in features_df.iterrows():
            try:
                X = row[feature_cols].values.reshape(1, -1)

                # decision_function returns a continuous score; lower means more anomalous.
                score = model.decision_function(X)[0]
                # predict() uses -1 for anomalies and 1 for normal traffic.
                prediction = model.predict(X)[0]
                is_anomaly = prediction == -1

                if is_anomaly:
                    ai_alerts.append({
                        'window_start': row['window_start'],
                        'score': score,
                        'is_anomaly': True
                    })
            except Exception as e:
                print(f"[LANGuard Flask] Error in AI detection: {e}")

    except FileNotFoundError:
        # The model is not trained yet. Run train_on_pi.py on clean traffic first.
        print("[LANGuard Flask] Model files not found, skipping AI detection. Run train_on_pi.py first.")

    # Store the alerts in the database.
    print("[LANGuard Flask] Storing results in database...")
    try:
        # Build a quick lookup from window_start to packet_count for each alert.
        packet_counts = {}
        for _, row in features_df.iterrows():
            packet_counts[str(row['window_start'])] = int(row.get('packet_count', 0))

        # Write one row for every rule that fired in each window.
        for window, alerts_list in rule_results.items():
            for alert in alerts_list:
                new_alert = Alerts(
                    timestamp=datetime.now(),
                    severity=alert['severity'],
                    status='OPEN',
                    score=1.0,  # Rule hits are binary, so the score stays at 1.0.
                    is_anomaly=True,
                    description=f"Rule Alert: {alert['name']}",
                    detection_type='RULE',
                    alert_name=alert['name'],
                    window_start=window,
                    anomaly_score=None,  # Rule-based alerts do not have a continuous score.
                    packet_count=packet_counts.get(str(window), 0)
                )
                db.session.add(new_alert)

        # AI alerts default to Medium because the model returns a score, not a label.
        for alert in ai_alerts:
            new_alert = Alerts(
                timestamp=datetime.now(),
                severity='Medium',
                status='OPEN',
                score=abs(alert['score']),  # Keep the display score positive.
                is_anomaly=True,
                description=f"AI Anomaly Detected (score: {alert['score']:.4f})",
                detection_type='AI',
                alert_name='Anomaly',
                window_start=alert['window_start'],
                anomaly_score=alert['score'],
                packet_count=packet_counts.get(str(alert['window_start']), 0)
            )
            db.session.add(new_alert)

        db.session.commit()
        print(f"[LANGuard Flask] Stored {len(rule_results)} rule alerts and {len(ai_alerts)} AI alerts")

    except Exception as e:
        print(f"[LANGuard Flask] Error storing results: {e}")
        db.session.rollback()
        return False

    return True
