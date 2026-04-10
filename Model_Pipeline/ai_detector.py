import pandas as pd
import joblib
import os
from datetime import datetime


class AIDetector:
    def __init__(self, model_path="friday_ddos_model.joblib"):
        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
            print(f"[*] AI Model loaded: {model_path}")
        else:
            raise FileNotFoundError(f"Model file {model_path} not found. Train it first!")

    def get_score(self, feature_row):
        # calcs the anomaly and give score.
        # 1. convert to a DataFrame if its a single row
        if isinstance(feature_row, pd.Series):
            X = pd.DataFrame([feature_row])
        else:
            X = feature_row.copy()

        # 2. safety check: only drop 'window_start' if it actually exists
        if 'window_start' in X.columns:
            X = X.drop(columns=['window_start'])

        # 3. ensure columns are in the EXACT same order as training
        # this matches the 9 features from your training script
        # if its not in exact order, model will break/not function correctly
        expected_columns = [
            "packet_count", "unique_src_ips", "unique_dst_ips",
            "unique_dst_ports", "avg_packet_len", "max_packet_len",
            "tcp_count", "udp_count", "syn_count"
        ]

        # reorder X to match expected_columns
        X = X[expected_columns]

        # 4. get the score
        raw_score = self.model.decision_function(X)[0]

        # returns raw score
        return round(raw_score, 6)


# sample run
if __name__ == "__main__":
    detector = AIDetector()

    input_file = "local_packets_to_featured.csv"
    if os.path.exists(input_file):
        df = pd.read_csv(input_file)

        if not df.empty:
            # Score the most recent window
            last_window = df.iloc[-1]
            raw, prob = detector.get_score(last_window)

            print(f"Window Start: {last_window['window_start']}")
            print(f"Raw Decision Score: {raw}")
            print(f"Anomaly Probability: {prob}")