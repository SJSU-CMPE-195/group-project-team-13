"""
Unit tests for Model_Pipeline/ai_detector.py and hybrid_detector.py
"""
import pytest
import pandas as pd
import numpy as np
import joblib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from Model_Pipeline.ai_detector import main as ai_main
from Model_Pipeline.hybrid_detector import main as hybrid_main

FEATURE_COLS = [
    "packet_count", "unique_src_ips", "unique_dst_ips", "unique_dst_ports",
    "unique_src_ports", "avg_packet_len", "max_packet_len", "min_packet_len",
    "tcp_count", "udp_count", "syn_count", "ack_count", "rst_count", "fin_count"
]


def make_normal_features(n=50):
    np.random.seed(42)
    return pd.DataFrame({
        "window_start": pd.date_range("2024-01-01", periods=n, freq="15s"),
        "packet_count":    np.random.randint(50, 200, n),
        "unique_src_ips":  np.random.randint(1, 5, n),
        "unique_dst_ips":  np.random.randint(1, 5, n),
        "unique_dst_ports":np.random.randint(1, 10, n),
        "unique_src_ports":np.random.randint(5, 30, n),
        "avg_packet_len":  np.random.uniform(64, 256, n),
        "max_packet_len":  np.random.randint(256, 1500, n),
        "min_packet_len":  np.random.randint(40, 64, n),
        "tcp_count":       np.random.randint(40, 160, n),
        "udp_count":       np.random.randint(0, 20, n),
        "syn_count":       np.random.randint(0, 10, n),
        "ack_count":       np.random.randint(30, 150, n),
        "rst_count":       np.random.randint(0, 5, n),
        "fin_count":       np.random.randint(0, 5, n),
    })


def train_model(tmp_path):
    """Train a model and return paths to model and meta files."""
    from sklearn.ensemble import IsolationForest
    df = make_normal_features(50)
    ff = str(tmp_path / "features.csv")
    mf = str(tmp_path / "model.pkl")
    meta = str(tmp_path / "model_features.json")
    df.to_csv(ff, index=False)
    feature_cols = [c for c in df.columns if c != "window_start"]
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(df[feature_cols])
    joblib.dump(model, mf)
    with open(meta, "w") as f:
        json.dump(feature_cols, f)
    return ff, mf, meta


class TestAiDetector:

    def test_output_file_created(self, tmp_path):
        ff, mf, meta = train_model(tmp_path)
        af = str(tmp_path / "ai_results.csv")
        ai_main(input_file=ff, model_file=mf,
                features_meta_file=meta, output_file=af)
        assert os.path.exists(af)

    def test_output_has_correct_columns(self, tmp_path):
        ff, mf, meta = train_model(tmp_path)
        af = str(tmp_path / "ai_results.csv")
        ai_main(input_file=ff, model_file=mf,
                features_meta_file=meta, output_file=af)
        df = pd.read_csv(af)
        assert "ai_status" in df.columns
        assert "anomaly_score" in df.columns

    def test_status_values_are_valid(self, tmp_path):
        ff, mf, meta = train_model(tmp_path)
        af = str(tmp_path / "ai_results.csv")
        ai_main(input_file=ff, model_file=mf,
                features_meta_file=meta, output_file=af)
        df = pd.read_csv(af)
        assert set(df["ai_status"].unique()).issubset({"NORMAL", "ANOMALY"})

    def test_missing_model_exits(self, tmp_path):
        ff, mf, meta = train_model(tmp_path)
        af = str(tmp_path / "ai_results.csv")
        with pytest.raises(SystemExit):
            ai_main(input_file=ff, model_file="nonexistent.pkl",
                    features_meta_file=meta, output_file=af)

    def test_missing_meta_exits(self, tmp_path):
        ff, mf, meta = train_model(tmp_path)
        af = str(tmp_path / "ai_results.csv")
        with pytest.raises(SystemExit):
            ai_main(input_file=ff, model_file=mf,
                    features_meta_file="nonexistent.json", output_file=af)

    def test_normal_traffic_mostly_labeled_normal(self, tmp_path):
        ff, mf, meta = train_model(tmp_path)
        af = str(tmp_path / "ai_results.csv")
        ai_main(input_file=ff, model_file=mf,
                features_meta_file=meta, output_file=af)
        df = pd.read_csv(af)
        normal_pct = (df["ai_status"] == "NORMAL").mean()
        assert normal_pct >= 0.7


class TestHybridDetector:

    def test_output_file_created(self, tmp_path):
        ff, mf, meta = train_model(tmp_path)
        af = str(tmp_path / "ai_results.csv")
        rf = str(tmp_path / "rule_results.csv")
        hf = str(tmp_path / "hybrid_results.csv")
        ai_main(input_file=ff, model_file=mf,
                features_meta_file=meta, output_file=af)
        pd.DataFrame(columns=["Date", "Alert_Name", "Severity"]).to_csv(rf, index=False)
        hybrid_main(ai_output=af, rule_output=rf, hybrid_output=hf)
        assert os.path.exists(hf)

    def test_hybrid_contains_ai_columns(self, tmp_path):
        ff, mf, meta = train_model(tmp_path)
        af = str(tmp_path / "ai_results.csv")
        rf = str(tmp_path / "rule_results.csv")
        hf = str(tmp_path / "hybrid_results.csv")
        ai_main(input_file=ff, model_file=mf,
                features_meta_file=meta, output_file=af)
        pd.DataFrame(columns=["Date", "Alert_Name", "Severity"]).to_csv(rf, index=False)
        hybrid_main(ai_output=af, rule_output=rf, hybrid_output=hf)
        df = pd.read_csv(hf)
        assert "ai_status" in df.columns
        assert "anomaly_score" in df.columns

    def test_missing_ai_results_exits(self, tmp_path):
        rf = str(tmp_path / "rule_results.csv")
        hf = str(tmp_path / "hybrid_results.csv")
        pd.DataFrame(columns=["Date", "Alert_Name", "Severity"]).to_csv(rf, index=False)
        with pytest.raises(SystemExit):
            hybrid_main(ai_output="nonexistent.csv",
                        rule_output=rf, hybrid_output=hf)

    def test_missing_rule_results_uses_empty(self, tmp_path):
        ff, mf, meta = train_model(tmp_path)
        af = str(tmp_path / "ai_results.csv")
        hf = str(tmp_path / "hybrid_results.csv")
        ai_main(input_file=ff, model_file=mf,
                features_meta_file=meta, output_file=af)
        hybrid_main(ai_output=af,
                    rule_output="nonexistent.csv", hybrid_output=hf)
        assert os.path.exists(hf)