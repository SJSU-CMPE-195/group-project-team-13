"""
Integration tests for the LANGuard pipeline.
"""
import pytest
import pandas as pd
import numpy as np
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from Model_Pipeline.rule_detector import RuleDetector
from Model_Pipeline.extract_features import main as extract_main


def run_extract(packets_path, features_path):
    extract_main(input_file=packets_path, output_file=features_path)


def make_normal_packets(n=20, base_ts=1700000000.0):
    rows = []
    for i in range(n):
        rows.append([base_ts + i * 0.1, "192.168.1.10", "192.168.1.20",
                     50000 + (i % 3), 80, "TCP", 128, "A"])
    return rows


def make_scan_packets(n=30, base_ts=1700000000.0):
    rows = []
    for i in range(n):
        rows.append([base_ts + i * 0.05, "192.168.1.10", "192.168.1.20",
                     40000 + i, 1000 + i, "TCP", 44, "S"])
    return rows


def make_packets_csv(path, rows):
    pd.DataFrame(rows, columns=[
        "timestamp", "src_ip", "dst_ip", "src_port",
        "dst_port", "protocol", "packet_len", "tcp_flags"
    ]).to_csv(path, index=False)


class TestPipelineIntegration:

    def test_extract_then_rule_detect_normal(self, tmp_path):
        pf = str(tmp_path / "packets.csv")
        ff = str(tmp_path / "features.csv")
        rf = str(tmp_path / "rule_results.csv")
        make_packets_csv(pf, make_normal_packets(20))
        run_extract(pf, ff)
        assert os.path.exists(ff)
        features_df = pd.read_csv(ff)
        assert len(features_df) > 0
        detector = RuleDetector(output_file=rf)
        for _, row in features_df.iterrows():
            detector.evaluate(row)
        alerts_df = pd.read_csv(rf)
        high_alerts = alerts_df[alerts_df["Severity"] == "High"]
        assert len(high_alerts) == 0

    def test_extract_then_rule_detect_port_scan(self, tmp_path):
        pf = str(tmp_path / "packets.csv")
        ff = str(tmp_path / "features.csv")
        rf = str(tmp_path / "rule_results.csv")
        make_packets_csv(pf, make_scan_packets(30))
        run_extract(pf, ff)
        features_df = pd.read_csv(ff)
        detector = RuleDetector(output_file=rf)
        for _, row in features_df.iterrows():
            detector.evaluate(row)
        alerts_df = pd.read_csv(rf)
        assert "Potential Port Scan" in alerts_df["Alert_Name"].tolist()

    def test_multiple_windows_processed(self, tmp_path):
        pf = str(tmp_path / "packets.csv")
        ff = str(tmp_path / "features.csv")
        base = 1700000000.0
        rows = make_normal_packets(10, base_ts=base)
        rows += make_normal_packets(10, base_ts=base + 20)
        make_packets_csv(pf, rows)
        run_extract(pf, ff)
        df = pd.read_csv(ff)
        assert len(df) == 2

    def test_rule_detector_appends_multiple_alerts(self, tmp_path):
        rf = str(tmp_path / "rule_results.csv")
        detector = RuleDetector(output_file=rf)
        row1 = pd.Series({"packet_count": 100, "unique_dst_ports": 25,
                          "unique_dst_ips": 3, "syn_count": 5,
                          "udp_count": 5, "avg_packet_len": 200})
        row2 = pd.Series({"packet_count": 100, "unique_dst_ports": 30,
                          "unique_dst_ips": 3, "syn_count": 5,
                          "udp_count": 5, "avg_packet_len": 200})
        detector.evaluate(row1)
        detector.evaluate(row2)
        df = pd.read_csv(rf)
        assert len(df) == 2

    def test_syn_flood_detected_end_to_end(self, tmp_path):
        pf = str(tmp_path / "packets.csv")
        ff = str(tmp_path / "features.csv")
        rf = str(tmp_path / "rule_results.csv")
        base = 1700000000.0
        rows = []
        for i in range(90):
            rows.append([base + i * 0.005, "10.0.0.1", "10.0.0.2",
                         40000 + i, 80, "TCP", 44, "S"])
        for i in range(10):
            rows.append([base + 0.5 + i * 0.005, "10.0.0.1", "10.0.0.2",
                         50000, 80, "TCP", 128, "A"])
        make_packets_csv(pf, rows)
        run_extract(pf, ff)
        features_df = pd.read_csv(ff)
        detector = RuleDetector(output_file=rf)
        for _, row in features_df.iterrows():
            detector.evaluate(row)
        alerts_df = pd.read_csv(rf)
        assert "SYN Flood Detected" in alerts_df["Alert_Name"].tolist()