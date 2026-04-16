"""
Unit tests for Model_Pipeline/extract_features.py
"""
import pytest
import pandas as pd
import numpy as np
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from Model_Pipeline.extract_features import main as extract_main


def run_extract(packets_path, features_path):
    extract_main(input_file=packets_path, output_file=features_path)


def make_packets(path, rows):
    pd.DataFrame(rows, columns=[
        "timestamp", "src_ip", "dst_ip", "src_port",
        "dst_port", "protocol", "packet_len", "tcp_flags"
    ]).to_csv(path, index=False)


def normal_packets(n=10, base_ts=1700000000.0):
    return [
        [base_ts + i * 0.1, "192.168.1.1", "192.168.1.2",
         50000 + i, 80, "TCP", 128, "A"]
        for i in range(n)
    ]


class TestExtractFeatures:

    def test_output_file_created(self, tmp_path):
        pf = str(tmp_path / "packets.csv")
        ff = str(tmp_path / "features.csv")
        make_packets(pf, normal_packets(10))
        run_extract(pf, ff)
        assert os.path.exists(ff)

    def test_output_has_required_columns(self, tmp_path):
        pf = str(tmp_path / "packets.csv")
        ff = str(tmp_path / "features.csv")
        make_packets(pf, normal_packets(10))
        run_extract(pf, ff)
        df = pd.read_csv(ff)
        for col in ["window_start", "packet_count", "unique_src_ips",
                    "unique_dst_ips", "unique_dst_ports", "unique_src_ports",
                    "tcp_count", "udp_count", "syn_count", "avg_packet_len"]:
            assert col in df.columns, f"Missing column: {col}"

    def test_windows_with_few_packets_filtered(self, tmp_path):
        pf = str(tmp_path / "packets.csv")
        ff = str(tmp_path / "features.csv")
        make_packets(pf, normal_packets(2))
        with pytest.raises(SystemExit):
            run_extract(pf, ff)

    def test_syn_packets_counted(self, tmp_path):
        pf = str(tmp_path / "packets.csv")
        ff = str(tmp_path / "features.csv")
        base = 1700000000.0
        rows = []
        for i in range(5):
            rows.append([base + i * 0.1, "10.0.0.1", "10.0.0.2",
                         1000 + i, 80, "TCP", 64, "S"])
        for i in range(5):
            rows.append([base + 0.5 + i * 0.1, "10.0.0.1", "10.0.0.2",
                         2000 + i, 80, "TCP", 64, "A"])
        make_packets(pf, rows)
        run_extract(pf, ff)
        df = pd.read_csv(ff)
        assert len(df) > 0
        assert df.iloc[0]["syn_count"] == 5

    def test_udp_packets_counted(self, tmp_path):
        pf = str(tmp_path / "packets.csv")
        ff = str(tmp_path / "features.csv")
        base = 1700000000.0
        rows = []
        for i in range(5):
            rows.append([base + i * 0.1, "10.0.0.1", "10.0.0.2",
                         1000 + i, 53, "UDP", 64, ""])
        for i in range(5):
            rows.append([base + 0.5 + i * 0.1, "10.0.0.1", "10.0.0.2",
                         2000 + i, 80, "TCP", 64, "A"])
        make_packets(pf, rows)
        run_extract(pf, ff)
        df = pd.read_csv(ff)
        assert len(df) > 0
        assert df.iloc[0]["udp_count"] == 5
        assert df.iloc[0]["tcp_count"] == 5

    def test_unique_dst_ports_counted(self, tmp_path):
        pf = str(tmp_path / "packets.csv")
        ff = str(tmp_path / "features.csv")
        base = 1700000000.0
        rows = [[base + i * 0.1, "10.0.0.1", "10.0.0.2",
                 50000, 80 + i, "TCP", 64, "S"]
                for i in range(10)]
        make_packets(pf, rows)
        run_extract(pf, ff)
        df = pd.read_csv(ff)
        assert len(df) > 0
        assert df.iloc[0]["unique_dst_ports"] == 10

    def test_avg_packet_len_correct(self, tmp_path):
        pf = str(tmp_path / "packets.csv")
        ff = str(tmp_path / "features.csv")
        base = 1700000000.0
        rows = [[base + i * 0.1, "10.0.0.1", "10.0.0.2",
                 1000, 80, "TCP", 100 * (i + 1), "A"]
                for i in range(4)]
        make_packets(pf, rows)
        run_extract(pf, ff)
        df = pd.read_csv(ff)
        assert len(df) > 0
        assert abs(df.iloc[0]["avg_packet_len"] - 250.0) < 0.01