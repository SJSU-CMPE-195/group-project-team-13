"""
Unit tests for Model_Pipeline/rule_detector.py
Tests every rule at boundary conditions using synthetic feature rows.
"""
import pytest
import pandas as pd
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from Model_Pipeline.rule_detector import RuleDetector


def make_row(**kwargs):
    """Return a default-normal feature row with optional overrides."""
    defaults = {
        "window_start": "2024-01-01 00:00:00",
        "packet_count": 100,
        "unique_src_ips": 2,
        "unique_dst_ips": 2,
        "unique_dst_ports": 5,
        "unique_src_ports": 10,
        "avg_packet_len": 200.0,
        "max_packet_len": 512,
        "min_packet_len": 40,
        "tcp_count": 90,
        "udp_count": 5,
        "syn_count": 5,
        "ack_count": 80,
        "rst_count": 2,
        "fin_count": 3,
    }
    defaults.update(kwargs)
    return pd.Series(defaults)


def get_alerts(tmp_path, row):
    """Run evaluate() and return the list of alert names triggered."""
    output = str(tmp_path / "rule_results.csv")
    detector = RuleDetector(output_file=output)
    detector.evaluate(row)
    df = pd.read_csv(output)
    return df["Alert_Name"].tolist()


class TestPortScanRule:

    def test_port_scan_triggered_above_threshold(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row(unique_dst_ports=21))
        assert "Potential Port Scan" in alerts

    def test_port_scan_not_triggered_at_threshold(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row(unique_dst_ports=20))
        assert "Potential Port Scan" not in alerts

    def test_port_scan_not_triggered_below_threshold(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row(unique_dst_ports=5))
        assert "Potential Port Scan" not in alerts


class TestSynFloodRule:

    def test_syn_flood_triggered(self, tmp_path):
        # 90 SYN out of 100 packets = 90% ratio, above 80% threshold
        alerts = get_alerts(tmp_path, make_row(syn_count=90, packet_count=100))
        assert "SYN Flood Detected" in alerts

    def test_syn_flood_not_triggered_low_ratio(self, tmp_path):
        # 40 SYN out of 100 = 40% — below threshold
        alerts = get_alerts(tmp_path, make_row(syn_count=40, packet_count=100))
        assert "SYN Flood Detected" not in alerts

    def test_syn_flood_not_triggered_small_window(self, tmp_path):
        # High ratio but packet_count <= 50 — rule requires > 50
        alerts = get_alerts(tmp_path, make_row(syn_count=45, packet_count=50))
        assert "SYN Flood Detected" not in alerts

    def test_syn_flood_boundary_packet_count(self, tmp_path):
        # 51 packets, 90% SYN — should trigger
        alerts = get_alerts(tmp_path, make_row(syn_count=46, packet_count=51))
        assert "SYN Flood Detected" in alerts


class TestUdpFloodRule:

    def test_udp_flood_triggered(self, tmp_path):
        # 95 UDP out of 100 = 95% — above 90% threshold
        alerts = get_alerts(tmp_path, make_row(udp_count=95, packet_count=100))
        assert "UDP Flooding" in alerts

    def test_udp_flood_not_triggered_below_threshold(self, tmp_path):
        # 85 UDP out of 100 = 85% — below threshold
        alerts = get_alerts(tmp_path, make_row(udp_count=85, packet_count=100))
        assert "UDP Flooding" not in alerts


class TestNetworkSweepRule:

    def test_sweep_triggered(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row(unique_dst_ips=16))
        assert "Network Sweep/Discovery" in alerts

    def test_sweep_not_triggered_at_threshold(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row(unique_dst_ips=15))
        assert "Network Sweep/Discovery" not in alerts


class TestLargePacketRule:

    def test_large_packet_triggered(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row(avg_packet_len=1201))
        assert "Large Packet Volume" in alerts

    def test_large_packet_not_triggered(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row(avg_packet_len=1200))
        assert "Large Packet Volume" not in alerts


class TestHighVolumeRule:

    def test_high_volume_triggered(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row(packet_count=5001))
        assert "High Traffic Volume Burst" in alerts

    def test_high_volume_not_triggered(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row(packet_count=5000))
        assert "High Traffic Volume Burst" not in alerts


class TestNetworkSilentRule:

    def test_silent_triggered(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row(packet_count=4))
        assert "Network Silent / Possible Outage" in alerts

    def test_silent_not_triggered(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row(packet_count=5))
        assert "Network Silent / Possible Outage" not in alerts


class TestNormalTraffic:

    def test_no_alerts_on_normal_traffic(self, tmp_path):
        alerts = get_alerts(tmp_path, make_row())
        assert alerts == []

    def test_multiple_rules_can_fire_simultaneously(self, tmp_path):
        # Port scan + network sweep at the same time
        row = make_row(unique_dst_ports=25, unique_dst_ips=20)
        alerts = get_alerts(tmp_path, row)
        assert "Potential Port Scan" in alerts
        assert "Network Sweep/Discovery" in alerts

    def test_output_file_created(self, tmp_path):
        output = str(tmp_path / "rule_results.csv")
        RuleDetector(output_file=output)
        assert os.path.exists(output)

    def test_output_has_correct_columns(self, tmp_path):
        output = str(tmp_path / "rule_results.csv")
        detector = RuleDetector(output_file=output)
        detector.evaluate(make_row(unique_dst_ports=25))
        df = pd.read_csv(output)
        assert "Date" in df.columns
        assert "Alert_Name" in df.columns
        assert "Severity" in df.columns
