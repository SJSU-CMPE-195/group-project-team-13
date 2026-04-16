import pandas as pd
import os
from datetime import datetime


class RuleDetector:
    """
    Threshold-based detector that checks each feature window against a set of
    hand-tuned rules. Unlike the AI model, these rules are fully interpretable —
    you can read exactly why an alert fired. Trade-off is that you have to manually
    tune the thresholds and the rules won't catch attacks that don't match a known pattern.
    """

    def __init__(self, output_file='rule_results.csv'):
        self.output_file = output_file

        # Create the output file up front so log_alert can always append to it.
        if not os.path.isfile(self.output_file):
            pd.DataFrame(columns=['Date', 'Alert_Name', 'Severity']).to_csv(self.output_file, index=False)

    def log_alert(self, name, severity):
        """Appends a single alert row to the CSV and prints it live."""
        new_alert = {
            'Date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'Alert_Name': name,
            'Severity': severity
        }

        # Append instead of rewriting the whole file for every alert.
        df_alert = pd.DataFrame([new_alert])
        df_alert.to_csv(self.output_file, mode='a', header=False, index=False)

        print(f"!!! [RULE ALERT] {severity}: {name}")

    def evaluate(self, feature_row):
        """
        Runs every rule against a single feature window (one row from features.csv).
        Multiple rules can fire on the same window — each gets its own alert row.
        """

        # Rule 1: too many unique destination ports in one window usually means port scanning.
        # Normal hosts use only a handful of ports; scanners hit many more.
        if feature_row['unique_dst_ports'] > 20:
            self.log_alert("Potential Port Scan", "High")

        # Rule 2: most packets are SYN with no matching ACKs, which looks like a SYN flood.
        # We also require at least 50 packets so tiny samples do not trigger it.
        syn_ratio = feature_row['syn_count'] / feature_row['packet_count'] if feature_row['packet_count'] > 0 else 0
        if syn_ratio > 0.8 and feature_row['packet_count'] > 50:
            self.log_alert("SYN Flood Detected", "High")

        # Rule 3: almost all traffic is UDP, which can point to flooding or DNS abuse.
        # The 90% threshold leaves room for networks that normally use a lot of UDP.
        if feature_row['udp_count'] > (feature_row['packet_count'] * 0.9):
            self.log_alert("UDP Flooding", "Medium")

        # Rule 4: talking to lots of different hosts in one window suggests a sweep.
        if feature_row['unique_dst_ips'] > 15:
            self.log_alert("Network Sweep/Discovery", "Medium")

        # Rule 5: unusually large packets can point to bulk transfer or MTU trouble.
        if feature_row['avg_packet_len'] > 1200:
            self.log_alert("Large Packet Volume", "Low")

        # Rule 6: an extremely high packet count in one window is often a burst.
        if feature_row['packet_count'] > 5000:
            self.log_alert("High Traffic Volume Burst", "Medium")

        # Rule 7: almost no traffic can mean the interface dropped, the cable was unplugged,
        # or something upstream is blocking traffic.
        if feature_row['packet_count'] < 5:
            self.log_alert("Network Silent / Possible Outage", "Low")
