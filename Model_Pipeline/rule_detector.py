import pandas as pd
import os
from datetime import datetime

class RuleDetector:
    def __init__(self, output_file='rule_results.csv'):
        self.output_file = output_file

        # make the file if it doesn't exist yet so we don't crash later
        if not os.path.isfile(self.output_file):
            pd.DataFrame(columns=['Date', 'Alert_Name', 'Severity']).to_csv(self.output_file, index=False)

    def log_alert(self, name, severity):
        # build one row for the alert we just found
        new_alert = {
            'Date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'Alert_Name': name,
            'Severity': severity
        }

        # add it to the csv without rewriting the whole file
        df_alert = pd.DataFrame([new_alert])
        df_alert.to_csv(self.output_file, mode='a', header=False, index=False)

        # also print it so we see it live in the console
        print(f"!!! [RULE ALERT] {severity}: {name}")

    def evaluate(self, feature_row):

        # rule 1: too many destination ports → probably port scanning
        if feature_row['unique_dst_ports'] > 20:
            self.log_alert("Potential Port Scan", "High")

        # rule 2: lots of SYN packets compared to total traffic → could be SYN flood
        syn_ratio = feature_row['syn_count'] / feature_row['packet_count'] if feature_row['packet_count'] > 0 else 0
        if syn_ratio > 0.8 and feature_row['packet_count'] > 50:
            self.log_alert("SYN Flood Detected", "High")

        # rule 3: almost everything is UDP → could be UDP flood/spam
        if feature_row['udp_count'] > (feature_row['packet_count'] * 0.9):
            self.log_alert("UDP Flooding", "Medium")

        # rule 4: talking to a lot of different destination IPs → looks like a sweep
        if feature_row['unique_dst_ips'] > 15:
            self.log_alert("Network Sweep/Discovery", "Medium")

        # rule 5: packets are unusually large on average → could be data exfiltration or weird traffic
        if feature_row['avg_packet_len'] > 1200:
            self.log_alert("Large Packet Volume", "Low")

        # rule 6: crazy high number of packets in a short time → traffic spike
        if feature_row['packet_count'] > 5000:
            self.log_alert("High Traffic Volume Burst", "Medium")

        # rule 7: basically no traffic → maybe network is down or something stopped working
        if feature_row['packet_count'] < 5:
            self.log_alert("Network Silent / Possible Outage", "Low")
