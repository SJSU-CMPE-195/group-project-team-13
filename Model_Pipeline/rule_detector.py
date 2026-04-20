import pandas as pd
import os
from datetime import datetime

class RuleDetector:
    def __init__(self, output_file='rule_results.csv'):
        self.output_file = output_file

        if not os.path.isfile(self.output_file):
            pd.DataFrame(columns=['Date', 'Alert_Name', 'Severity', 'Source_IP', 'Window_Start']).to_csv(self.output_file, index=False)

    def log_alert(self, name, severity, source_ip='Unknown', window_start=''):
        new_alert = {
            'Date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'Alert_Name': name,
            'Severity': severity,
            'Source_IP': source_ip,
            'Window_Start': window_start
        }
        df_alert = pd.DataFrame([new_alert])
        df_alert.to_csv(self.output_file, mode='a', header=False, index=False)
        print(f"!!! [RULE ALERT] {severity}: {name} from {source_ip}")

    def evaluate(self, feature_row):
        source_ip = str(feature_row.get('top_src_ip', 'Unknown'))
        window_start = str(feature_row.get('window_start', ''))

        # rule 1: port scan — hitting many different destination ports
        if feature_row['unique_dst_ports'] > 50:
            self.log_alert("Potential Port Scan", "High", source_ip, window_start)

        # rule 2: SYN flood — mostly SYN packets with high volume
        syn_ratio = feature_row['syn_count'] / feature_row['packet_count'] if feature_row['packet_count'] > 0 else 0
        if syn_ratio > 0.8 and feature_row['packet_count'] > 200:
            self.log_alert("SYN Flood Detected", "High", source_ip, window_start)

        # rule 3: UDP flood — nearly all traffic is UDP at high volume
        if feature_row['udp_count'] > (feature_row['packet_count'] * 0.95) and feature_row['packet_count'] > 100:
            self.log_alert("UDP Flooding", "Medium", source_ip, window_start)

        # rule 4: network sweep — scanning many different destination IPs
        if feature_row['unique_dst_ips'] > 30:
            self.log_alert("Network Sweep/Discovery", "Medium", source_ip, window_start)

        # rule 5: large packets — possible data exfiltration
        if feature_row['avg_packet_len'] > 1400:
            self.log_alert("Large Packet Volume", "Low", source_ip, window_start)

        # rule 6: traffic burst — extremely high packet count in one window
        if feature_row['packet_count'] > 5000:
            self.log_alert("High Traffic Volume Burst", "Medium", source_ip, window_start)

        # rule 7: ICMP flood — ping flood attack
        if feature_row.get('icmp_count', 0) > 500:
            self.log_alert("ICMP Flood (Ping Flood)", "High", source_ip, window_start)

        # rule 8: ARP spoofing — excessive ARP replies on the network
        if feature_row.get('arp_count', 0) > 100:
            self.log_alert("ARP Spoofing Detected", "High", source_ip, window_start)

        # rule 9: SSH brute force — many connection attempts to port 22
        if feature_row.get('ssh_attempts', 0) > 30:
            self.log_alert("SSH Brute Force Attack", "High", source_ip, window_start)

        # rule 10: suspicious DNS activity — unusually high DNS traffic
        if feature_row.get('dns_count', 0) > 200:
            self.log_alert("Suspicious DNS Activity", "Medium", source_ip, window_start)

        # rule 11: Slowloris — many HTTP SYN connections with very few completions
        if feature_row.get('http_syn_count', 0) > 20 and feature_row.get('fin_count', 0) < 3:
            self.log_alert("Slowloris / HTTP Flood", "High", source_ip, window_start)
