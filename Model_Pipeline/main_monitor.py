import pandas as pd
import time
import os
from ai_detector import AIDetector
from rule_detector import RuleDetector

# files
RAW_DATA = "local_packets.csv"
FEATURED_DATA = "local_packets_to_featured.csv"


def extract_live_features():
    if not os.path.exists(RAW_DATA) or os.stat(RAW_DATA).st_size == 0:
        return None

    try:
        df = pd.read_csv(RAW_DATA)
        # convert timestamp and group into one 15s window
        df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")

        # calculate features
        features = {
            "packet_count": len(df),
            "unique_src_ips": df["src_ip"].nunique(),
            "unique_dst_ips": df["dst_ip"].nunique(),
            "unique_dst_ports": df["dst_port"].nunique(),
            "avg_packet_len": df["packet_len"].mean(),
            "max_packet_len": df["packet_len"].max(),
            "tcp_count": (df["protocol"] == "TCP").sum(),
            "udp_count": (df["protocol"] == "UDP").sum(),
            "syn_count": df["tcp_flags"].str.contains("S", na=False).sum()
        }

        # erase the raw file after extraction so we dont process
        # the same packets twice in the next loop
        with open(RAW_DATA, "w") as f:
            f.write("timestamp,src_ip,dst_ip,src_port,dst_port,protocol,packet_len,tcp_flags\n")

        return pd.Series(features)
    except Exception as e:
        print(f"Extraction Error: {e}")
        return None


def main():
    ai = AIDetector()
    rules = RuleDetector()

    print("[*] Languard System Live: Monitoring Network Heartbeat...")

    while True:
        # 1. extract features
        current_features = extract_live_features()

        if current_features is not None and current_features['packet_count'] > 5:
            # 2. rule detection function
            rules.evaluate(current_features)

            # 3. AI scoring
            raw_score = ai.get_score(current_features)

            # 4. output
            status = " NORMAL ACTIVITY " if raw_score > -0.1 else " POSSIBLE ANOMALY "
            timestamp = time.strftime('%H:%M:%S')
            print(f"[{timestamp}] Pkts: {current_features['packet_count']} | Score: {raw_score:.4f} | {status}")

        # wait for the next 15-second window to fill up from capture_to_csv.py
        time.sleep(15)


if __name__ == "__main__":
    main()