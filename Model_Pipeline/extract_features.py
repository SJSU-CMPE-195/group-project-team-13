import pandas as pd
import numpy as np

INPUT_FILE = "packets.csv"
OUTPUT_FILE = "features.csv"
WINDOW_SIZE_SECONDS = 15
MIN_PACKETS_PER_WINDOW = 3


def main(input_file=INPUT_FILE, output_file=OUTPUT_FILE):
    print(f"[LANGuard] Reading packets from {input_file}...")
    try:
        df = pd.read_csv(input_file)
    except FileNotFoundError:
        print(f"[LANGuard] {input_file} not found")
        exit(1)

    if df.empty:
        print("[LANGuard] No packets found")
        exit(1)

    print(f"[LANGuard] Processing {len(df)} packets...")

    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
    df['window_start'] = pd.to_datetime(
        (df['timestamp'].astype(np.int64) // (WINDOW_SIZE_SECONDS * 1_000_000_000)) * WINDOW_SIZE_SECONDS,
        unit='s'
    )

    features_list = []

    for window, group in df.groupby('window_start'):
        if len(group) < MIN_PACKETS_PER_WINDOW:
            continue

        tcp_packets = len(group[group['protocol'] == 'TCP'])
        udp_packets = len(group[group['protocol'] == 'UDP'])

        syn_count = sum(group['tcp_flags'].astype(str).str.contains('S', na=False))
        ack_count = sum(group['tcp_flags'].astype(str).str.contains('A', na=False))
        rst_count = sum(group['tcp_flags'].astype(str).str.contains('R', na=False))
        fin_count = sum(group['tcp_flags'].astype(str).str.contains('F', na=False))

        feature_row = {
            'window_start': window,
            'packet_count': len(group),
            'unique_src_ips': group['src_ip'].nunique(),
            'unique_dst_ips': group['dst_ip'].nunique(),
            'unique_src_ports': group['src_port'].nunique(),
            'unique_dst_ports': group['dst_port'].nunique(),
            'tcp_count': tcp_packets,
            'udp_count': udp_packets,
            'syn_count': syn_count,
            'ack_count': ack_count,
            'rst_count': rst_count,
            'fin_count': fin_count,
            'avg_packet_len': group['packet_len'].mean(),
            'max_packet_len': group['packet_len'].max(),
            'min_packet_len': group['packet_len'].min(),
        }
        features_list.append(feature_row)

    if not features_list:
        print("[LANGuard] No valid windows")
        exit(1)

    features_df = pd.DataFrame(features_list)
    features_df.to_csv(output_file, index=False)
    print(f"[LANGuard] Extracted {len(features_df)} windows to {output_file}")
    return features_df


if __name__ == "__main__":
    main()