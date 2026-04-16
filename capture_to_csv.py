import csv
import time
from scapy.all import sniff, IP, TCP, UDP

# Captured packet metadata is written here.
OUTPUT_FILE = "packets.csv"

# Set this to the network interface on your LAN.
# On a Pi it is often eth0 or wlan0.
INTERFACE = "eth0"

# Column order for the CSV. Keep this in sync with process_packet.
header = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_len",
    "tcp_flags"
]


def ensure_header():
    """
    Start each run with a clean CSV and a fresh header row.
    That keeps the file from growing forever and gives extract_features.py
    a predictable input file.
    """
    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)


def process_packet(packet):
    """
    Scapy calls this for every packet on the interface.
    We keep IP traffic, skip the rest, and store metadata instead of payloads.
    """
    # Ignore traffic that is not carrying IP data.
    if IP not in packet:
        return

    timestamp = time.time()
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_len = len(packet)

    # Default transport-layer values for packets that are not TCP or UDP.
    src_port = 0
    dst_port = 0
    protocol = "OTHER"
    tcp_flags = ""

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = "TCP"
        tcp_flags = str(packet[TCP].flags)  # For example, "SA" means SYN+ACK.

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = "UDP"
        # UDP does not use flags, so tcp_flags stays empty.

    # Write one row per packet instead of buffering everything in memory.
    with open(OUTPUT_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            packet_len,
            tcp_flags
        ])


if __name__ == "__main__":
    ensure_header()

    print("Starting packet capture on interface:", INTERFACE)
    print("Saving traffic metadata to:", OUTPUT_FILE)
    print("Press CTRL+C to stop capture\n")

    # store=False keeps Scapy from holding packets in RAM.
    sniff(
        iface=INTERFACE,
        prn=process_packet,
        store=False
    )
