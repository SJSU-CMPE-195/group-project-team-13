import csv
import time
from scapy.all import sniff, IP, TCP, UDP

OUTPUT_FILE = "packets.csv"
INTERFACE = "eth0"

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
    # Overwrite file every run so dataset starts fresh
    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)


def process_packet(packet):
    if IP not in packet:
        return

    timestamp = time.time()
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_len = len(packet)

    src_port = 0
    dst_port = 0
    protocol = "OTHER"
    tcp_flags = ""

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = "TCP"
        tcp_flags = str(packet[TCP].flags)

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = "UDP"

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

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        store=False
    )


This program is run on the Raspberry Pi: 
I used these commands

cd ~/languard
source venv/bin/activate
sudo venv/bin/python capture_to_csv.py
