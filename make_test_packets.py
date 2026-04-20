import pandas as pd
import time

rows = []
base_time = time.time()

# Generate 100 packets all within the same 15 second window
for i in range(100):
    rows.append({
        'timestamp': base_time + (i * 0.1),  # 0.1 second apart, all in same window
        'src_ip': '192.168.10.10',
        'dst_ip': '192.168.10.20',
        'src_port': 12345,
        'dst_port': i + 1,  # 100 unique destination ports
        'protocol': 'TCP',
        'tcp_flags': 'S',
        'packet_len': 60
    })

pd.DataFrame(rows).to_csv('packets.csv', index=False)
print('Done - created port scan traffic')