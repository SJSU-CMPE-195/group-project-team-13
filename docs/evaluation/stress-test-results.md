# Stress Test Results

### Test Configuration
- Tool: hping3 (flood testing), nmap (port scan simulation)
- Duration: ~60 seconds per attack type
- Attack Types: SYN flood, UDP flood, ICMP flood, HTTP flood, port scan
- Target: LANGuard node — Victim Computer (192.168.10.20)
- Attacker: Kali Linux machine on same network
- Network: Isolated test network (192.168.10.0/24)
- Detection Pipeline Interval: 120 seconds
### Results
| Metric | Value |
|--------|-------|
| Total Alerts Generated | 35 |
| Unique Rule Types Triggered | 6 / 7 |
| CPU Usage Under Load | ~7% |
| Memory Used | 5170 MB / 16215 MB (32%) |
| System Crashes | 0 |
| Dashboard Availability | 100% |

### Alerts Breakdown
| Alert Type | Severity | Count |
|------------|----------|-------|
| High Traffic Volume Burst | Medium | 14 |
| SYN Flood Detected | High | 6 |
| Slowloris / HTTP Flood | High | 5 |
| Suspicious DNS Activity | Medium | 4 |
| UDP Flooding | Medium | 4 |
| Potential Port Scan | High | 2 |
### Observations
- All attack types were successfully detected
- SYN flood triggered HIGH severity alert within one pipeline cycle
- Flask dashboard remained accessible throughout all tests
### Bottlenecks Identified
- Pi 5 handled all attack types with only 7% CPU usage
- 16GB RAM provided significant headroom (only 32% used)
- Sustained packet floods above ~1000 pkt/sec
### What Would Be Optimized in Production
- Reduce pipeline interval to 30 seconds for faster detection its at 2 minutes 
- Implement real-time streaming detection for HIGH severity events
- Add webhook/email alerting on HIGH severity detections


### Test 2 — Multi-Vector Concurrent Attack (Final Stress Test)
- Tool: hping3 + nmap (simultaneous)
- Duration: 5 minutes sustained
- Attack Types: SYN flood + UDP flood + ICMP flood + full port scan (concurrent)
- Target: Victim machine (192.168.10.20)
- Monitored by: LANGuard on Raspberry Pi 5 (192.168.10.30)
### Final Results
| Metric | Value |
|--------|-------|
| Total Alerts Generated | 75 |
| Unique Rule Types Triggered | 6 / 7 |
| CPU Usage (idle) | 7% |
| CPU Usage (under attack) | 14.6% |
| Load Average Peak | 3.86 |
| Memory Used | 5254 MB / 16215 MB (32%) |
| System Crashes | 0 |
| Dashboard Availability | 100% |

### Alerts Breakdown (Final)
| Alert Type | Severity | Count |
|------------|----------|-------|
| Slowloris / HTTP Flood | High | 26 |
| Suspicious DNS Activity | Medium | 25 |
| High Traffic Volume Burst | Medium | 24 |
| SYN Flood Detected | High | 6 |
| UDP Flooding | Medium | 4 |
| Potential Port Scan | High | 2 |
### System Limits
- CPU doubled under concurrent multi-vector attack (7% → 14.6%) but remained stable
- Load average peaked at 3.86 on 4-core Pi 5 — approaching but not exceeding capacity
- System did not crash or degrade under sustained 5-minute flood
- Detection pipeline continued running throughout with no missed cycles
