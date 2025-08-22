# network-sniffer
A Python-based network traffic sniffer and intrusion detection tool. Detects floods, port scans (SYN, FIN, Null, Xmas, UDP), logs alerts into SQLite, and provides analysis with charts and reports.
# 🚨 Network Sniffer & Intrusion Detection Tool

## 📌 Overview
This project is a custom **Network Intrusion Detection System (IDS)** built in Python.  
It captures packets in real-time, detects different types of scans and floods, logs events, and provides analysis via CLI and charts.

---

## ✅ Features
- Sniffs live TCP/UDP traffic from a chosen interface.
- Detects scans: SYN, FIN, Xmas, Null, UDP.
- Detects flood attacks (packet floods above threshold).
- Logs alerts to both `alerts.log` and `packets.db` (SQLite).
- Provides CLI analysis (`analyze.py`).
- Generates visual charts (`charts.py`).

---

## 🛠 Tools & Dependencies
- **Python 3**
- **Scapy** (packet sniffing)
- **SQLite3** (database logging)
- **Matplotlib** (charting)
- **Nmap** (for testing scans)
- **Hping3** (for flood simulation)

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## ⚙️ Usage

### Run Sniffer
```bash
sudo -E python3 sniffer.py --iface eth0 --filter "tcp or udp" --window 10 --flood-threshold 100 --scan-threshold 10 --db packets.db --log alerts.log --verbose
```

### Run Analysis
```bash
python3 analyze.py --db packets.db scan-types
python3 analyze.py --db packets.db top-attackers --limit 5
python3 analyze.py --db packets.db recent --minutes 15
```

### Generate Charts
```bash
python3 charts.py --db packets.db --top 10
```
Outputs:
- `alerts_by_type.png`
- `top_sources.png`
- `alerts_timeline.png`

---

## 📊 Example Results
- Detected SYN, FIN, Xmas, Null, and UDP scans.
- Flood attacks identified with >2000 packets in 10s.
- Attacker `192.168.80.129` generated **63 alerts**.
- Charts show attack patterns clearly.

---

## 📌 Folder Structure
```
network-sniffer/
│── sniffer.py          # Packet sniffer & detector
│── analyze.py          # CLI analysis tool
│── charts.py           # Visualization tool
│── alerts.log          # Log file
│── packets.db          # SQLite DB storing alerts
│── requirements.txt    # Dependencies
│── README.md           # Documentation
```

---

## 🚀 Future Work
- Add anomaly detection using ML.
- Create web dashboard for live monitoring.
- Multi-node IDS for large networks.

---
Made with ❤️ for Cybersecurity Project
