#!/usr/bin/env python3
"""
Lightweight IDS-style sniffer:
- Detects floods and port scans (UDP, SYN, FIN, Xmas, NULL)
- Prints live alerts with color
- Writes alerts to alerts.log
- Persists alerts to SQLite (packets.db) for later analysis
"""

import argparse
import signal
import sys
import time
import sqlite3
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP  # type: ignore

# =========================
# Colors (console only)
# =========================
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
DIM = "\033[2m"
RESET = "\033[0m"

# =========================
# Globals (filled in main)
# =========================
ARGS = None
DB = None
CUR = None
LOG_FH = None

# Sliding windows
packet_counts = defaultdict(deque)  # src_ip -> deque[timestamps]
port_scans = defaultdict(deque)     # src_ip -> deque[(port, ts, proto, scan_kind)]

# Summary counters
summary = {
    "Flood": 0,
    "UDP Scan": 0,
    "SYN Scan": 0,
    "FIN Scan": 0,
    "Xmas Scan": 0,
    "Null Scan": 0,
    "Other TCP": 0,
    "Other": 0,
}

# Basic rate-limiting so we don't spam duplicates every tick:
# (src, scan_type) -> last_alert_ts
last_alert_at = {}


# =========================
# Database / logging
# =========================
def init_db(path: str):
    global DB, CUR
    DB = sqlite3.connect(path, check_same_thread=False)
    DB.execute("PRAGMA journal_mode=WAL;")
    DB.execute("PRAGMA synchronous=NORMAL;")
    CUR = DB.cursor()
    CUR.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            ts REAL NOT NULL,
            ts_readable TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,     -- 'TCP' | 'UDP' | 'Other'
            scan_type TEXT NOT NULL,    -- 'Flood' | 'UDP Scan' | 'SYN Scan' | ...
            dst_port INTEGER,           -- nullable
            details TEXT                -- free-form JSON-ish text
        )
        """
    )
    CUR.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);")
    CUR.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);")
    CUR.execute("CREATE INDEX IF NOT EXISTS idx_alerts_scan ON alerts(scan_type);")
    DB.commit()


def init_log(path: str):
    global LOG_FH
    LOG_FH = open(path, "a", buffering=1, encoding="utf-8")


def write_log(line: str):
    if LOG_FH:
        LOG_FH.write(line.rstrip() + "\n")


def emit_alert(scan_type: str, src: str, dst: str, protocol: str, dst_port: int | None, details: str, color: str):
    """Print to console, append to alerts.log, insert into SQLite, bump counters."""
    # Basic per (src, scan_type) throttle
    now = time.time()
    key = (src, scan_type)
    if ARGS.ratelimit > 0:
        last = last_alert_at.get(key, 0)
        if now - last < ARGS.ratelimit:
            return
        last_alert_at[key] = now

    ts_readable = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
    line = f"{color}🔺 ALERT [{scan_type}] {src} → {dst} | proto={protocol} port={dst_port if dst_port is not None else '-'} | {details}{RESET}"
    print(line)
    write_log(f"{ts_readable} {scan_type} {src} -> {dst} proto={protocol} port={dst_port} details={details}")

    # DB
    CUR.execute(
        "INSERT INTO alerts(ts, ts_readable, src_ip, dst_ip, protocol, scan_type, dst_port, details) VALUES(?,?,?,?,?,?,?,?)",
        (now, ts_readable, src, dst, protocol, scan_type, dst_port, details),
    )
    DB.commit()

    # Summary
    summary[scan_type] = summary.get(scan_type, 0) + 1


# =========================
# Detection
# =========================
def detect_packet(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    now = time.time()
    length = len(pkt)

    protocol = "Other"
    dport: int | None = None

    # 1) Flood (by packet rate per source in last N seconds)
    window = ARGS.window
    packet_counts[src].append(now)
    # prune old
    dq = packet_counts[src]
    while dq and now - dq[0] > window:
        dq.popleft()

    if len(dq) > ARGS.flood_threshold:
        emit_alert(
            "Flood",
            src, dst, protocol="Mixed",
            dst_port=None,
            details=f"{len(dq)} pkts in {window}s",
            color=RED,
        )

    # 2) Port-scan detection (TCP/UDP) by unique dports hit per source in last N seconds
    scan_kind = None

    if TCP in pkt:
        protocol = "TCP"
        dport = int(pkt[TCP].dport)
        flags = int(pkt[TCP].flags)

        # Identify scan flavor
        if flags == 0x02:
            scan_kind = "SYN Scan"
        elif flags == 0x01:
            scan_kind = "FIN Scan"
        elif flags == 0x29:
            scan_kind = "Xmas Scan"
        elif flags == 0x00:
            scan_kind = "Null Scan"
        else:
            scan_kind = "Other TCP"

    elif UDP in pkt:
        protocol = "UDP"
        dport = int(pkt[UDP].dport)
        scan_kind = "UDP Scan"

    # Track ports only if TCP/UDP
    if scan_kind is not None and dport is not None:
        port_scans[src].append((dport, now, protocol, scan_kind))
        # prune
        pq = port_scans[src]
        while pq and now - pq[0][1] > window:
            pq.popleft()

        # Count unique ports in the current window
        unique_ports = sorted({p for p, t, _, _ in pq})
        if len(unique_ports) > ARGS.scan_threshold:
            examples = ", ".join(map(str, unique_ports[:10]))
            emit_alert(
                scan_kind,
                src, dst,
                protocol=protocol,
                dst_port=dport,
                details=f"{len(unique_ports)} ports in {window}s (e.g., {examples}{'...' if len(unique_ports) > 10 else ''})",
                color=YELLOW,
            )

    # Optional verbose packet line
    if ARGS.verbose:
        print(f"{DIM}{src} -> {dst} | Protocol: {protocol} | Length: {length}{RESET}")


# =========================
# Graceful shutdown
# =========================
def print_summary():
    print("\n" + GREEN + "▤▤ Detection Summary ▤▤" + RESET)
    keys = ["Flood", "UDP Scan", "SYN Scan", "FIN Scan", "Xmas Scan", "Null Scan", "Other TCP", "Other"]
    for k in keys:
        print(f"{k:>10}: {summary.get(k, 0)}")
    print(GREEN + "========================" + RESET)
    print(GREEN + f"✔ Full log saved in alerts.log" + RESET)


def on_sigint(_sig=None, _frame=None):
    print_summary()
    try:
        if LOG_FH:
            LOG_FH.flush()
            LOG_FH.close()
        if DB:
            DB.commit()
            DB.close()
    finally:
        sys.exit(0)


# =========================
# Main
# =========================
def parse_args():
    p = argparse.ArgumentParser(description="Mini IDS sniffer with SQLite logging")
    p.add_argument("--iface", default="eth0", help="Interface to sniff on (default: eth0)")
    p.add_argument("--filter", default="tcp or udp", help="BPF filter (default: 'tcp or udp')")
    p.add_argument("--window", type=int, default=10, help="Sliding window (seconds) (default: 10)")
    p.add_argument("--flood-threshold", type=int, default=100, help="Packets per source in window to flag flood (default: 100)")
    p.add_argument("--scan-threshold", type=int, default=10, help="Unique ports per source in window to flag scan (default: 10)")
    p.add_argument("--db", default="packets.db", help="SQLite database path (default: packets.db)")
    p.add_argument("--log", default="alerts.log", help="Alerts log file (default: alerts.log)")
    p.add_argument("--ratelimit", type=int, default=3, help="Seconds to suppress duplicate (src, scan_type) alerts (default: 3)")
    p.add_argument("--verbose", action="store_true", help="Print every packet line (dim)")
    return p.parse_args()


def main():
    global ARGS
    ARGS = parse_args()

    init_db(ARGS.db)
    init_log(ARGS.log)

    print(BLUE + f"[+] Sniffing on {ARGS.iface} with filter '{ARGS.filter}'" + RESET)
    print(BLUE + f"[+] Window={ARGS.window}s  Flood>{ARGS.flood_threshold}  Scan>{ARGS.scan_threshold}" + RESET)
    print(BLUE + f"[+] Logging to {ARGS.log} & {ARGS.db}" + RESET)

    signal.signal(signal.SIGINT, on_sigint)
    signal.signal(signal.SIGTERM, on_sigint)

    sniff(prn=detect_packet, store=False, iface=ARGS.iface, filter=ARGS.filter)


if __name__ == "__main__":
    main()

