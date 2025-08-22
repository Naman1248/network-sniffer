#!/usr/bin/env python3
"""
Quick analyst CLI for packets.db

Examples:
  python3 analyze.py --db packets.db top-attackers --limit 10
  python3 analyze.py --db packets.db scan-types
  python3 analyze.py --db packets.db recent --minutes 15
  python3 analyze.py --db packets.db ports-by-src --src 192.168.80.1 --limit 20
"""

import argparse
import sqlite3
from datetime import datetime, timedelta

def connect(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def cmd_top_attackers(conn, limit: int):
    q = """
    SELECT src_ip, COUNT(*) AS cnt
    FROM alerts
    GROUP BY src_ip
    ORDER BY cnt DESC
    LIMIT ?;
    """
    cur = conn.execute(q, (limit,))
    print(f"\nTop {limit} attacking sources:")
    for r in cur:
        print(f"  {r['src_ip']:>16}  ->  {r['cnt']} alerts")

def cmd_scan_types(conn):
    q = """
    SELECT scan_type, COUNT(*) AS cnt
    FROM alerts
    GROUP BY scan_type
    ORDER BY cnt DESC;
    """
    cur = conn.execute(q)
    print("\nAlerts by scan type:")
    for r in cur:
        print(f"  {r['scan_type']:>10}  ->  {r['cnt']}")

def cmd_recent(conn, minutes: int):
    cutoff = datetime.utcnow().timestamp() - (minutes * 60)
    q = """
    SELECT ts_readable, src_ip, dst_ip, protocol, scan_type, dst_port, details
    FROM alerts
    WHERE ts >= ?
    ORDER BY ts DESC;
    """
    cur = conn.execute(q, (cutoff,))
    print(f"\nAlerts in the last {minutes} minute(s):")
    for r in cur:
        port = r["dst_port"] if r["dst_port"] is not None else "-"
        print(f"  [{r['ts_readable']}] {r['scan_type']:>9} {r['src_ip']} → {r['dst_ip']} proto={r['protocol']} port={port}  {r['details']}")

def cmd_ports_by_src(conn, src: str, limit: int):
    q = """
    SELECT dst_port, COUNT(*) AS cnt
    FROM alerts
    WHERE src_ip = ? AND dst_port IS NOT NULL
    GROUP BY dst_port
    ORDER BY cnt DESC
    LIMIT ?;
    """
    cur = conn.execute(q, (src, limit))
    print(f"\nMost targeted ports by {src}:")
    for r in cur:
        print(f"  port {str(r['dst_port']).rjust(5)}  ->  {r['cnt']} alerts")

def main():
    ap = argparse.ArgumentParser(description="Analyze alerts stored in packets.db")
    ap.add_argument("--db", default="packets.db", help="SQLite database path (default: packets.db)")

    sub = ap.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("top-attackers", help="List top N attacking sources")
    s1.add_argument("--limit", type=int, default=10)

    s2 = sub.add_parser("scan-types", help="Counts by scan type")

    s3 = sub.add_parser("recent", help="List alerts from the last N minutes")
    s3.add_argument("--minutes", type=int, default=10)

    s4 = sub.add_parser("ports-by-src", help="Top destination ports for a given source")
    s4.add_argument("--src", required=True, help="Source IP")
    s4.add_argument("--limit", type=int, default=20)

    args = ap.parse_args()
    conn = connect(args.db)

    if args.cmd == "top-attackers":
        cmd_top_attackers(conn, args.limit)
    elif args.cmd == "scan-types":
        cmd_scan_types(conn)
    elif args.cmd == "recent":
        cmd_recent(conn, args.minutes)
    elif args.cmd == "ports-by-src":
        cmd_ports_by_src(conn, args.src, args.limit)

if __name__ == "__main__":
    main()
