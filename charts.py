#!/usr/bin/env python3
import argparse, sqlite3
import matplotlib.pyplot as plt

def q(conn, sql, args=()):
    return conn.execute(sql, args).fetchall()

def plot_bar(labels, values, title, outfile, xlabel="", ylabel="Count"):
    plt.figure()
    plt.bar(labels, values)
    plt.title(title); plt.xlabel(xlabel); plt.ylabel(ylabel)
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout(); plt.savefig(outfile); plt.close()

def plot_line(labels, values, title, outfile, xlabel="", ylabel="Count"):
    plt.figure()
    plt.plot(labels, values)
    plt.title(title); plt.xlabel(xlabel); plt.ylabel(ylabel)
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout(); plt.savefig(outfile); plt.close()

def main():
    ap = argparse.ArgumentParser(description="Make charts from packets.db")
    ap.add_argument("--db", default="packets.db")
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()
    conn = sqlite3.connect(args.db)

    # 1) By scan type
    rows = q(conn, "SELECT scan_type, COUNT(*) FROM alerts GROUP BY scan_type ORDER BY 2 DESC;")
    if rows:
        labels = [r[0] for r in rows]; counts = [r[1] for r in rows]
        plot_bar(labels, counts, "Alerts by Scan Type", "alerts_by_type.png", xlabel="Scan Type")

    # 2) Top sources
    rows = q(conn, "SELECT src_ip, COUNT(*) FROM alerts GROUP BY src_ip ORDER BY 2 DESC LIMIT ?;", (args.top,))
    if rows:
        labels = [r[0] for r in rows]; counts = [r[1] for r in rows]
        plot_bar(labels, counts, f"Top {args.top} Source IPs", "top_sources.png", xlabel="Source IP")

    # 3) Timeline (per minute)
    rows = q(conn, """
      SELECT strftime('%Y-%m-%d %H:%M', ts, 'unixepoch') AS minute, COUNT(*)
      FROM alerts
      GROUP BY minute
      ORDER BY minute;
    """)
    if rows:
        labels = [r[0] for r in rows]; counts = [r[1] for r in rows]
        plot_line(labels, counts, "Alerts Timeline (per minute)", "alerts_timeline.png", xlabel="Minute")
    print("Saved: alerts_by_type.png, top_sources.png, alerts_timeline.png")

if __name__ == "__main__":
    main()
