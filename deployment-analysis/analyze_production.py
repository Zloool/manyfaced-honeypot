#!/usr/bin/env python3
"""Analyze production honeypot logs and database for attack patterns, errors, and trends."""

import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict

LOG_PATH = "honeypot.log"
DB_PATH = "honeypot.db"

# ─── Log Analysis ───────────────────────────────────────────────────────────

def parse_log_line(line):
    """Parse a JSON log line."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
        # Normalize fields
        return {
            "timestamp": obj.get("timestamp", ""),
            "level": obj.get("level", "UNKNOWN"),
            "module": obj.get("logger", ""),
            "process": obj.get("processName", str(obj.get("process", "?"))),
            "message": obj.get("message", ""),
        }
    except json.JSONDecodeError:
        return None

def analyze_logs(log_path):
    print("=" * 70)
    print("HONEYPOT LOG ANALYSIS")
    print("=" * 70)
    
    lines = []
    with open(log_path, "r") as f:
        lines = f.readlines()
    
    print(f"\nTotal log lines: {len(lines)}")
    
    # Parse all lines
    parsed = []
    for line in lines:
        p = parse_log_line(line)
        if p:
            parsed.append(p)
    
    print(f"Parsed lines: {len(parsed)}")
    
    # Time range
    if parsed:
        print("\n--- Time Range ---")
        print(f"First entry: {parsed[0]['timestamp']}")
        print(f"Last entry:  {parsed[-1]['timestamp']}")
    
    # Log level distribution
    print("\n--- Log Level Distribution ---")
    level_counts = Counter(p["level"] for p in parsed)
    for level, count in level_counts.most_common():
        print(f"  {level:8s}: {count:>6d}")
    
    # Process distribution
    print("\n--- Process Distribution ---")
    proc_counts = Counter(p["process"] for p in parsed)
    for proc, count in proc_counts.most_common():
        print(f"  {proc:20s}: {count:>6d}")
    
    # Module distribution
    print("\n--- Module Distribution ---")
    mod_counts = Counter(p["module"] for p in parsed)
    for mod, count in mod_counts.most_common(15):
        print(f"  {mod:40s}: {count:>6d}")
    
    # Error/Exception analysis
    print("\n--- Errors / Warnings ---")
    error_lines = [p for p in parsed if p["level"] in ("ERROR", "WARNING", "CRITICAL")]
    print(f"Total errors/warnings: {len(error_lines)}")
    
    error_messages = [p["message"] for p in error_lines]
    error_counter = Counter()
    for msg in error_messages:
        short = msg[:200] if len(msg) > 200 else msg
        error_counter[short] += 1
    
    if error_counter:
        print("\nTop error types:")
        for msg, count in error_counter.most_common(15):
            print(f"  [{count:>3d}x] {msg}")
    
    # Extract bot IPs from log messages
    print("\n--- Bot IPs Detected in Logs ---")
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    all_ips = []
    for p in parsed:
        ips = ip_pattern.findall(p["message"])
        all_ips.extend(ips)
    
    ip_counter = Counter(all_ips)
    print(f"Total IP mentions: {len(all_ips)}")
    print(f"Unique IPs: {len(ip_counter)}")
    print("\nTop 20 attacking IPs:")
    for ip, count in ip_counter.most_common(20):
        print(f"  {ip:20s}: {count:>5d} mentions")
    
    # Extract detected flag values
    print("\n--- Detected Service Flags ---")
    detected_pattern = re.compile(r"detected=(\d+)")
    detected_values = []
    for p in parsed:
        m = detected_pattern.search(p["message"])
        if m:
            detected_values.append(int(m.group(1)))
    
    if detected_values:
        detected_counter = Counter(detected_values)
        print(f"Total detections logged: {len(detected_values)}")
        # Canonical detected_id values: manyfaced/common/status.py
        detected_names = {
            1: "HTTP Handler (WordPress/Drupal/Jenkins/etc)",
            4294967287: "TLS ClientHello",
            4294967288: "Redis RESP Command",
            4294967289: "MongoDB Wire Protocol",
            4294967290: "DNS-over-TCP Query",
            4294967291: "Empty Connection (port scan)",
            4294967292: "Unknown Non-HTTP Probe",
            4294967293: "SSH Client Probe",
            4294967294: "Generic/Malformed HTTP Request",
        }
        for flag, count in detected_counter.most_common():
            name = detected_names.get(flag, f"Unknown({flag})")
            print(f"  {name:30s} (ID={flag:>10d}): {count:>5d}")
    
    # Requests per minute / time distribution
    print("\n--- Temporal Distribution ---")
    if parsed:
        hour_counts = Counter()
        for p in parsed:
            ts = p["timestamp"]
            # Handle ISO format: 2026-05-01T14:29:11.117687+00:00
            if "T" in ts:
                hour = ts[:13].replace("T", " ")
            else:
                hour = ts[:13]
            hour_counts[hour] += 1
        
        for hour in sorted(hour_counts.keys()):
            bar = "#" * min(hour_counts[hour], 80)
            print(f"  {hour}: {bar} ({hour_counts[hour]})")
    
    # Bot IP activity over time
    print("\n--- Bot Activity Timeline ---")
    bot_activity = defaultdict(list)
    for p in parsed:
        ips = ip_pattern.findall(p["message"])
        for ip in ips:
            bot_activity[ip].append(p["timestamp"])
    
    active_ips = {ip: ts for ip, ts in bot_activity.items() if len(ts) >= 2}
    print(f"IPs with multiple log entries: {len(active_ips)}")
    
    # Extract unique bot IPs that had interactions
    interaction_ips = set()
    for p in parsed:
        if "Generated response for" in p["message"] or "report" in p["message"].lower():
            ips = ip_pattern.findall(p["message"])
            for ip in ips:
                interaction_ips.add(ip)
    
    print(f"IPs in interaction messages: {len(interaction_ips)}")
    
    # Sample error/warning messages
    print("\n--- Sample Warning Messages ---")
    warnings = [p for p in parsed if p["level"] == "WARNING"]
    for w in warnings[:10]:
        print(f"  [{w['timestamp']}] [{w['module']}] {w['message'][:120]}")
    
    # Sample info messages about bot interactions
    print("\n--- Sample Bot Interaction Messages ---")
    bot_msgs = [p for p in parsed if any(kw in p["message"] for kw in ["Generated response", "BearStorage", "send_report", "data saved", "Report sent", "receive_timeout"])]
    for m in bot_msgs[:15]:
        msg = m["message"]
        if len(msg) > 150:
            msg = msg[:150] + "..."
        print(f"  [{m['timestamp']}] [{m['process']}] {msg}")
    
    return parsed, ip_counter, interaction_ips


# ─── Database Analysis ──────────────────────────────────────────────────────

def analyze_db(db_path):
    print("\n" + "=" * 70)
    print("HONEYPOT DATABASE ANALYSIS")
    print("=" * 70)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Table info
    print("\n--- Tables ---")
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"Tables: {tables}")
    
    # Schema
    for table in tables:
        cursor.execute(f"PRAGMA table_info({table});")
        cols = cursor.fetchall()
        print(f"\n--- Schema: {table} ---")
        for col in cols:
            print(f"  {col[1]:30s} {col[2]:20s} {'NOT NULL' if col[3] else 'NULLABLE'}")
    
    # Row counts
    print("\n--- Row Counts ---")
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table};")
        count = cursor.fetchone()[0]
        print(f"  {table:30s}: {count:>8d}")
    
    # Analyze honeypot_bears table
    if "honeypot_bears" in tables:
        print("\n--- honeypot_bears Analysis ---")
        
        # Count
        cursor.execute("SELECT COUNT(*) FROM honeypot_bears;")
        total_bears = cursor.fetchone()[0]
        print(f"Total bear records: {total_bears}")
        
        # Columns
        cursor.execute("PRAGMA table_info(honeypot_bears);")
        cols = [row[1] for row in cursor.fetchall()]
        print(f"Columns: {cols}")
        
        # Sample records
        cursor.execute("SELECT * FROM honeypot_bears ORDER BY id DESC LIMIT 3;")
        samples = cursor.fetchall()
        print("\nLatest 3 records:")
        for row in samples:
            for col_name, val in zip(cols, row):
                if isinstance(val, str) and len(val) > 100:
                    val = val[:100] + "..."
                print(f"  {col_name:25s}: {val}")
            print()
        
        # Unique IPs
        cursor.execute("SELECT DISTINCT bot_ip, COUNT(*) as cnt FROM honeypot_bears GROUP BY bot_ip ORDER BY cnt DESC;")
        ip_rows = cursor.fetchall()
        print(f"\nUnique IPs in DB: {len(ip_rows)}")
        print("Top 20 IPs by request count:")
        for row in ip_rows[:20]:
            print(f"  {row[0]:20s}: {row[1]:>5d} requests")
        
        # User agents
        cursor.execute("SELECT DISTINCT bot_user_agent, COUNT(*) as cnt FROM honeypot_bears GROUP BY bot_user_agent ORDER BY cnt DESC;")
        ua_rows = cursor.fetchall()
        print(f"\nUnique User-Agents: {len(ua_rows)}")
        print("Top 20 User-Agents:")
        for row in ua_rows[:20]:
            ua = row[0]
            if ua and len(ua) > 80:
                ua = ua[:80] + "..."
            print(f"  [{row[1]:>4d}x] {ua}")
        
        # Detected services
        cursor.execute("SELECT DISTINCT detected_id, COUNT(*) as cnt FROM honeypot_bears GROUP BY detected_id ORDER BY cnt DESC;")
        det_rows = cursor.fetchall()
        print("\nDetected services distribution:")
        # Canonical detected_id values: manyfaced/common/status.py
        det_names = {
            1: "HTTP Handler (WordPress/Drupal/Jenkins/etc)",
            4294967287: "TLS ClientHello",
            4294967288: "Redis RESP Command",
            4294967289: "MongoDB Wire Protocol",
            4294967290: "DNS-over-TCP Query",
            4294967291: "Empty Connection (port scan)",
            4294967292: "Unknown Non-HTTP Probe",
            4294967293: "SSH Client Probe",
            4294967294: "Generic/Malformed HTTP Request",
        }
        for row in det_rows:
            name = det_names.get(row[0], f"Unknown({row[0]})")
            print(f"  {name:30s} (ID={row[0]:>10d}): {row[1]:>5d}")
        
        # Countries
        cursor.execute("SELECT DISTINCT bot_country, COUNT(*) as cnt FROM honeypot_bears GROUP BY bot_country ORDER BY cnt DESC;")
        country_rows = cursor.fetchall()
        print("\nCountries distribution:")
        for row in country_rows[:20]:
            print(f"  {str(row[0]):20s}: {row[1]:>5d}")
        
        # DNS names / Hostnames
        cursor.execute("SELECT DISTINCT bot_dns_name, COUNT(*) as cnt FROM honeypot_bears GROUP BY bot_dns_name ORDER BY cnt DESC;")
        dns_rows = cursor.fetchall()
        print("\nTop 20 Hostnames/DNS names:")
        for row in dns_rows[:20]:
            val = str(row[0])
            if len(val) > 40:
                val = val[:40] + "..."
            print(f"  {val:40s}: {row[1]:>5d}")
        
        # Paths requested
        cursor.execute("SELECT DISTINCT request_path, COUNT(*) as cnt FROM honeypot_bears GROUP BY request_path ORDER BY cnt DESC;")
        path_rows = cursor.fetchall()
        print("\nRequest paths distribution:")
        for row in path_rows[:20]:
            val = row[0]
            if val and len(val) > 50:
                val = val[:50] + "..."
            print(f"  {str(val):50s}: {row[1]:>5d}")
        
        # Time range
        cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM honeypot_bears;")
        time_range = cursor.fetchone()
        print(f"\nTime range: {time_range[0]} to {time_range[1]}")
        
        # Request commands
        cursor.execute("SELECT DISTINCT request_command, COUNT(*) as cnt FROM honeypot_bears GROUP BY request_command ORDER BY cnt DESC;")
        cmd_rows = cursor.fetchall()
        print("\nRequest commands:")
        for row in cmd_rows:
            print(f"  {row[0]:10s}: {row[1]:>5d}")
        
        # Login values
        print("\n--- Login/Credential Data ---")
        cursor.execute("SELECT DISTINCT login, COUNT(*) as cnt FROM honeypot_bears GROUP BY login ORDER BY cnt DESC;")
        login_rows = cursor.fetchall()
        print(f"Unique login values: {len(login_rows)}")
        for row in login_rows[:20]:
            print(f"  {str(row[0]):30s}: {row[1]:>5d}")
        
        # Request raw samples (truncated)
        print("\n--- Sample Full Requests ---")
        cursor.execute("SELECT bot_ip, request_path, request_raw FROM honeypot_bears WHERE request_raw IS NOT NULL AND request_raw != '' ORDER BY id DESC LIMIT 5;")
        raw_rows = cursor.fetchall()
        for row in raw_rows:
            print(f"\n  From {row[0]} -> {row[1]}:")
            raw = row[2]
            if raw and len(raw) > 200:
                raw = raw[:200] + "..."
            print(f"    {raw}")
    
    conn.close()


# ─── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os_path = sys.argv[1] if len(sys.argv) > 1 else "."
    
    import os
    os.chdir(os_path)
    
    parsed, ip_counter, interaction_ips = analyze_logs(LOG_PATH)
    analyze_db(DB_PATH)
    
    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)
