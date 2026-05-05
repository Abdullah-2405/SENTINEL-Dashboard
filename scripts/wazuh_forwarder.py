#!/usr/bin/env python3
"""
Wazuh → SOC Dashboard Bridge
Run this on the Wazuh Manager (or on a Windows agent with Python).
Reads Wazuh alerts.json and forwards to the dashboard API.

Usage:
  python wazuh_forwarder.py --api http://localhost:8000 --token YOUR_TOKEN

Options:
  --api     Dashboard API base URL
  --token   API auth token (run `python gen_token.py` to get it)
  --tail    Tail the log file in real-time (default: True)
  --batch   Batch send old logs on startup
"""

import json
import time
import argparse
import hashlib
import hmac
import requests
import os
from pathlib import Path
from datetime import datetime

# ── CONFIG ──────────────────────────────────
WAZUH_ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"        # Linux Wazuh Manager
WAZUH_ALERTS_WIN  = r"C:\Program Files (x86)\ossec-agent\logs\alerts\alerts.json"  # Windows agent

API_SECRET = os.getenv("API_SECRET", "soc-lab-secret-key-change-in-prod")

def gen_token():
    return hmac.new(API_SECRET.encode(), b"soc-dashboard", hashlib.sha256).hexdigest()

# ── PARSE WAZUH ALERT ──────────────────────
def parse_wazuh_alert(line: str) -> dict | None:
    try:
        return json.loads(line.strip())
    except json.JSONDecodeError:
        return None

# ── FORWARD TO API ─────────────────────────
def forward_alert(api_url: str, token: str, alert: dict) -> bool:
    try:
        r = requests.post(
            f"{api_url}/ingest/wazuh",
            json=alert,
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        return r.status_code == 200
    except requests.RequestException as e:
        print(f"[ERROR] Forward failed: {e}")
        return False

# ── PARSE FIM EVENTS ───────────────────────
def extract_fim_from_alert(alert: dict) -> dict | None:
    """Extract FIM-specific data from Wazuh syscheck alert"""
    syscheck = alert.get("syscheck")
    if not syscheck:
        return None
    agent = alert.get("agent", {})
    return {
        "agent_id": agent.get("id", "unknown"),
        "agent_name": agent.get("name", "unknown"),
        "file_path": syscheck.get("path", ""),
        "event_type": syscheck.get("event", "modified"),
        "file_size": syscheck.get("size_after"),
        "md5": syscheck.get("md5_after"),
        "sha256": syscheck.get("sha256_after"),
        "user": syscheck.get("uname_after"),
    }

def forward_fim(api_url: str, token: str, fim: dict) -> bool:
    try:
        r = requests.post(
            f"{api_url}/ingest/fim",
            json=fim,
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        return r.status_code == 200
    except Exception:
        return False

# ── TAIL FILE ──────────────────────────────
def tail_file(filepath: str, api_url: str, token: str):
    """Follow the alerts.json log file and forward new entries"""
    path = Path(filepath)
    if not path.exists():
        print(f"[WARN] File not found: {filepath}. Waiting...")
        while not path.exists():
            time.sleep(5)

    print(f"[INFO] Tailing: {filepath}")
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)  # Seek to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            alert = parse_wazuh_alert(line)
            if not alert:
                continue

            # Forward full alert
            ok = forward_alert(api_url, token, alert)
            status = "✅" if ok else "❌"

            # Also extract FIM if applicable
            fim = extract_fim_from_alert(alert)
            if fim:
                forward_fim(api_url, token, fim)

            rule = alert.get("rule", {})
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] {status} Rule {rule.get('id','?')} L{rule.get('level','?')} | {rule.get('description','')[:60]}")

# ── BATCH HISTORICAL ───────────────────────
def batch_historical(filepath: str, api_url: str, token: str, limit: int = 500):
    """Send last N alerts from file for initial dashboard population"""
    path = Path(filepath)
    if not path.exists():
        print(f"[WARN] File not found for batch: {filepath}")
        return
    
    lines = path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
    recent = lines[-limit:]
    print(f"[INFO] Sending {len(recent)} historical alerts...")
    
    for i, line in enumerate(recent):
        alert = parse_wazuh_alert(line)
        if alert:
            forward_alert(api_url, token, alert)
            fim = extract_fim_from_alert(alert)
            if fim:
                forward_fim(api_url, token, fim)
        if i % 50 == 0:
            print(f"  Progress: {i}/{len(recent)}")
        time.sleep(0.05)  # Gentle throttle
    print("[INFO] Batch complete.")

# ──────────────────────────────────────────
# WINDOWS FIREWALL LOG PARSER
# ──────────────────────────────────────────
def parse_pfirewall_log(logfile: str, api_url: str, token: str):
    """
    Parse Windows Firewall pfirewall.log and forward to /ingest/network
    Format: date time action protocol src-ip dst-ip src-port dst-port ...
    """
    path = Path(logfile)
    if not path.exists():
        print(f"[WARN] Firewall log not found: {logfile}")
        return

    print(f"[INFO] Parsing firewall log: {logfile}")
    with open(logfile, "r") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 8:
                continue
            try:
                date_str, time_str, action, proto, src_ip, dst_ip, src_port, dst_port = parts[:8]
                event = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": int(src_port) if src_port.isdigit() else None,
                    "dst_port": int(dst_port) if dst_port.isdigit() else None,
                    "protocol": proto,
                    "action": action,
                }
                requests.post(
                    f"{api_url}/ingest/network",
                    json=event,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=3,
                )
            except Exception:
                continue
    print("[INFO] Firewall log parsing complete.")

# ── NESSUS CSV PARSER ──────────────────────
def parse_nessus_csv(csvfile: str, api_url: str, token: str):
    """
    Parse Nessus export CSV and forward to /ingest/vulnerability
    Export from Nessus: Reports → Export → CSV
    """
    import csv
    path = Path(csvfile)
    if not path.exists():
        print(f"[WARN] Nessus CSV not found: {csvfile}")
        return
    
    print(f"[INFO] Parsing Nessus CSV: {csvfile}")
    with open(csvfile, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                vuln = {
                    "cve_id": row.get("CVE", "CVE-UNKNOWN"),
                    "title": row.get("Name", ""),
                    "cvss_score": float(row.get("CVSS v2.0 Base Score", 0) or 0),
                    "affected_host": row.get("Host", ""),
                    "affected_service": row.get("Protocol", "") + "/" + row.get("Name", ""),
                    "port": int(row.get("Port", 0) or 0),
                    "description": row.get("Description", ""),
                    "solution": row.get("Solution", ""),
                    "plugin_id": row.get("Plugin ID", ""),
                }
                requests.post(
                    f"{api_url}/ingest/vulnerability",
                    json=vuln,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5,
                )
            except Exception as e:
                print(f"[WARN] Row error: {e}")
    print("[INFO] Nessus import complete.")

# ── MAIN ───────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wazuh → SOC Dashboard Forwarder")
    parser.add_argument("--api", default="http://localhost:8000", help="Dashboard API URL")
    parser.add_argument("--token", default=gen_token(), help="API auth token")
    parser.add_argument("--alerts", default=WAZUH_ALERTS_JSON, help="Path to alerts.json")
    parser.add_argument("--batch", action="store_true", help="Send historical alerts first")
    parser.add_argument("--firewall", default="", help="Path to pfirewall.log")
    parser.add_argument("--nessus", default="", help="Path to Nessus CSV export")
    args = parser.parse_args()

    print(f"[SOC Forwarder] API: {args.api}")
    print(f"[SOC Forwarder] Token: {args.token[:16]}...")

    if args.nessus:
        parse_nessus_csv(args.nessus, args.api, args.token)
    if args.firewall:
        parse_pfirewall_log(args.firewall, args.api, args.token)
    if args.batch:
        batch_historical(args.alerts, args.api, args.token)

    tail_file(args.alerts, args.api, args.token)
