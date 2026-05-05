#!/usr/bin/env python3
"""
SOC Dashboard - Demo Data Generator
Floods the API with realistic mock data so you can test the dashboard
without a real Wazuh environment.

Usage: python demo_data.py --api http://localhost:8000
"""

import requests
import random
import time
import hashlib
import hmac
import os
from datetime import datetime, timedelta

API_URL = "http://localhost:8000"
API_SECRET = os.getenv("API_SECRET", "soc-lab-secret-key-change-in-prod")
TOKEN = hmac.new(API_SECRET.encode(), b"soc-dashboard", hashlib.sha256).hexdigest()
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

AGENTS = [
    {"id": "001", "name": "WIN-WORKSTATION-01"},
    {"id": "002", "name": "WIN-SERVER-DC"},
    {"id": "003", "name": "WIN-SERVER-WEB"},
    {"id": "004", "name": "WIN-LAPTOP-HR"},
]

WAZUH_RULES = [
    (5502, 3, "User account created"),
    (5503, 5, "User account deleted"),
    (5710, 8, "Multiple Windows logon failures"),
    (5712, 10, "Windows logon failure - possible brute force"),
    (18103, 12, "Malware detected by antivirus"),
    (31151, 9, "Web attack: SQL injection attempt"),
    (31530, 7, "Nmap port scan detected"),
    (60106, 11, "Brute force attempt against RDP"),
    (100001, 14, "Ransomware behavior: mass file encryption"),
    (92000, 6, "Suspicious PowerShell execution"),
    (86001, 4, "New process created"),
    (61612, 8, "LLMNR/NBT-NS poisoning attempt (Responder)"),
]

CVSS_VULNS = [
    ("CVE-2021-34527", "PrintNightmare - Windows Print Spooler RCE", 8.8, "Windows", "Print Spooler", 445),
    ("CVE-2020-1472", "ZeroLogon - Netlogon Privilege Escalation", 10.0, "WIN-SERVER-DC", "Netlogon", 445),
    ("CVE-2021-44228", "Log4Shell - Log4j Remote Code Execution", 10.0, "WIN-SERVER-WEB", "Apache Tomcat", 8080),
    ("CVE-2022-30190", "Follina - MSDT Remote Code Execution", 7.8, "WIN-WORKSTATION-01", "MSDT", 0),
    ("CVE-2019-0708", "BlueKeep - RDP Remote Code Execution", 9.8, "WIN-SERVER-DC", "RDP", 3389),
    ("CVE-2021-26855", "ProxyLogon - Exchange Server SSRF", 9.1, "WIN-SERVER-WEB", "Exchange", 443),
    ("CVE-2023-23397", "Outlook Zero-click Privilege Escalation", 9.8, "WIN-LAPTOP-HR", "Outlook", 0),
    ("CVE-2022-41040", "ProxyNotShell - Exchange Server RCE", 8.8, "WIN-SERVER-WEB", "Exchange", 443),
]

CRITICAL_PATHS = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\config\SAM",
    r"C:\Users\Administrator\Desktop\passwords.txt",
    r"C:\Program Files\ossec-agent\ossec.conf",
    r"C:\Windows\Temp\mimikatz.exe",
    r"C:\Users\Public\nc.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
]

PRIV_IPS = ["192.168.1.1", "192.168.1.50", "10.0.0.1", "10.0.0.100"]
PUB_IPS = ["185.220.101.1", "45.33.32.156", "198.51.100.42", "203.0.113.5", "91.108.4.100"]

MITRE = [
    ("Initial Access", "T1190 - Exploit Public-Facing Application"),
    ("Execution", "T1059 - Command and Scripting Interpreter"),
    ("Persistence", "T1098 - Account Manipulation"),
    ("Privilege Escalation", "T1068 - Exploitation for Privilege Escalation"),
    ("Defense Evasion", "T1027 - Obfuscated Files or Information"),
    ("Credential Access", "T1003 - OS Credential Dumping"),
    ("Discovery", "T1046 - Network Service Scanning"),
    ("Lateral Movement", "T1021 - Remote Services"),
    ("Exfiltration", "T1048 - Exfiltration Over Alternative Protocol"),
]

def post(endpoint, payload):
    try:
        r = requests.post(f"{API_URL}{endpoint}", json=payload, headers=HEADERS, timeout=5)
        return r.status_code == 200
    except Exception as e:
        print(f"  [ERR] {endpoint}: {e}")
        return False

def gen_alerts(n=50):
    print(f"[+] Generating {n} Wazuh alerts...")
    for _ in range(n):
        rule_id, level, desc = random.choice(WAZUH_RULES)
        agent = random.choice(AGENTS)
        mitre_tactic, mitre_tech = random.choice(MITRE)
        alert = {
            "rule": {"id": str(rule_id), "level": level, "description": desc, "mitre": {"tactic": [mitre_tactic], "technique": [mitre_tech]}},
            "agent": {"id": agent["id"], "name": agent["name"]},
            "data": {
                "srcip": random.choice(PUB_IPS + PRIV_IPS),
                "dstip": random.choice(PRIV_IPS),
                "dstport": random.choice([22, 80, 443, 3389, 445, 8080, 135])
            },
            "full_log": f"[{datetime.utcnow().isoformat()}] Rule {rule_id} triggered on {agent['name']}: {desc}",
        }
        ok = post("/ingest/wazuh", alert)
        print(f"  {'✅' if ok else '❌'} Alert: {desc[:50]}")
        time.sleep(0.05)

def gen_vulnerabilities():
    print(f"[+] Generating {len(CVSS_VULNS)} vulnerabilities...")
    for cve, title, cvss, host, service, port in CVSS_VULNS:
        vuln = {
            "cve_id": cve,
            "title": title,
            "cvss_score": cvss,
            "affected_host": host,
            "affected_service": service,
            "port": port,
            "description": f"{title}. This vulnerability allows remote attackers to execute arbitrary code.",
            "solution": "Apply the latest security patches from Microsoft Security Update Guide.",
            "plugin_id": str(random.randint(100000, 199999)),
        }
        ok = post("/ingest/vulnerability", vuln)
        print(f"  {'✅' if ok else '❌'} {cve}: {title[:40]} (CVSS {cvss})")

def gen_fim(n=20):
    print(f"[+] Generating {n} FIM events...")
    events = ["added", "modified", "deleted"]
    for _ in range(n):
        agent = random.choice(AGENTS)
        fim = {
            "agent_id": agent["id"],
            "agent_name": agent["name"],
            "file_path": random.choice(CRITICAL_PATHS),
            "event_type": random.choice(events),
            "file_size": random.randint(1024, 1024*1024),
            "md5": hashlib.md5(os.urandom(8)).hexdigest(),
            "sha256": hashlib.sha256(os.urandom(8)).hexdigest(),
            "user": random.choice(["SYSTEM", "Administrator", "hr_user", "svc_account"]),
        }
        ok = post("/ingest/fim", fim)
        print(f"  {'✅' if ok else '❌'} FIM [{fim['event_type']}]: {fim['file_path'][-40:]}")
        time.sleep(0.05)

def gen_network(n=30):
    print(f"[+] Generating {n} network/firewall events...")
    actions = ["ALLOW", "DROP", "BLOCK"]
    protocols = ["TCP", "UDP", "ICMP"]
    for _ in range(n):
        action = random.choices(actions, weights=[40, 35, 25])[0]
        agent = random.choice(AGENTS)
        net = {
            "src_ip": random.choice(PUB_IPS + PRIV_IPS),
            "dst_ip": random.choice(PRIV_IPS),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([22, 80, 443, 3389, 445, 135, 8080, 23]),
            "protocol": random.choice(protocols),
            "action": action,
            "bytes_sent": random.randint(64, 65535),
            "agent_id": agent["id"],
        }
        ok = post("/ingest/network", net)
        print(f"  {'✅' if ok else '❌'} Network [{action}]: {net['src_ip']}:{net['src_port']} → {net['dst_ip']}:{net['dst_port']}")
        time.sleep(0.03)

def gen_continuous(interval=3):
    """Keep generating live data to simulate a real environment"""
    print(f"\n[🔄] Continuous mode: generating events every {interval}s (Ctrl+C to stop)\n")
    while True:
        choice = random.choice(["alert", "alert", "alert", "fim", "network"])
        if choice == "alert":
            gen_alerts(n=random.randint(1, 3))
        elif choice == "fim":
            gen_fim(n=1)
        else:
            gen_network(n=random.randint(1, 3))
        time.sleep(interval)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--continuous", action="store_true", help="Keep generating data")
    parser.add_argument("--interval", type=int, default=3)
    args = parser.parse_args()

    print("=" * 55)
    print("  SOC Dashboard - Demo Data Generator")
    print("=" * 55)
    
    # Initial bulk load
    gen_vulnerabilities()
    gen_alerts(n=80)
    gen_fim(n=30)
    gen_network(n=50)
    
    print("\n✅ Initial data loaded!")
    
    if args.continuous:
        gen_continuous(args.interval)
