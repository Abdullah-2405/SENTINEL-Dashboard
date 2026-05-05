# SOC CTI DASHBOARD — FULL SETUP GUIDE
University SOC Lab | Wazuh + Windows Environment

---

## ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATA SOURCES (Windows Lab)                  │
│                                                                 │
│  [Wazuh Agent]    [Nessus Essentials]    [Windows Firewall]    │
│  alerts.json      Export CSV             pfirewall.log          │
│  syscheck FIM     CVE/CVSS data          Blocked connections    │
│  Sysmon events    Plugin results         DROP/BLOCK events      │
└──────────┬────────────────┬────────────────────┬───────────────┘
           │                │                    │
           ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                   FORWARDER LAYER (Python scripts)              │
│                                                                 │
│   wazuh_forwarder.py  ──────────────────────────────────────►  │
│   - Tails alerts.json in real-time                              │
│   - Parses Nessus CSV                                           │
│   - Parses pfirewall.log                                        │
│   - POSTs to API /ingest endpoints                             │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTP POST (JSON)
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    BACKEND API (FastAPI / Python)               │
│                                                                 │
│   /ingest/wazuh ──► Threat Classifier ──► MongoDB              │
│   /ingest/vulnerability ──────────────► MongoDB                │
│   /ingest/fim ────────────────────────► MongoDB                │
│   /ingest/network ────────────────────► MongoDB                │
│                                                                 │
│   /alerts, /vulnerabilities, /fim-events, /network-events      │
│   /stats/summary  /export/csv  /logs                           │
│                                                                 │
│   WebSocket /ws ──► Real-time broadcast to dashboard           │
│                                                                 │
│   Rate Limiting (slowapi) + HMAC Auth + CORS                   │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
            ┌─────────────┐      ┌──────────────────┐
            │   MongoDB   │      │  Dashboard UI     │
            │  soc_       │      │  (HTML/CSS/JS)    │
            │  dashboard  │      │  React Charts     │
            │             │      │  WebSocket live   │
            │  alerts     │      │  7-panel layout   │
            │  vulns      │      │  Filter/Search    │
            │  fim_events │      │  Export CSV       │
            │  net_events │      │  Sound alerts     │
            └─────────────┘      └──────────────────┘
```

---

## STEP-BY-STEP SETUP

### PREREQUISITES
- Python 3.11+
- MongoDB (Community) — https://www.mongodb.com/try/download/community
- A browser (Chrome/Firefox)
- Wazuh Manager running (or use demo_data.py to simulate)

---

### STEP 1 — Install MongoDB

**Windows:**
```
winget install MongoDB.Server
# OR download from mongodb.com
```

**Linux/Kali (Wazuh Manager side):**
```bash
# MongoDB is already on the manager if you used the Wazuh OVA
# If not:
sudo apt install mongodb
sudo systemctl start mongodb
```

---

### STEP 2 — Backend Setup

```bash
# Clone / copy the soc-dashboard folder
cd soc-dashboard/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate          # Linux/Mac
venv\Scripts\activate             # Windows

# Install dependencies
pip install -r requirements.txt

# Run the backend
python main.py
# → API running at http://localhost:8000
# → Docs at http://localhost:8000/docs
```

---

### STEP 3 — Frontend Setup (No build required)

```bash
# Just open the file in a browser:
# Option A: Double-click frontend/index.html

# Option B: Serve it with Python (better for WebSocket)
cd soc-dashboard/frontend
python -m http.server 3000
# → Open http://localhost:3000

# Option C: Use VS Code Live Server extension
```

**Edit API URL if needed:**
In `frontend/index.html`, find:
```javascript
const API_BASE = 'http://localhost:8000';
```
Change `localhost` to your backend machine's IP if running on a different machine.

---

### STEP 4 — Configure Wazuh to Forward Logs

#### Method A: Run the forwarder script (Recommended for lab)
```bash
# Get your auth token first:
python -c "import hmac,hashlib; print(hmac.new(b'soc-lab-secret-key-change-in-prod', b'soc-dashboard', hashlib.sha256).hexdigest())"

# Run the forwarder on the Wazuh Manager:
cd soc-dashboard/scripts
pip install requests
python wazuh_forwarder.py \
  --api http://YOUR_BACKEND_IP:8000 \
  --alerts /var/ossec/logs/alerts/alerts.json \
  --batch    # Send historical data first
```

#### Method B: Wazuh Webhook Integration (Advanced)
Add to `/var/ossec/etc/ossec.conf`:
```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://YOUR_BACKEND_IP:8000/ingest/wazuh</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

---

### STEP 5 — Import Nessus Scan Results

1. In Nessus Essentials: Reports → Export → CSV
2. Run:
```bash
python wazuh_forwarder.py --nessus path/to/nessus_export.csv --api http://localhost:8000
```

---

### STEP 6 — Import Windows Firewall Logs

```bash
# Enable Windows Firewall Logging first:
# Windows Defender Firewall → Advanced Settings → Properties
# → Private Profile → Logging → Log dropped packets: Yes
# → Log file: C:\Windows\System32\LogFiles\Firewall\pfirewall.log

python wazuh_forwarder.py \
  --firewall "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" \
  --api http://localhost:8000
```

---

### STEP 7 — Test with Demo Data (No Wazuh needed)

```bash
# Populate with realistic fake data immediately:
cd soc-dashboard/scripts
python demo_data.py

# Keep generating live events:
python demo_data.py --continuous --interval 2
```

---

## MONGODB SCHEMA

### alerts collection
```json
{
  "_id": "ObjectId",
  "timestamp": "ISODate",
  "agent_id": "001",
  "agent_name": "WIN-WORKSTATION-01",
  "rule_id": "31151",
  "rule_description": "Web attack: SQL injection attempt",
  "rule_level": 9,
  "severity": "High",          // Critical | High | Medium | Low
  "category": "Web Attack",    // See ThreatCategory enum
  "src_ip": "185.220.101.1",
  "dst_ip": "192.168.1.50",
  "dst_port": 80,
  "raw_log": "...",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "T1190"
}
```

### vulnerabilities collection
```json
{
  "_id": "ObjectId",
  "timestamp": "ISODate",
  "cve_id": "CVE-2021-44228",
  "title": "Log4Shell - Log4j RCE",
  "cvss_score": 10.0,
  "severity": "Critical",
  "affected_host": "WIN-SERVER-WEB",
  "affected_service": "Apache Tomcat",
  "port": 8080,
  "description": "...",
  "solution": "...",
  "plugin_id": "156860"
}
```

### fim_events collection
```json
{
  "_id": "ObjectId",
  "timestamp": "ISODate",
  "agent_id": "001",
  "agent_name": "WIN-SERVER-DC",
  "file_path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
  "event_type": "modified",   // added | modified | deleted
  "file_size": 1024,
  "md5": "abc123...",
  "sha256": "def456...",
  "user": "Administrator",
  "severity": "High"
}
```

### network_events collection
```json
{
  "_id": "ObjectId",
  "timestamp": "ISODate",
  "src_ip": "185.220.101.1",
  "dst_ip": "192.168.1.1",
  "src_port": 55123,
  "dst_port": 3389,
  "protocol": "TCP",
  "action": "DROP",          // ALLOW | DROP | BLOCK
  "bytes_sent": 512,
  "category": "Firewall Violation",
  "severity": "High",
  "agent_id": "001"
}
```

---

## API ENDPOINTS REFERENCE

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/ingest/wazuh` | Receive Wazuh alert |
| POST | `/ingest/vulnerability` | Receive Nessus vuln |
| POST | `/ingest/fim` | Receive FIM event |
| POST | `/ingest/network` | Receive network event |
| GET | `/alerts` | Query alerts with filters |
| GET | `/vulnerabilities` | Query CVEs |
| GET | `/fim-events` | Query FIM events |
| GET | `/network-events` | Query firewall events |
| GET | `/logs` | Unified log stream |
| GET | `/stats/summary` | Dashboard stats |
| GET | `/export/csv` | CSV export |
| WS | `/ws` | Real-time WebSocket |
| GET | `/health` | Health check |
| GET | `/docs` | Swagger UI |

**Auth:** All endpoints (except /health) require:
```
Authorization: Bearer <token>
```
Generate token:
```python
import hmac, hashlib
token = hmac.new(b'soc-lab-secret-key-change-in-prod', b'soc-dashboard', hashlib.sha256).hexdigest()
```

---

## THREAT CLASSIFICATION LOGIC

### Wazuh Rule Level → Severity
| Level | Severity |
|-------|----------|
| 0–5   | Low      |
| 6–8   | Medium   |
| 9–11  | High     |
| 12–15 | Critical |

### CVSS Score → Severity
| CVSS | Severity |
|------|----------|
| 0–3.9  | Low    |
| 4–6.9  | Medium |
| 7–8.9  | High   |
| 9–10   | Critical |

### Category Classification (keyword-based)
- malware, virus, trojan, ransomware → Malware
- brute force, auth failure, rdp, ssh → Intrusion
- sql injection, xss, web attack → Web Attack
- nmap, scan, probe, recon → Reconnaissance
- firewall, blocked, denied → Firewall Violation
- fim, syscheck, file → File Integrity
- network, packet, flood → Network Anomaly

---

## SECURITY BEST PRACTICES

1. **Change API_SECRET** in both `main.py` and `index.html` to something strong
2. **MongoDB**: Add auth in production (`--auth` flag)
3. **Rate limiting**: Already configured (500/min for ingestion, 60/min for reads)
4. **CORS**: Restrict `allow_origins` to your dashboard URL in production
5. **HTTPS**: Add SSL in front (nginx + certbot) for real deployments
6. **Log sanitization**: Raw logs are stored but HTML-escaped on display
7. **Input validation**: All ingestion endpoints validate via Pydantic

---

## PROJECT FILE STRUCTURE

```
soc-dashboard/
├── backend/
│   ├── main.py              # FastAPI application + all endpoints
│   └── requirements.txt     # Python dependencies
├── frontend/
│   └── index.html           # Complete dashboard (single file)
├── scripts/
│   ├── wazuh_forwarder.py   # Wazuh → API bridge + Nessus/Firewall parsers
│   └── demo_data.py         # Test data generator
└── docs/
    └── SETUP.md             # This file
```

---

## WAZUH FIM CONFIGURATION (Windows)

Add to `C:\Program Files (x86)\ossec-agent\ossec.conf`:
```xml
<syscheck>
  <frequency>300</frequency>
  <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
  <directories check_all="yes" realtime="yes">C:\Users</directories>
  <directories check_all="yes" realtime="yes">C:\Program Files</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\Temp</directories>
  <ignore>C:\Windows\System32\LogFiles</ignore>
</syscheck>
```

---

## QUICK START DEMO (5 minutes)

```bash
# Terminal 1: Start MongoDB
mongod --dbpath ./data

# Terminal 2: Start backend
cd backend && python main.py

# Terminal 3: Generate demo data
cd scripts && python demo_data.py --continuous

# Browser: Open frontend/index.html
```
