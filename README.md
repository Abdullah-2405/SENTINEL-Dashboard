# SENTINEL — Cyber Threat Intelligence Dashboard

A personal SOC dashboard built to monitor, visualize, and analyze security events in real time. SENTINEL integrates with Wazuh to collect and forward logs, stores them in MongoDB, and presents them through a React frontend backed by a FastAPI API.

Built as a hands-on project during CEH coursework to apply SOC concepts in a real environment.

---

## Features

- **Real-time Alert Monitoring** — Live feed of security alerts with severity classification (Critical, High, Medium, Low)
- **File Integrity Monitoring (FIM)** — Tracks file creation, modification, and deletion events across monitored directories
- **Vulnerability Detection** — Displays CVEs detected on connected agents with CVSS scores and affected software
- **Firewall Log Analysis** — Captures and visualizes Windows Firewall events mapped against CIS Benchmark rules
- **Threat Category Breakdown** — Donut chart and 24-hour timeline showing alert distribution by category
- **Multi-Agent Support** — Monitors multiple Wazuh agents simultaneously from a single dashboard

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React |
| Backend | FastAPI (Python) |
| Database | MongoDB |
| Log Source | Wazuh SIEM (v4.x) |
| Environment | Python venv |

---

## Architecture

```
Wazuh Agent (Windows/Linux)
        │
        ▼
Wazuh Manager (Ubuntu VM)
        │
        ▼
FastAPI Backend ──► MongoDB (log storage)
        │
        ▼
React Frontend (Dashboard UI)
```

---

## Screenshots

### Dashboard Overview
> 2,671 total alerts | 4 critical | 200 CVEs scanned | 1,768 FIM events

![Dashboard Overview](docs/screenshots/dashboard_overview.png)

### File Integrity Monitoring
> Real-time ADDED and MODIFIED events on monitored directories

![FIM Events](docs/screenshots/fim_events.png)

### Firewall Violation Alerts
> CIS Windows 11 Benchmark v3.0.0 rule violations

![Firewall Alerts](docs/screenshots/firewall_alerts.png)

### Threat Categories & Alert Timeline
> 24-hour alert distribution with category breakdown

![Threat Categories](docs/screenshots/threat_categories.png)

### Vulnerability Panel
> High-severity CVEs (CVSS 8.8) detected on Windows agent

![Vulnerabilities](docs/screenshots/vulnerabilities.png)

---

## Setup & Installation

### Prerequisites

- Python 3.10+
- Node.js 18+
- MongoDB running locally or via Atlas
- Wazuh Manager deployed and at least one agent connected

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Environment Variables

Create a `.env` file in the `backend/` directory:

```
MONGO_URI=mongodb://localhost:27017
WAZUH_API_URL=https://<your-wazuh-manager-ip>:55000
WAZUH_USER=wazuh-wui
WAZUH_PASS=<your-password>
```

> ⚠️ Never commit your `.env` file. It is already listed in `.gitignore`.

---

## Lab Environment

| Component | Details |
|---|---|
| Wazuh Manager | Ubuntu VM (VirtualBox) |
| Wazuh Agent | Windows 11 (DESKTOP-T4T9UUP) |
| Dashboard | Localhost (React dev server) |
| Monitoring Scope | Downloads folder, Desktop, Firewall logs |

---

## Key Findings (Live Lab Data)

- **1,768 FIM events** captured during a single monitoring session
- **4 critical alerts** and **1,784 high alerts** detected over 24 hours
- **5 CVEs with CVSS 8.8** found on the Windows agent (Microsoft SQL Server drivers)
- **23 firewall violations** flagged against CIS Benchmark v3.0.0
- Alert spike observed during batch file operations — confirms real-time detection capability

---

## Project Structure

```
SENTINEL-Dashboard/
├── backend/          # FastAPI application
├── frontend/         # React application
├── scripts/          # Utility and automation scripts
├── docs/
│   └── screenshots/  # Dashboard screenshots
├── .gitignore
└── README.md
```

---

## Author

**Muhammad Abdullah**
BS Cybersecurity & Network Security | Karachi, Pakistan
CEH (In Progress) | CCNA Certified

---

## License

This project is for personal and educational use.
