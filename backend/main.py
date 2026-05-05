"""
SOC CTI Dashboard - Backend API
FastAPI + MongoDB + WebSocket real-time updates
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
import asyncio
import json
import time
import hashlib
import hmac
import csv
import io
from datetime import datetime, timedelta
from typing import Optional, List
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn
import os
import logging
from enum import Enum

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "soc_dashboard"
API_SECRET = os.getenv("API_SECRET", "soc-lab-secret-key-change-in-prod")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# APP SETUP
# ─────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="SOC CTI Dashboard API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────
client: AsyncIOMotorClient = None
db = None

@app.on_event("startup")
async def startup():
    global client, db
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]
    # Create indexes for performance
    await db.alerts.create_index([("timestamp", -1)])
    await db.alerts.create_index([("severity", 1)])
    await db.alerts.create_index([("category", 1)])
    await db.alerts.create_index([("agent_id", 1)])
    await db.vulnerabilities.create_index([("cvss_score", -1)])
    await db.fim_events.create_index([("timestamp", -1)])
    await db.network_events.create_index([("timestamp", -1)])
    logger.info("✅ Database connected and indexes created")

@app.on_event("shutdown")
async def shutdown():
    client.close()

# ─────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Simple HMAC token verification for lab use"""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authorization token")
    expected = hmac.new(API_SECRET.encode(), b"soc-dashboard", hashlib.sha256).hexdigest()
    if not hmac.compare_digest(credentials.credentials, expected):
        raise HTTPException(status_code=403, detail="Invalid token")
    return True

# ─────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────
class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class ThreatCategory(str, Enum):
    INTRUSION = "Intrusion"
    MALWARE = "Malware"
    WEB_ATTACK = "Web Attack"
    RECONNAISSANCE = "Reconnaissance"
    NETWORK_ANOMALY = "Network Anomaly"
    FIREWALL_VIOLATION = "Firewall Violation"
    FIM = "File Integrity"
    UNKNOWN = "Unknown"

class Alert(BaseModel):
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_id: str
    agent_name: str
    rule_id: str
    rule_description: str
    rule_level: int          # Wazuh rule level 0-15
    severity: SeverityLevel
    category: ThreatCategory
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    raw_log: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None

class Vulnerability(BaseModel):
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    cve_id: str
    title: str
    cvss_score: float
    severity: SeverityLevel
    affected_host: str
    affected_service: str
    port: Optional[int] = None
    description: str
    solution: Optional[str] = None
    plugin_id: Optional[str] = None  # Nessus plugin ID

class FIMEvent(BaseModel):
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_id: str
    agent_name: str
    file_path: str
    event_type: str       # added, modified, deleted
    file_size: Optional[int] = None
    md5: Optional[str] = None
    sha256: Optional[str] = None
    user: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM

class NetworkEvent(BaseModel):
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    action: str             # ALLOW, DROP, BLOCK
    bytes_sent: Optional[int] = None
    category: ThreatCategory = ThreatCategory.NETWORK_ANOMALY
    severity: SeverityLevel = SeverityLevel.LOW
    agent_id: Optional[str] = None

# ─────────────────────────────────────────────
# THREAT CLASSIFIER
# ─────────────────────────────────────────────
def classify_wazuh_alert(rule_level: int, rule_id: str, description: str) -> tuple[SeverityLevel, ThreatCategory]:
    """Map Wazuh rule levels to severity + category"""
    desc_lower = description.lower()

    # Severity by rule level
    if rule_level >= 12:
        severity = SeverityLevel.CRITICAL
    elif rule_level >= 9:
        severity = SeverityLevel.HIGH
    elif rule_level >= 6:
        severity = SeverityLevel.MEDIUM
    else:
        severity = SeverityLevel.LOW

    # Category by keywords
    if any(k in desc_lower for k in ["malware", "virus", "trojan", "ransomware", "worm"]):
        category = ThreatCategory.MALWARE
    elif any(k in desc_lower for k in ["brute force", "authentication failure", "login attempt", "ssh", "rdp"]):
        category = ThreatCategory.INTRUSION
    elif any(k in desc_lower for k in ["sql injection", "xss", "web attack", "http", "scanning url"]):
        category = ThreatCategory.WEB_ATTACK
    elif any(k in desc_lower for k in ["nmap", "scan", "probe", "enumerat", "reconnaissance"]):
        category = ThreatCategory.RECONNAISSANCE
    elif any(k in desc_lower for k in ["firewall", "blocked", "drop", "denied", "pfirewall"]):
        category = ThreatCategory.FIREWALL_VIOLATION
    elif any(k in desc_lower for k in ["fim", "file", "integrity", "syscheck"]):
        category = ThreatCategory.FIM
    elif any(k in desc_lower for k in ["network", "packet", "traffic", "bandwidth", "flood"]):
        category = ThreatCategory.NETWORK_ANOMALY
    else:
        category = ThreatCategory.UNKNOWN

    return severity, category

def classify_cvss(cvss_score: float) -> SeverityLevel:
    if cvss_score >= 9.0:
        return SeverityLevel.CRITICAL
    elif cvss_score >= 7.0:
        return SeverityLevel.HIGH
    elif cvss_score >= 4.0:
        return SeverityLevel.MEDIUM
    else:
        return SeverityLevel.LOW

def classify_firewall(action: str, dst_port: Optional[int]) -> SeverityLevel:
    if action.upper() in ("DROP", "BLOCK"):
        if dst_port in (22, 3389, 445, 135, 137, 139):
            return SeverityLevel.HIGH
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW

# ─────────────────────────────────────────────
# WEBSOCKET MANAGER
# ─────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WS connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active_connections.remove(ws)

manager = ConnectionManager()

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def serialize_doc(doc: dict) -> dict:
    """Convert MongoDB ObjectId + datetime to JSON-serializable"""
    doc["_id"] = str(doc["_id"])
    for k, v in doc.items():
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc

def build_time_filter(hours: Optional[int] = None) -> dict:
    if hours:
        return {"timestamp": {"$gte": datetime.utcnow() - timedelta(hours=hours)}}
    return {}

# ─────────────────────────────────────────────
# WAZUH INGESTION ENDPOINT
# ─────────────────────────────────────────────
@app.post("/ingest/wazuh", tags=["Ingestion"])
@limiter.limit("500/minute")
async def ingest_wazuh(request: Request, payload: dict, auth: bool = Depends(verify_token)):
    """
    Receive raw Wazuh alerts (via Wazuh webhook integration or custom script).
    Normalizes, classifies, stores, and broadcasts via WebSocket.
    """
    try:
        rule = payload.get("rule", {})
        rule_level = int(rule.get("level", 0))
        rule_id = str(rule.get("id", "0"))
        description = rule.get("description", "")
        agent = payload.get("agent", {})
        src_ip = payload.get("data", {}).get("srcip") or payload.get("src_ip")
        dst_ip = payload.get("data", {}).get("dstip")
        mitre = payload.get("rule", {}).get("mitre", {})

        severity, category = classify_wazuh_alert(rule_level, rule_id, description)

        alert_doc = {
            "timestamp": datetime.utcnow(),
            "agent_id": agent.get("id", "unknown"),
            "agent_name": agent.get("name", "unknown"),
            "rule_id": rule_id,
            "rule_description": description,
            "rule_level": rule_level,
            "severity": severity.value,
            "category": category.value,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": payload.get("data", {}).get("dstport"),
            "raw_log": payload.get("full_log", ""),
            "mitre_tactic": mitre.get("tactic", [None])[0] if mitre.get("tactic") else None,
            "mitre_technique": mitre.get("technique", [None])[0] if mitre.get("technique") else None,
        }

        result = await db.alerts.insert_one(alert_doc)
        alert_doc["_id"] = str(result.inserted_id)
        alert_doc["timestamp"] = alert_doc["timestamp"].isoformat()

        # Broadcast to all dashboard clients
        await manager.broadcast({"type": "new_alert", "data": alert_doc})
        return {"status": "ok", "id": alert_doc["_id"]}
    except Exception as e:
        logger.error(f"Wazuh ingest error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/ingest/vulnerability", tags=["Ingestion"])
@limiter.limit("200/minute")
async def ingest_vulnerability(request: Request, payload: dict, auth: bool = Depends(verify_token)):
    """Receive Nessus/OpenVAS vulnerability scan results"""
    cvss = float(payload.get("cvss_score", 0))
    vuln_doc = {
        "timestamp": datetime.utcnow(),
        "cve_id": payload.get("cve_id", "CVE-UNKNOWN"),
        "title": payload.get("title", ""),
        "cvss_score": cvss,
        "severity": classify_cvss(cvss).value,
        "affected_host": payload.get("affected_host", ""),
        "affected_service": payload.get("affected_service", ""),
        "port": payload.get("port"),
        "description": payload.get("description", ""),
        "solution": payload.get("solution", ""),
        "plugin_id": payload.get("plugin_id"),
    }
    result = await db.vulnerabilities.insert_one(vuln_doc)
    vuln_doc["_id"] = str(result.inserted_id)
    vuln_doc["timestamp"] = vuln_doc["timestamp"].isoformat()
    await manager.broadcast({"type": "new_vulnerability", "data": vuln_doc})
    return {"status": "ok", "id": vuln_doc["_id"]}


@app.post("/ingest/fim", tags=["Ingestion"])
@limiter.limit("500/minute")
async def ingest_fim(request: Request, payload: dict, auth: bool = Depends(verify_token)):
    """Receive FIM events (from Wazuh syscheck)"""
    fim_doc = {
        "timestamp": datetime.utcnow(),
        "agent_id": payload.get("agent_id", "unknown"),
        "agent_name": payload.get("agent_name", "unknown"),
        "file_path": payload.get("file_path", ""),
        "event_type": payload.get("event_type", "modified"),
        "file_size": payload.get("file_size"),
        "md5": payload.get("md5"),
        "sha256": payload.get("sha256"),
        "user": payload.get("user"),
        "severity": SeverityLevel.HIGH.value if "system32" in payload.get("file_path", "").lower() else SeverityLevel.MEDIUM.value,
    }
    result = await db.fim_events.insert_one(fim_doc)
    fim_doc["_id"] = str(result.inserted_id)
    fim_doc["timestamp"] = fim_doc["timestamp"].isoformat()
    await manager.broadcast({"type": "new_fim", "data": fim_doc})
    return {"status": "ok", "id": fim_doc["_id"]}


@app.post("/ingest/network", tags=["Ingestion"])
@limiter.limit("1000/minute")
async def ingest_network(request: Request, payload: dict, auth: bool = Depends(verify_token)):
    """Receive Windows Firewall / Sysmon / Wireshark network events"""
    action = payload.get("action", "ALLOW")
    dst_port = payload.get("dst_port")
    sev = classify_firewall(action, dst_port)
    cat = ThreatCategory.FIREWALL_VIOLATION if action.upper() in ("DROP","BLOCK") else ThreatCategory.NETWORK_ANOMALY

    net_doc = {
        "timestamp": datetime.utcnow(),
        "src_ip": payload.get("src_ip", ""),
        "dst_ip": payload.get("dst_ip", ""),
        "src_port": payload.get("src_port"),
        "dst_port": dst_port,
        "protocol": payload.get("protocol", "TCP"),
        "action": action.upper(),
        "bytes_sent": payload.get("bytes_sent"),
        "category": cat.value,
        "severity": sev.value,
        "agent_id": payload.get("agent_id"),
    }
    result = await db.network_events.insert_one(net_doc)
    net_doc["_id"] = str(result.inserted_id)
    net_doc["timestamp"] = net_doc["timestamp"].isoformat()
    await manager.broadcast({"type": "new_network", "data": net_doc})
    return {"status": "ok", "id": net_doc["_id"]}

# ─────────────────────────────────────────────
# READ ENDPOINTS
# ─────────────────────────────────────────────
@app.get("/alerts", tags=["Data"])
@limiter.limit("60/minute")
async def get_alerts(
    request: Request,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    hours: Optional[int] = Query(None, description="Filter last N hours"),
    agent_id: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, le=1000),
    skip: int = 0,
):
    query = build_time_filter(hours)
    if severity:
        query["severity"] = severity
    if category:
        query["category"] = category
    if agent_id:
        query["agent_id"] = agent_id
    if search:
        query["$or"] = [
            {"rule_description": {"$regex": search, "$options": "i"}},
            {"src_ip": {"$regex": search, "$options": "i"}},
            {"agent_name": {"$regex": search, "$options": "i"}},
        ]
    cursor = db.alerts.find(query).sort("timestamp", -1).skip(skip).limit(limit)
    docs = [serialize_doc(d) async for d in cursor]
    total = await db.alerts.count_documents(query)
    return {"total": total, "data": docs}


@app.get("/vulnerabilities", tags=["Data"])
@limiter.limit("60/minute")
async def get_vulnerabilities(
    request: Request,
    severity: Optional[str] = None,
    host: Optional[str] = None,
    hours: Optional[int] = None,
    limit: int = Query(100, le=500),
    skip: int = 0,
):
    query = build_time_filter(hours)
    if severity:
        query["severity"] = severity
    if host:
        query["affected_host"] = {"$regex": host, "$options": "i"}
    cursor = db.vulnerabilities.find(query).sort("cvss_score", -1).skip(skip).limit(limit)
    docs = [serialize_doc(d) async for d in cursor]
    total = await db.vulnerabilities.count_documents(query)
    return {"total": total, "data": docs}


@app.get("/fim-events", tags=["Data"])
@limiter.limit("60/minute")
async def get_fim_events(
    request: Request,
    event_type: Optional[str] = None,
    hours: Optional[int] = None,
    agent_id: Optional[str] = None,
    limit: int = Query(100, le=500),
    skip: int = 0,
):
    query = build_time_filter(hours)
    if event_type:
        query["event_type"] = event_type
    if agent_id:
        query["agent_id"] = agent_id
    cursor = db.fim_events.find(query).sort("timestamp", -1).skip(skip).limit(limit)
    docs = [serialize_doc(d) async for d in cursor]
    total = await db.fim_events.count_documents(query)
    return {"total": total, "data": docs}


@app.get("/network-events", tags=["Data"])
@limiter.limit("60/minute")
async def get_network_events(
    request: Request,
    action: Optional[str] = None,
    severity: Optional[str] = None,
    hours: Optional[int] = None,
    search: Optional[str] = None,
    limit: int = Query(100, le=500),
    skip: int = 0,
):
    query = build_time_filter(hours)
    if action:
        query["action"] = action.upper()
    if severity:
        query["severity"] = severity
    if search:
        query["$or"] = [
            {"src_ip": {"$regex": search, "$options": "i"}},
            {"dst_ip": {"$regex": search, "$options": "i"}},
        ]
    cursor = db.network_events.find(query).sort("timestamp", -1).skip(skip).limit(limit)
    docs = [serialize_doc(d) async for d in cursor]
    total = await db.network_events.count_documents(query)
    return {"total": total, "data": docs}


@app.get("/logs", tags=["Data"])
@limiter.limit("30/minute")
async def get_logs(
    request: Request,
    hours: Optional[int] = 24,
    limit: int = Query(200, le=1000),
):
    """Unified log stream combining all sources"""
    query = build_time_filter(hours)
    alerts = [{"source": "wazuh", **serialize_doc(d)} async for d in db.alerts.find(query).sort("timestamp", -1).limit(limit // 4)]
    fim = [{"source": "fim", **serialize_doc(d)} async for d in db.fim_events.find(query).sort("timestamp", -1).limit(limit // 4)]
    net = [{"source": "network", **serialize_doc(d)} async for d in db.network_events.find(query).sort("timestamp", -1).limit(limit // 4)]
    vulns = [{"source": "vuln", **serialize_doc(d)} async for d in db.vulnerabilities.find(query).sort("timestamp", -1).limit(limit // 4)]
    combined = sorted(alerts + fim + net + vulns, key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"total": len(combined), "data": combined[:limit]}

# ─────────────────────────────────────────────
# STATS / SUMMARY
# ─────────────────────────────────────────────
@app.get("/stats/summary", tags=["Stats"])
@limiter.limit("30/minute")
async def get_summary(request: Request, hours: int = 24):
    """Dashboard overview stats"""
    tf = build_time_filter(hours)
    
    total_alerts = await db.alerts.count_documents(tf)
    critical_alerts = await db.alerts.count_documents({**tf, "severity": "Critical"})
    high_alerts = await db.alerts.count_documents({**tf, "severity": "High"})
    total_vulns = await db.vulnerabilities.count_documents(tf)
    critical_vulns = await db.vulnerabilities.count_documents({**tf, "severity": "Critical"})
    fim_count = await db.fim_events.count_documents(tf)
    net_blocked = await db.network_events.count_documents({**tf, "action": {"$in": ["DROP", "BLOCK"]}})

    # Category breakdown
    pipeline = [{"$match": tf}, {"$group": {"_id": "$category", "count": {"$sum": 1}}}]
    cat_cursor = db.alerts.aggregate(pipeline)
    categories = {doc["_id"]: doc["count"] async for doc in cat_cursor}

    # Agent status
    agent_pipeline = [{"$match": tf}, {"$group": {"_id": "$agent_id", "name": {"$last": "$agent_name"}, "last_seen": {"$max": "$timestamp"}, "alert_count": {"$sum": 1}}}]
    agent_cursor = db.alerts.aggregate(agent_pipeline)
    agents = [{"id": d["_id"], "name": d["name"], "last_seen": d["last_seen"].isoformat() if isinstance(d["last_seen"], datetime) else d["last_seen"], "alert_count": d["alert_count"]} async for d in agent_cursor]

    # Hourly timeline (last 24h)
    timeline_pipeline = [
        {"$match": build_time_filter(24)},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%dT%H:00:00", "date": "$timestamp"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    tl_cursor = db.alerts.aggregate(timeline_pipeline)
    timeline = [{"time": d["_id"], "count": d["count"]} async for d in tl_cursor]

    return {
        "overview": {
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "fim_events": fim_count,
            "blocked_connections": net_blocked,
        },
        "categories": categories,
        "agents": agents,
        "timeline": timeline,
    }


@app.get("/stats/top-vulnerabilities", tags=["Stats"])
async def top_vulnerabilities(request: Request, limit: int = 10):
    cursor = db.vulnerabilities.find({}).sort("cvss_score", -1).limit(limit)
    return [serialize_doc(d) async for d in cursor]

# ─────────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────────
@app.get("/export/csv", tags=["Export"])
async def export_csv(
    request: Request,
    source: str = Query("alerts", enum=["alerts", "vulnerabilities", "fim-events", "network-events"]),
    hours: int = 24,
):
    """Export data as CSV"""
    collection = db[source.replace("-", "_")]
    query = build_time_filter(hours)
    cursor = collection.find(query).sort("timestamp", -1).limit(5000)
    docs = [serialize_doc(d) async for d in cursor]

    if not docs:
        return {"message": "No data to export"}

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=docs[0].keys())
    writer.writeheader()
    writer.writerows(docs)
    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={source}-export.csv"}
    )

# ─────────────────────────────────────────────
# WEBSOCKET
# ─────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial heartbeat
        await websocket.send_json({"type": "connected", "message": "SOC Dashboard WebSocket active"})
        while True:
            # Keep alive ping every 30s
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping", "ts": datetime.utcnow().isoformat()})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ─────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat(), "ws_clients": len(manager.active_connections)}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
