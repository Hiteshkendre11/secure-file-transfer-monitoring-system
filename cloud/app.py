from __future__ import annotations

import hmac
import os
import sqlite3
import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

ROOT_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("EVENT_DB_PATH", str(ROOT_DIR / "data" / "events.sqlite3")))
AGENT_API_TOKEN = os.getenv("AGENT_API_TOKEN", "").strip()
APP_VERSION = "1.0.0"

app = FastAPI(
    title="Secure File Transfer Monitoring System",
    version=APP_VERSION,
    description="Auditor dashboard and authenticated event receiver for the Windows monitoring agent.",
)


class IncomingEvent(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    source_path: Optional[str] = Field(default=None, max_length=2048)
    destination_path: Optional[str] = Field(default=None, max_length=2048)
    drive: Optional[str] = Field(default=None, max_length=32)
    drive_type: Optional[str] = Field(default=None, max_length=32)
    user: Optional[str] = Field(default=None, max_length=128)
    process: Optional[str] = Field(default=None, max_length=128)
    severity: str = Field(default="INFO", max_length=20)
    status: Optional[str] = Field(default="Detected", max_length=1000)
    agent_id: str = Field(default="windows-agent", min_length=1, max_length=64)
    occurred_at: Optional[str] = Field(default=None, max_length=64)


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def _init_db() -> None:
    with _connect() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                occurred_at TEXT,
                event_type TEXT NOT NULL,
                source_name TEXT,
                destination_name TEXT,
                drive TEXT,
                drive_type TEXT,
                severity TEXT NOT NULL,
                status TEXT,
                agent_id TEXT NOT NULL
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at DESC)")
        connection.commit()


@app.on_event("startup")
def startup() -> None:
    _init_db()


def _basename(value: Optional[str]) -> Optional[str]:
    if not value or value == "N/A":
        return None
    # Normalize Windows and POSIX separators, then retain only the filename.
    return value.replace("\\", "/").rstrip("/").split("/")[-1][:255]


def _check_agent_token(authorization: Optional[str]) -> None:
    if not AGENT_API_TOKEN:
        raise HTTPException(status_code=503, detail="Agent ingestion is not configured. Set AGENT_API_TOKEN on the hosting service.")
    expected = f"Bearer {AGENT_API_TOKEN}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing agent token.")


def _event_rows(limit: int = 100) -> list[dict]:
    with _connect() as connection:
        rows = connection.execute(
            """SELECT id, received_at, occurred_at, event_type, source_name,
                      destination_name, drive, drive_type, severity, status, agent_id
               FROM events ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "sftms-auditor-dashboard", "version": APP_VERSION}


@app.get("/api/status")
def status() -> dict:
    _init_db()
    with _connect() as connection:
        total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        warnings = connection.execute("SELECT COUNT(*) FROM events WHERE UPPER(severity) IN ('WARNING','ERROR','CRITICAL')").fetchone()[0]
        last = connection.execute("SELECT received_at FROM events ORDER BY id DESC LIMIT 1").fetchone()
    return {
        "service": "online",
        "agent_ingestion_configured": bool(AGENT_API_TOKEN),
        "total_events": total,
        "alerts": warnings,
        "last_event_at": last[0] if last else None,
        "storage_note": "Event storage uses the configured EVENT_DB_PATH. On a free Render web service, local files are ephemeral and may be reset on restart, spin-down, or redeploy.",
    }


@app.get("/api/events")
def get_events(limit: int = Query(default=100, ge=1, le=200)) -> dict:
    _init_db()
    return {"events": _event_rows(limit)}


@app.post("/api/events")
def ingest_event(event: IncomingEvent, authorization: Optional[str] = Header(default=None)) -> dict:
    _check_agent_token(authorization)
    _init_db()
    received_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    occurred_at = event.occurred_at or received_at
    # Store filenames only. Full local paths, file contents, and hash values are not uploaded.
    record = (
        received_at,
        occurred_at,
        event.event_type,
        _basename(event.source_path),
        _basename(event.destination_path),
        event.drive,
        event.drive_type,
        event.severity.upper(),
        (event.status or "")[:1000],
        event.agent_id,
    )
    with _connect() as connection:
        cursor = connection.execute(
            """INSERT INTO events (
                received_at, occurred_at, event_type, source_name, destination_name,
                drive, drive_type, severity, status, agent_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            record,
        )
        connection.commit()
        event_id = cursor.lastrowid
    return {"accepted": True, "event_id": event_id}


@app.get("/api/demo-events")
def demo_events() -> dict:
    now = datetime.now(timezone.utc)
    examples = [
        ("FILE_CREATED", "sample.txt", None, "INFO", "Detected"),
        ("FILE_HASHED", "sample.txt", None, "INFO", "Baseline hash stored"),
        ("FILE_MODIFIED", "sample.txt", None, "INFO", "Detected"),
        ("INTEGRITY_CHANGED", "sample.txt", None, "WARNING", "SHA256_MISMATCH | MD5_MISMATCH"),
        ("POLICY_VIOLATION", "test.ps1", None, "WARNING", "SUSPICIOUS_FILE_EXTENSION: Suspicious extension detected"),
        ("FILE_MOVED", "sample.txt", "approved-folder", "INFO", "Detected"),
    ]
    events = []
    for index, (kind, source, destination, severity, note) in enumerate(examples):
        events.append({
            "id": f"demo-{index + 1}",
            "received_at": (now.replace(microsecond=0)).isoformat(),
            "occurred_at": (now.replace(microsecond=0)).isoformat(),
            "event_type": kind,
            "source_name": source,
            "destination_name": destination,
            "drive": "DEMO",
            "drive_type": "DEMO",
            "severity": severity,
            "status": note,
            "agent_id": "DEMO-ONLY",
            "demo": True,
        })
    return {"events": events, "notice": "These are synthetic examples for interface preview; they are not live endpoint telemetry."}


def _bundle_files() -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    for path in sorted((ROOT_DIR / "src").glob("*.py")):
        if path.name == "__init__.py":
            continue
        files.append((path, f"secure-file-transfer-monitoring-agent/src/{path.name}"))
    required = [
        (ROOT_DIR / "config" / "config.json", "secure-file-transfer-monitoring-agent/config/config.json"),
        (ROOT_DIR / "requirements.txt", "secure-file-transfer-monitoring-agent/requirements.txt"),
        (ROOT_DIR / "windows_agent" / "Run_Auditor_Agent.bat", "secure-file-transfer-monitoring-agent/Run_Auditor_Agent.bat"),
        (ROOT_DIR / "windows_agent" / "AUDITOR_INSTRUCTIONS.txt", "secure-file-transfer-monitoring-agent/AUDITOR_INSTRUCTIONS.txt"),
    ]
    for path, archive_name in required:
        if path.is_file():
            files.append((path, archive_name))
    return files


@app.get("/download/windows-agent.zip")
def download_windows_agent() -> StreamingResponse:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, archive_name in _bundle_files():
            archive.write(path, archive_name)
    buffer.seek(0)
    headers = {"Content-Disposition": 'attachment; filename="secure-file-transfer-windows-agent.zip"'}
    return StreamingResponse(buffer, media_type="application/zip", headers=headers)


DASHBOARD_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure File Transfer Monitoring System</title>
<style>
:root{font-family:Inter,Segoe UI,Arial,sans-serif;color:#172033;background:#f4f7fb;font-synthesis:none}*{box-sizing:border-box}body{margin:0}.shell{max-width:1120px;margin:0 auto;padding:36px 22px 60px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}.eyebrow{font-size:12px;letter-spacing:.13em;text-transform:uppercase;color:#53647f;font-weight:700}.title{font-size:30px;line-height:1.15;margin:9px 0 8px}.sub{color:#5c6880;margin:0}.pill{border-radius:999px;padding:8px 12px;font-size:12px;font-weight:700;background:#e6f6ed;color:#167344}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:28px 0}.card,.panel{background:#fff;border:1px solid #e1e7f0;border-radius:15px;box-shadow:0 5px 18px rgba(24,42,75,.04)}.card{padding:19px}.label{font-size:12px;color:#6d7890}.value{font-size:27px;font-weight:750;margin-top:7px}.actions{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:22px}.action{display:block;padding:16px;text-decoration:none;color:#172033;background:#fff;border:1px solid #e1e7f0;border-radius:13px;font-weight:700}.action span{display:block;font-size:12px;color:#68758c;font-weight:400;margin-top:5px}.primary{background:#1f4f9b;color:#fff;border-color:#1f4f9b}.primary span{color:#dce8ff}.panel{padding:20px}.panelhead{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:14px}.tabs{display:flex;gap:8px}.tab,button{font:inherit;border:1px solid #d8dfeb;background:#fff;border-radius:9px;padding:9px 13px;cursor:pointer}.tab.active{background:#eaf1ff;border-color:#aac4f4;color:#174b9d;font-weight:700}.notice{background:#fff8e7;color:#745515;padding:12px 14px;border-radius:10px;font-size:13px;margin:16px 0}.demo{background:#eef4ff;color:#214d89}.tablewrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:#63708a;font-size:11px;text-transform:uppercase;letter-spacing:.06em;padding:12px 10px;border-bottom:1px solid #e5eaf2}td{padding:13px 10px;border-bottom:1px solid #edf0f5;white-space:nowrap}.tag{display:inline-block;border-radius:999px;padding:4px 8px;font-size:10px;font-weight:800;background:#edf1f6;color:#4c5a70}.tag.warning{background:#fff0e6;color:#a94c17}.tag.error{background:#fee9e9;color:#a32323}.muted{color:#758198}.footer{color:#7a869a;font-size:12px;margin-top:18px;line-height:1.6}.hidden{display:none}@media(max-width:760px){.cards,.actions{grid-template-columns:1fr}.title{font-size:25px}}
</style></head><body><main class="shell">
<div class="top"><div><div class="eyebrow">Auditor portal · Windows endpoint monitoring</div><h1 class="title">Secure File Transfer<br>Monitoring System</h1><p class="sub">File activity visibility · SHA-256 integrity checks · Security policy alerts</p></div><div class="pill" id="serviceStatus">● Service status: checking</div></div>
<div class="cards"><div class="card"><div class="label">Live events received</div><div class="value" id="totalEvents">—</div></div><div class="card"><div class="label">Warning / error events</div><div class="value" id="alertCount">—</div></div><div class="card"><div class="label">Last event received</div><div class="value" style="font-size:16px" id="lastEvent">No events yet</div></div></div>
<div class="actions"><a class="action primary" href="/download/windows-agent.zip">↓ Download Windows Agent<span>ZIP bundle · Windows 10/11 · Python required</span></a><a class="action" href="https://github.com/Hiteshkendre11/secure-file-transfer-monitoring-system" target="_blank" rel="noreferrer">↗ View GitHub Source<span>Review source code and project report</span></a><a class="action" href="/health" target="_blank">✓ Service Health<span>Check cloud API availability</span></a></div>
<div class="notice" id="agentNotice">Live agent ingestion requires the project administrator to configure an API token on the hosting service. Ask the administrator for the token through an approved private channel; do not place it in a public issue or repository.</div>
<div class="panel"><div class="panelhead"><div><strong>Monitoring event stream</strong><div class="muted" style="font-size:12px;margin-top:4px">Live records are received from configured Windows agents. Demo records are synthetic examples.</div></div><div class="tabs"><button class="tab active" id="liveTab" onclick="setMode('live')">Live events</button><button class="tab" id="demoTab" onclick="setMode('demo')">Demo mode</button></div></div><div id="modeNotice" class="notice hidden"></div><div class="tablewrap"><table><thead><tr><th>Time received</th><th>Event</th><th>File</th><th>Severity</th><th>Agent</th><th>Result</th></tr></thead><tbody id="eventRows"><tr><td colspan="6" class="muted">Loading…</td></tr></tbody></table></div><div class="footer" id="refreshNote">Live mode refreshes automatically every 5 seconds.</div></div>
<div class="footer">Privacy: the cloud receiver stores event metadata and file names only. It does not upload file contents or full local filesystem paths. Policy alerts are detection-only; the endpoint agent does not block Windows file operations.</div>
</main><script>
let mode='live';let timer=null;
function esc(v){return String(v??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function severityTag(s){let v=String(s||'INFO').toUpperCase();let cls=(v==='ERROR'||v==='CRITICAL')?'error':(v==='WARNING'?'warning':'');return `<span class="tag ${cls}">${esc(v)}</span>`;}
function render(rows){let body=document.getElementById('eventRows');if(!rows.length){body.innerHTML='<tr><td colspan="6" class="muted">No live events yet. Download and configure the Windows agent, or switch to Demo mode to preview the dashboard.</td></tr>';return;}body.innerHTML=rows.map(e=>`<tr><td>${esc(e.received_at)}</td><td><strong>${esc(e.event_type)}</strong></td><td>${esc(e.source_name||e.destination_name||'—')}</td><td>${severityTag(e.severity)}</td><td>${esc(e.agent_id)}</td><td>${esc(e.status)}</td></tr>`).join('');}
async function load(){try{let [s,ev]=await Promise.all([fetch('/api/status').then(r=>r.json()),fetch(mode==='demo'?'/api/demo-events':'/api/events?limit=100').then(r=>r.json())]);document.getElementById('serviceStatus').textContent='● Service status: online';document.getElementById('totalEvents').textContent=mode==='demo'?ev.events.length:s.total_events;document.getElementById('alertCount').textContent=mode==='demo'?ev.events.filter(e=>e.severity==='WARNING').length:s.alerts;document.getElementById('lastEvent').textContent=mode==='demo'?'Sample data':(s.last_event_at||'No events yet');render(ev.events||[]);document.getElementById('agentNotice').classList.toggle('hidden',!!s.agent_ingestion_configured);document.getElementById('modeNotice').textContent=mode==='demo'?(ev.notice||'Synthetic demo records only.'):(s.storage_note||'');document.getElementById('modeNotice').classList.toggle('hidden',mode!=='demo'&&!s.storage_note);}catch(e){document.getElementById('serviceStatus').textContent='● Service status: unavailable';}}
function setMode(next){mode=next;document.getElementById('liveTab').classList.toggle('active',mode==='live');document.getElementById('demoTab').classList.toggle('active',mode==='demo');load();}
load();timer=setInterval(()=>{if(mode==='live')load();},5000);
</script></body></html>'''


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return DASHBOARD_HTML
