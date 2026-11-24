"""Optional HTTPS event forwarding to the SFTMS cloud auditor dashboard."""

import json
import os
import urllib.error
import urllib.request
from pathlib import PureWindowsPath, PurePosixPath
from datetime import datetime, timezone


def forward_event(event: dict) -> bool:
    """Send event metadata when cloud environment variables are configured.

    Local logging is independent from cloud forwarding. Network or API failures
    are intentionally swallowed so they never stop the Windows file monitor.
    File contents and hash values are not sent.
    """
    base_url = os.getenv("MONITOR_API_URL", "").strip().rstrip("/")
    token = os.getenv("MONITOR_API_TOKEN", "").strip()
    if not base_url or not token:
        return False

    payload = dict(event)
    # Strip directory components before anything leaves the Windows endpoint.
    for path_key in ("source_path", "destination_path"):
        value = payload.get(path_key)
        if value and value != "N/A":
            normalized = str(value).replace("\\", "/")
            payload[path_key] = normalized.rstrip("/").split("/")[-1][:255]
    payload.setdefault("agent_id", os.getenv("MONITOR_AGENT_ID", "windows-agent")[:64])
    payload.setdefault("occurred_at", datetime.now(timezone.utc).isoformat(timespec="seconds"))

    request = urllib.request.Request(
        url=f"{base_url}/api/events",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "SFTMS-Windows-Agent/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False
