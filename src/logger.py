import logging
import os
from datetime import datetime

try:
    from cloud_forwarder import forward_event
except ImportError:
    def forward_event(event):
        return False


LOG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "logs"
)
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "file_activity.log")

logger = logging.getLogger("SecureFileMonitor")
logger.setLevel(logging.INFO)

if not logger.handlers:
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    formatter = logging.Formatter(
        "%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def log_event(
    event_type,
    source_path="N/A",
    destination_path="N/A",
    drive="N/A",
    drive_type="N/A",
    user="N/A",
    process="N/A",
    severity="INFO",
    status="Detected"
):
    """Write locally and optionally forward a metadata-only cloud event."""
    message = (
        f"EVENT={event_type} | "
        f"SOURCE={source_path} | "
        f"DESTINATION={destination_path} | "
        f"DRIVE={drive} | "
        f"DRIVE_TYPE={drive_type} | "
        f"USER={user} | "
        f"PROCESS={process} | "
        f"SEVERITY={severity} | "
        f"STATUS={status}"
    )
    logger.info(message)
    forward_event({
        "event_type": str(event_type),
        "source_path": str(source_path),
        "destination_path": str(destination_path),
        "drive": str(drive),
        "drive_type": str(drive_type),
        "user": str(user),
        "process": str(process),
        "severity": str(severity),
        "status": str(status),
    })


def log_system_event(event_type, message, severity="INFO"):
    """Write a system event and optionally forward its metadata."""
    logger.info(
        f"EVENT={event_type} | "
        f"SEVERITY={severity} | "
        f"{message}"
    )
    forward_event({
        "event_type": str(event_type),
        "severity": str(severity),
        "status": str(message),
    })


def get_log_file():
    """Return the local audit log path."""
    return LOG_FILE
