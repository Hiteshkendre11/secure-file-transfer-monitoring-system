import time
import string
import os
import json
from datetime import datetime

import win32file

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from logger import log_event, log_system_event
from hash_monitor import calculate_file_hashes
from hash_store import store_file_hashes, get_file_hashes, move_file_hash


CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config", "config.json"))
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TRANSFER_TEST_PATH = os.path.join(PROJECT_ROOT, "TransferTest")
DESTINATION_PATH = os.path.join(PROJECT_ROOT, "Destination")
MONITOR_PATHS = [TRANSFER_TEST_PATH, DESTINATION_PATH]


def load_config():
    """Load config and expand portable ${PROJECT_ROOT} path placeholders."""
    with open(CONFIG_PATH, "r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    required_keys = ["monitoring", "sensitive_paths", "restricted_destinations", "allowed_destinations", "suspicious_extensions", "alerts"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing configuration key: {key}")
    if not isinstance(config["monitoring"], dict):
        raise ValueError("'monitoring' must be an object.")
    if not isinstance(config["alerts"], dict):
        raise ValueError("'alerts' must be an object.")
    for key in ["sensitive_paths", "restricted_destinations", "allowed_destinations", "suspicious_extensions"]:
        if not isinstance(config[key], list):
            raise ValueError(f"'{key}' must be a list.")

    for key in ["sensitive_paths", "restricted_destinations", "allowed_destinations"]:
        config[key] = [
            value.replace("${PROJECT_ROOT}", PROJECT_ROOT) if isinstance(value, str) else value
            for value in config[key]
        ]
    return config


def get_current_drives():
    drives = set()
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        try:
            if win32file.GetDriveType(drive) != win32file.DRIVE_NO_ROOT_DIR:
                drives.add(drive)
        except Exception:
            pass
    return drives


def get_drive_type(drive):
    try:
        drive_type = win32file.GetDriveType(drive)
        return {
            win32file.DRIVE_UNKNOWN: "UNKNOWN",
            win32file.DRIVE_NO_ROOT_DIR: "NO_ROOT_DIR",
            win32file.DRIVE_REMOVABLE: "REMOVABLE",
            win32file.DRIVE_FIXED: "FIXED",
            win32file.DRIVE_REMOTE: "NETWORK",
            win32file.DRIVE_CDROM: "CDROM",
            win32file.DRIVE_RAMDISK: "RAMDISK",
        }.get(drive_type, "UNKNOWN")
    except Exception:
        return "UNKNOWN"


def check_drive_accessibility(drive):
    try:
        os.listdir(drive)
        return True, "Accessible"
    except PermissionError:
        return False, "Access denied"
    except OSError as error:
        return False, str(error)
    except Exception as error:
        return False, str(error)


class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.last_modified = {}
        self.modify_debounce_seconds = 1.0

    def is_path_within(self, path, configured_path):
        try:
            path = os.path.normcase(os.path.abspath(path))
            configured_path = os.path.normcase(os.path.abspath(configured_path))
            return os.path.commonpath([path, configured_path]) == configured_path
        except (ValueError, OSError):
            return False

    def matches_any_path(self, path, configured_paths):
        return any(self.is_path_within(path, item) for item in configured_paths)

    def get_timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def get_drive(self, path):
        drive = os.path.splitdrive(path)[0]
        return drive + "\\" if drive else "UNKNOWN"

    def is_noise(self, path):
        path_lower = os.path.abspath(path).lower()
        ignored_extensions = (".tmp", ".temp", ".pf", ".ldb", ".jfm", ".db-wal", ".db-shm")
        ignored_paths = ("\\appdata\\local\\temp\\", "\\appdata\\local\\google\\chrome\\", "\\appdata\\local\\microsoft\\edge\\", "\\windows\\prefetch\\")
        return path_lower.endswith(ignored_extensions) or any(item in path_lower for item in ignored_paths)

    def report_policy_violation(self, policy_name, file_path, message, destination_path="N/A"):
        alerts = self.config.get("alerts", {})
        if not alerts.get("enabled", False) or not alerts.get("log_policy_violations", False):
            return
        timestamp = self.get_timestamp()
        print(f"[{timestamp}] [POLICY VIOLATION] {policy_name}: {file_path}")
        print(f"    {message}")
        log_event(
            event_type="POLICY_VIOLATION",
            source_path=file_path,
            destination_path=destination_path,
            drive=self.get_drive(destination_path if destination_path != "N/A" else file_path),
            severity="WARNING",
            status=f"{policy_name}: {message}"
        )

    def check_file_policies(self, file_path, event_type, destination_path="N/A"):
        if not file_path or file_path == "N/A":
            return
        if self.matches_any_path(file_path, self.config.get("sensitive_paths", [])):
            self.report_policy_violation("SENSITIVE_PATH_ACTIVITY", file_path, f"File activity detected during {event_type}.", destination_path)
        extension = os.path.splitext(file_path)[1].lower()
        suspicious = {item.lower() for item in self.config.get("suspicious_extensions", [])}
        if extension in suspicious:
            self.report_policy_violation("SUSPICIOUS_FILE_EXTENSION", file_path, f"Suspicious extension '{extension}' detected during {event_type}.", destination_path)

    def check_destination_policies(self, destination_path, event_type, source_path="N/A"):
        if not destination_path or destination_path == "N/A":
            return
        restricted = self.config.get("restricted_destinations", [])
        if self.matches_any_path(destination_path, restricted):
            self.report_policy_violation("RESTRICTED_DESTINATION", source_path if source_path != "N/A" else destination_path, f"File {event_type} detected in a restricted destination.", destination_path)
            return
        if self.is_path_within(destination_path, DESTINATION_PATH):
            allowed = self.config.get("allowed_destinations", [])
            if allowed and not self.matches_any_path(destination_path, allowed):
                self.report_policy_violation("UNAPPROVED_DESTINATION", source_path if source_path != "N/A" else destination_path, f"File {event_type} detected outside configured allowed destinations.", destination_path)

    def calculate_and_store_hash(self, file_path):
        try:
            hashes = calculate_file_hashes(file_path)
            store_file_hashes(file_path, hashes["sha256"], hashes["md5"])
            return hashes
        except (FileNotFoundError, PermissionError, OSError):
            return None
        except Exception:
            return None

    def check_file_integrity(self, file_path):
        try:
            stored = get_file_hashes(file_path)
            if stored is None:
                return {"status": "NO_BASELINE", "sha256_match": None, "md5_match": None}
            current = calculate_file_hashes(file_path)
            sha_ok = stored["sha256"].lower() == current["sha256"].lower()
            md5_ok = stored["md5"].lower() == current["md5"].lower()
            return {"status": "UNCHANGED" if sha_ok and md5_ok else "CHANGED", "sha256_match": sha_ok, "md5_match": md5_ok}
        except Exception:
            return {"status": "CHECK_FAILED", "sha256_match": None, "md5_match": None}

    def on_created(self, event):
        if event.is_directory or self.is_noise(event.src_path):
            return
        timestamp = self.get_timestamp()
        print(f"[{timestamp}] [CREATED] {event.src_path}")
        log_event("FILE_CREATED", source_path=event.src_path, drive=self.get_drive(event.src_path), severity="INFO", status="Detected")
        self.check_file_policies(event.src_path, "file creation")
        self.check_destination_policies(event.src_path, "creation")
        hashes = self.calculate_and_store_hash(event.src_path)
        if hashes:
            print(f"[{timestamp}] [HASHED] {event.src_path}")
            log_event("FILE_HASHED", source_path=event.src_path, drive=self.get_drive(event.src_path), severity="INFO", status="Baseline hash stored")
        else:
            print(f"[{timestamp}] [HASH FAILED] {event.src_path}")
            log_event("FILE_HASH_FAILED", source_path=event.src_path, drive=self.get_drive(event.src_path), severity="WARNING", status="Unable to calculate baseline hash")

    def on_modified(self, event):
        if event.is_directory or self.is_noise(event.src_path):
            return
        current_time = time.monotonic()
        last_time = self.last_modified.get(event.src_path)
        if last_time is not None and current_time - last_time < self.modify_debounce_seconds:
            return
        self.last_modified[event.src_path] = current_time
        timestamp = self.get_timestamp()
        print(f"[{timestamp}] [MODIFIED] {event.src_path}")
        log_event("FILE_MODIFIED", source_path=event.src_path, drive=self.get_drive(event.src_path), severity="INFO", status="Detected")
        self.check_file_policies(event.src_path, "file modification")
        integrity = self.check_file_integrity(event.src_path)
        if integrity["status"] == "UNCHANGED":
            print(f"[{timestamp}] [INTEGRITY OK] {event.src_path}")
            log_event("INTEGRITY_CHECK", source_path=event.src_path, drive=self.get_drive(event.src_path), severity="INFO", status="UNCHANGED")
        elif integrity["status"] == "CHANGED":
            print(f"[{timestamp}] [INTEGRITY CHANGED] {event.src_path}")
            print(f"    SHA-256 Match: {integrity['sha256_match']}")
            print(f"    MD5 Match: {integrity['md5_match']}")
            log_event("INTEGRITY_CHANGED", source_path=event.src_path, drive=self.get_drive(event.src_path), severity="WARNING", status="SHA256_MISMATCH | MD5_MISMATCH")
        elif integrity["status"] == "NO_BASELINE":
            print(f"[{timestamp}] [NO BASELINE] {event.src_path}")
            log_event("INTEGRITY_CHECK", source_path=event.src_path, drive=self.get_drive(event.src_path), severity="INFO", status="NO_BASELINE")
        else:
            print(f"[{timestamp}] [INTEGRITY CHECK FAILED] {event.src_path}")
            log_event("INTEGRITY_CHECK_FAILED", source_path=event.src_path, drive=self.get_drive(event.src_path), severity="WARNING", status="Unable to calculate current hash")

    def on_deleted(self, event):
        if event.is_directory or self.is_noise(event.src_path):
            return
        timestamp = self.get_timestamp()
        print(f"[{timestamp}] [DELETED] {event.src_path}")
        log_event("FILE_DELETED", source_path=event.src_path, drive=self.get_drive(event.src_path), severity="INFO", status="Detected")

    def on_moved(self, event):
        if event.is_directory or (self.is_noise(event.src_path) and self.is_noise(event.dest_path)):
            return
        timestamp = self.get_timestamp()
        print(f"[{timestamp}] [MOVED] {event.src_path} -> {event.dest_path}")
        log_event("FILE_MOVED", source_path=event.src_path, destination_path=event.dest_path, drive=self.get_drive(event.dest_path), severity="INFO", status="Detected")
        self.check_file_policies(event.src_path, "file move (source path)", event.dest_path)
        self.check_file_policies(event.dest_path, "file move (destination path)", event.dest_path)
        self.check_destination_policies(event.dest_path, "move", event.src_path)
        try:
            moved = move_file_hash(event.src_path, event.dest_path)
            if moved:
                print(f"[{timestamp}] [BASELINE MOVED] {event.dest_path}")
                log_event("HASH_BASELINE_MOVED", source_path=event.src_path, destination_path=event.dest_path, drive=self.get_drive(event.dest_path), severity="INFO", status="Existing hash baseline migrated")
            else:
                print(f"[{timestamp}] [NO BASELINE TO MOVE] {event.src_path}")
                log_event("HASH_BASELINE_NOT_FOUND", source_path=event.src_path, destination_path=event.dest_path, drive=self.get_drive(event.dest_path), severity="INFO", status="No stored baseline for source path")
        except Exception as error:
            print(f"[{timestamp}] [BASELINE MOVE FAILED] {error}")
            log_event("HASH_BASELINE_MOVE_FAILED", source_path=event.src_path, destination_path=event.dest_path, drive=self.get_drive(event.dest_path), severity="WARNING", status=f"Baseline migration failed: {error}")


def start_drive_monitor(drive, drive_type, observers, config):
    project_drive = os.path.splitdrive(PROJECT_ROOT)[0] + "\\"
    if os.path.normcase(drive) != os.path.normcase(project_drive):
        print("\n[MONITORING SKIPPED]")
        print(f"Drive: {drive}")
        print("Reason: Outside the current project test scope.")
        return False
    accessible, status = check_drive_accessibility(drive)
    if not accessible:
        print("\n[MONITORING SKIPPED]")
        print(f"Drive: {drive}\nType: {drive_type}\nReason: {status}")
        log_system_event("DRIVE_MONITORING_SKIPPED", f"DRIVE={drive} | DRIVE_TYPE={drive_type} | REASON={status}", severity="INFO")
        return False
    existing_paths = [folder for folder in MONITOR_PATHS if os.path.isdir(folder)]
    if not existing_paths:
        print("[MONITORING SKIPPED] Test folders were not found.")
        log_system_event("TEST_FOLDERS_NOT_FOUND", f"PROJECT_ROOT={PROJECT_ROOT}", severity="WARNING")
        return False
    try:
        observer = Observer()
        handler = FileMonitorHandler(config)
        for folder in existing_paths:
            observer.schedule(handler, folder, recursive=True)
        observer.start()
        observers[drive] = observer
        print("\n[MONITORING STARTED]")
        print(f"Drive: {drive}\nType: {drive_type}\nMonitored folders:")
        for folder in existing_paths:
            print(f"  - {folder}")
        log_system_event("TEST_FOLDER_MONITORING_STARTED", f"DRIVE={drive} | FOLDERS={'; '.join(existing_paths)}", severity="INFO")
        return True
    except Exception as error:
        print(f"\n[MONITORING ERROR]\nDrive: {drive}\nError: {error}")
        log_system_event("DRIVE_MONITORING_ERROR", f"DRIVE={drive} | DRIVE_TYPE={drive_type} | ERROR={error}", severity="ERROR")
        return False


def stop_drive_monitor(drive, observers):
    observer = observers.get(drive)
    if observer is None:
        return
    try:
        observer.stop()
        observer.join(timeout=2)
    except Exception:
        pass
    observers.pop(drive, None)
    print(f"\n[MONITORING STOPPED]\nDrive: {drive}")
    log_system_event("DRIVE_MONITORING_STOPPED", f"DRIVE={drive}", severity="INFO")


def start_integrated_monitor():
    config = load_config()
    if not config["monitoring"].get("enabled", False):
        print("[INFO] Monitoring is disabled in config.json.")
        return
    observers = {}
    previous_drives = get_current_drives()
    print("=" * 70)
    print("SECURE FILE TRANSFER MONITORING SYSTEM")
    print("=" * 70)
    print("\nINITIAL DRIVE DISCOVERY\n" + "-" * 70)
    for drive in sorted(previous_drives):
        drive_type = get_drive_type(drive)
        print(f"{drive} -> {drive_type}")
        start_drive_monitor(drive, drive_type, observers, config)
    print("\n" + "-" * 70)
    print("Test-folder monitoring is active (TransferTest and Destination).")
    print("Drive and USB connection/removal detection is active.")
    print("Other drive contents are not monitored in this test stage.")
    print("Filesystem event filtering is active.")
    print("Modification debouncing is active.")
    print("SHA-256 and MD5 baseline hashing is active.")
    print("File integrity comparison is active.")
    print("Security policy detection is active (alert-only mode).")
    print("File operations are detected and logged, not blocked.")
    if os.getenv("MONITOR_API_URL") and os.getenv("MONITOR_API_TOKEN"):
        print("Cloud event forwarding is configured.")
    else:
        print("Cloud event forwarding is not configured (local monitoring only).")
    print("Press Ctrl+C to stop.\n" + "-" * 70)
    try:
        while True:
            time.sleep(2)
            current_drives = get_current_drives()
            for drive in sorted(current_drives - previous_drives):
                drive_type = get_drive_type(drive)
                accessible, status = check_drive_accessibility(drive)
                print(f"\n[DRIVE DETECTED]\nDrive: {drive}\nType: {drive_type}\nAccessibility: {status}")
                if drive_type == "REMOVABLE":
                    print("[USB DETECTED] Removable drive connected.")
                    log_system_event("USB_CONNECTED", f"DRIVE={drive} | DRIVE_TYPE={drive_type} | ACCESSIBILITY={status}", severity="INFO")
                else:
                    log_system_event("DRIVE_CONNECTED", f"DRIVE={drive} | DRIVE_TYPE={drive_type} | ACCESSIBILITY={status}", severity="INFO")
                start_drive_monitor(drive, drive_type, observers, config)
            for drive in sorted(previous_drives - current_drives):
                print(f"\n[DRIVE REMOVED]\nDrive: {drive}\n[STATUS] Drive is no longer available.")
                log_system_event("DRIVE_REMOVED", f"DRIVE={drive} | STATUS=No longer available", severity="INFO")
                stop_drive_monitor(drive, observers)
            previous_drives = current_drives
    except KeyboardInterrupt:
        print("\n" + "=" * 70 + "\nStopping integrated monitor...\n" + "=" * 70)
        for drive in list(observers.keys()):
            stop_drive_monitor(drive, observers)
        print("\nIntegrated monitoring stopped.")


if __name__ == "__main__":
    start_integrated_monitor()
