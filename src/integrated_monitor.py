
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
from hash_store import (
    store_file_hashes,
    get_file_hashes,
    move_file_hash
)


# ============================================================
# CONFIGURATION
# ============================================================

CONFIG_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "config",
        "config.json"
    )
)


def load_config():
    """Load and validate the monitoring configuration."""

    with open(CONFIG_PATH, "r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    required_keys = [
        "monitoring",
        "sensitive_paths",
        "restricted_destinations",
        "allowed_destinations",
        "suspicious_extensions",
        "alerts"
    ]

    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing configuration key: {key}")

    if not isinstance(config["monitoring"], dict):
        raise ValueError("'monitoring' must be an object.")

    if not isinstance(config["alerts"], dict):
        raise ValueError("'alerts' must be an object.")

    for key in [
        "sensitive_paths",
        "restricted_destinations",
        "allowed_destinations",
        "suspicious_extensions"
    ]:
        if not isinstance(config[key], list):
            raise ValueError(f"'{key}' must be a list.")

    return config


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

TRANSFER_TEST_PATH = os.path.join(
    PROJECT_ROOT,
    "TransferTest"
)

DESTINATION_PATH = os.path.join(
    PROJECT_ROOT,
    "Destination"
)

MONITOR_PATHS = [
    TRANSFER_TEST_PATH,
    DESTINATION_PATH
]


# ============================================================
# DRIVE FUNCTIONS
# ============================================================

def get_current_drives():
    """Return all currently available Windows drives."""

    drives = set()

    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"

        try:
            drive_type = win32file.GetDriveType(drive)

            if drive_type != win32file.DRIVE_NO_ROOT_DIR:
                drives.add(drive)

        except Exception:
            pass

    return drives


def get_drive_type(drive):
    """Identify the type of a Windows drive."""

    try:
        drive_type = win32file.GetDriveType(drive)

        drive_types = {
            win32file.DRIVE_UNKNOWN: "UNKNOWN",
            win32file.DRIVE_NO_ROOT_DIR: "NO_ROOT_DIR",
            win32file.DRIVE_REMOVABLE: "REMOVABLE",
            win32file.DRIVE_FIXED: "FIXED",
            win32file.DRIVE_REMOTE: "NETWORK",
            win32file.DRIVE_CDROM: "CDROM",
            win32file.DRIVE_RAMDISK: "RAMDISK",
        }

        return drive_types.get(drive_type, "UNKNOWN")

    except Exception:
        return "UNKNOWN"


def check_drive_accessibility(drive):
    """Check whether a drive is currently accessible."""

    try:
        os.listdir(drive)
        return True, "Accessible"

    except PermissionError:
        return False, "Access denied"

    except OSError as error:
        return False, str(error)

    except Exception as error:
        return False, str(error)


# ============================================================
# FILE SYSTEM MONITOR
# ============================================================

class FileMonitorHandler(FileSystemEventHandler):

    def __init__(self, config):
        super().__init__()

        self.config = config
        self.last_modified = {}
        self.modify_debounce_seconds = 1.0

    def is_path_within(self, path, configured_path):
        """Return True when path is the configured path or inside it."""

        try:
            path = os.path.normcase(os.path.abspath(path))
            configured_path = os.path.normcase(os.path.abspath(configured_path))
            return os.path.commonpath([path, configured_path]) == configured_path
        except (ValueError, OSError):
            return False

    def matches_any_path(self, path, configured_paths):
        """Check a path against a list of configured directories."""

        return any(
            self.is_path_within(path, configured_path)
            for configured_path in configured_paths
        )

    def report_policy_violation(
        self,
        policy_name,
        file_path,
        message,
        destination_path="N/A"
    ):
        """Print and log a policy alert when policy alerts are enabled."""

        alerts = self.config.get("alerts", {})

        if not alerts.get("enabled", False):
            return

        if not alerts.get("log_policy_violations", False):
            return

        timestamp = self.get_timestamp()

        print(
            f"[{timestamp}] [POLICY VIOLATION] "
            f"{policy_name}: {file_path}"
        )
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
        """Evaluate sensitive-path and suspicious-extension policies."""

        if not file_path or file_path == "N/A":
            return

        # Sensitive paths: activity involving files under configured paths is flagged.
        sensitive_paths = self.config.get("sensitive_paths", [])
        if self.matches_any_path(file_path, sensitive_paths):
            self.report_policy_violation(
                "SENSITIVE_PATH_ACTIVITY",
                file_path,
                f"File activity detected during {event_type}.",
                destination_path
            )

        # Suspicious extensions: flag matching file extensions.
        extension = os.path.splitext(file_path)[1].lower()
        suspicious_extensions = {
            item.lower() for item in self.config.get("suspicious_extensions", [])
        }

        if extension in suspicious_extensions:
            self.report_policy_violation(
                "SUSPICIOUS_FILE_EXTENSION",
                file_path,
                f"Suspicious extension '{extension}' detected during {event_type}.",
                destination_path
            )

    def check_destination_policies(self, destination_path, event_type, source_path="N/A"):
        """Check restricted and allowed destination rules for destination activity."""

        if not destination_path or destination_path == "N/A":
            return

        restricted = self.config.get("restricted_destinations", [])
        if self.matches_any_path(destination_path, restricted):
            self.report_policy_violation(
                "RESTRICTED_DESTINATION",
                source_path if source_path != "N/A" else destination_path,
                f"File {event_type} detected in a restricted destination.",
                destination_path
            )
            return

        # TransferTest is the staging/source folder, not a final destination.
        # Enforce the allow-list only for files entering the Destination folder.
        if self.is_path_within(destination_path, DESTINATION_PATH):
            allowed = self.config.get("allowed_destinations", [])
            if allowed and not self.matches_any_path(destination_path, allowed):
                self.report_policy_violation(
                    "UNAPPROVED_DESTINATION",
                    source_path if source_path != "N/A" else destination_path,
                    f"File {event_type} detected outside configured allowed destinations.",
                    destination_path
                )

    def get_timestamp(self):
        """Return current local date/time with milliseconds."""

        return datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]

    def get_drive(self, path):
        """Get the Windows drive letter from a path."""

        drive = os.path.splitdrive(path)[0]

        if drive:
            return drive + "\\"

        return "UNKNOWN"

    def is_noise(self, path):
        """Filter common temporary/system filesystem noise."""

        path_lower = os.path.abspath(path).lower()

        ignored_extensions = (
            ".tmp",
            ".temp",
            ".pf",
            ".ldb",
            ".jfm",
            ".db-wal",
            ".db-shm",
        )

        ignored_paths = (
            "\\appdata\\local\\temp\\",
            "\\appdata\\local\\google\\chrome\\",
            "\\appdata\\local\\microsoft\\edge\\",
            "\\windows\\prefetch\\",
        )

        if path_lower.endswith(ignored_extensions):
            return True

        for ignored_path in ignored_paths:
            if ignored_path in path_lower:
                return True

        return False

    # ========================================================
    # HASH FUNCTIONS
    # ========================================================

    def calculate_and_store_hash(self, file_path):
        """Calculate SHA-256 and MD5 hashes and store the baseline."""

        try:
            hashes = calculate_file_hashes(file_path)

            store_file_hashes(
                file_path,
                hashes["sha256"],
                hashes["md5"]
            )

            return hashes

        except (
            FileNotFoundError,
            PermissionError,
            OSError
        ):
            return None

        except Exception:
            return None

    def check_file_integrity(self, file_path):
        """Compare current file hashes against the stored baseline."""

        try:
            stored_hashes = get_file_hashes(file_path)

            if stored_hashes is None:
                return {
                    "status": "NO_BASELINE",
                    "sha256_match": None,
                    "md5_match": None,
                    "current_sha256": None,
                    "current_md5": None
                }

            current_hashes = calculate_file_hashes(file_path)

            sha256_match = (
                stored_hashes["sha256"].lower()
                == current_hashes["sha256"].lower()
            )

            md5_match = (
                stored_hashes["md5"].lower()
                == current_hashes["md5"].lower()
            )

            status = (
                "UNCHANGED"
                if sha256_match and md5_match
                else "CHANGED"
            )

            return {
                "status": status,
                "sha256_match": sha256_match,
                "md5_match": md5_match,
                "current_sha256": current_hashes["sha256"],
                "current_md5": current_hashes["md5"]
            }

        except (
            FileNotFoundError,
            PermissionError,
            OSError
        ):
            return {
                "status": "CHECK_FAILED",
                "sha256_match": None,
                "md5_match": None,
                "current_sha256": None,
                "current_md5": None
            }

        except Exception:
            return {
                "status": "CHECK_FAILED",
                "sha256_match": None,
                "md5_match": None,
                "current_sha256": None,
                "current_md5": None
            }

    # ========================================================
    # FILE CREATED
    # ========================================================

    def on_created(self, event):

        if event.is_directory:
            return

        if self.is_noise(event.src_path):
            return

        timestamp = self.get_timestamp()

        print(
            f"[{timestamp}] [CREATED] "
            f"{event.src_path}"
        )

        log_event(
            event_type="FILE_CREATED",
            source_path=event.src_path,
            drive=self.get_drive(event.src_path),
            severity="INFO",
            status="Detected"
        )

        self.check_file_policies(event.src_path, "file creation")
        self.check_destination_policies(
            event.src_path,
            "creation"
        )

        hashes = self.calculate_and_store_hash(event.src_path)

        if hashes is not None:

            print(
                f"[{timestamp}] [HASHED] "
                f"{event.src_path}"
            )

            log_event(
                event_type="FILE_HASHED",
                source_path=event.src_path,
                drive=self.get_drive(event.src_path),
                severity="INFO",
                status="Baseline hash stored"
            )

        else:

            print(
                f"[{timestamp}] [HASH FAILED] "
                f"{event.src_path}"
            )

            log_event(
                event_type="FILE_HASH_FAILED",
                source_path=event.src_path,
                drive=self.get_drive(event.src_path),
                severity="WARNING",
                status="Unable to calculate baseline hash"
            )

    # ========================================================
    # FILE MODIFIED
    # ========================================================

    def on_modified(self, event):

        if event.is_directory:
            return

        if self.is_noise(event.src_path):
            return

        current_time = time.monotonic()

        last_time = self.last_modified.get(event.src_path)

        if last_time is not None:
            elapsed = current_time - last_time

            if elapsed < self.modify_debounce_seconds:
                return

        self.last_modified[event.src_path] = current_time

        timestamp = self.get_timestamp()

        print(
            f"[{timestamp}] [MODIFIED] "
            f"{event.src_path}"
        )

        log_event(
            event_type="FILE_MODIFIED",
            source_path=event.src_path,
            drive=self.get_drive(event.src_path),
            severity="INFO",
            status="Detected"
        )

        self.check_file_policies(event.src_path, "file modification")

        integrity = self.check_file_integrity(event.src_path)

        if integrity["status"] == "UNCHANGED":

            print(
                f"[{timestamp}] [INTEGRITY OK] "
                f"{event.src_path}"
            )

            log_event(
                event_type="INTEGRITY_CHECK",
                source_path=event.src_path,
                drive=self.get_drive(event.src_path),
                severity="INFO",
                status="UNCHANGED"
            )

        elif integrity["status"] == "CHANGED":

            print(
                f"[{timestamp}] [INTEGRITY CHANGED] "
                f"{event.src_path}"
            )

            print(
                f"    SHA-256 Match: "
                f"{integrity['sha256_match']}"
            )

            print(
                f"    MD5 Match: "
                f"{integrity['md5_match']}"
            )

            log_event(
                event_type="INTEGRITY_CHANGED",
                source_path=event.src_path,
                drive=self.get_drive(event.src_path),
                severity="WARNING",
                status="SHA256_MISMATCH | MD5_MISMATCH"
            )

        elif integrity["status"] == "NO_BASELINE":

            print(
                f"[{timestamp}] [NO BASELINE] "
                f"{event.src_path}"
            )

            log_event(
                event_type="INTEGRITY_CHECK",
                source_path=event.src_path,
                drive=self.get_drive(event.src_path),
                severity="INFO",
                status="NO_BASELINE"
            )

        else:

            print(
                f"[{timestamp}] [INTEGRITY CHECK FAILED] "
                f"{event.src_path}"
            )

            log_event(
                event_type="INTEGRITY_CHECK_FAILED",
                source_path=event.src_path,
                drive=self.get_drive(event.src_path),
                severity="WARNING",
                status="Unable to calculate current hash"
            )

    # ========================================================
    # FILE DELETED
    # ========================================================

    def on_deleted(self, event):

        if event.is_directory:
            return

        if self.is_noise(event.src_path):
            return

        timestamp = self.get_timestamp()

        print(
            f"[{timestamp}] [DELETED] "
            f"{event.src_path}"
        )

        log_event(
            event_type="FILE_DELETED",
            source_path=event.src_path,
            drive=self.get_drive(event.src_path),
            severity="INFO",
            status="Detected"
        )

    # ========================================================
    # FILE MOVED
    # ========================================================

    def on_moved(self, event):

        if event.is_directory:
            return

        if (
            self.is_noise(event.src_path)
            and self.is_noise(event.dest_path)
        ):
            return

        timestamp = self.get_timestamp()

        print(
            f"[{timestamp}] [MOVED] "
            f"{event.src_path} -> "
            f"{event.dest_path}"
        )

        log_event(
            event_type="FILE_MOVED",
            source_path=event.src_path,
            destination_path=event.dest_path,
            drive=self.get_drive(event.dest_path),
            severity="INFO",
            status="Detected"
        )

        self.check_file_policies(
            event.src_path,
            "file move (source path)",
            event.dest_path
        )
        self.check_file_policies(
            event.dest_path,
            "file move (destination path)",
            event.dest_path
        )
        self.check_destination_policies(
            event.dest_path,
            "move",
            event.src_path
        )

        # Preserve the existing integrity baseline after a rename/move.
        try:
            baseline_moved = move_file_hash(
                event.src_path,
                event.dest_path
            )

            if baseline_moved:
                print(
                    f"[{timestamp}] [BASELINE MOVED] "
                    f"{event.dest_path}"
                )

                log_event(
                    event_type="HASH_BASELINE_MOVED",
                    source_path=event.src_path,
                    destination_path=event.dest_path,
                    drive=self.get_drive(event.dest_path),
                    severity="INFO",
                    status="Existing hash baseline migrated"
                )
            else:
                print(
                    f"[{timestamp}] [NO BASELINE TO MOVE] "
                    f"{event.src_path}"
                )

                log_event(
                    event_type="HASH_BASELINE_NOT_FOUND",
                    source_path=event.src_path,
                    destination_path=event.dest_path,
                    drive=self.get_drive(event.dest_path),
                    severity="INFO",
                    status="No stored baseline for source path"
                )

        except Exception as error:
            print(
                f"[{timestamp}] [BASELINE MOVE FAILED] {error}"
            )

            log_event(
                event_type="HASH_BASELINE_MOVE_FAILED",
                source_path=event.src_path,
                destination_path=event.dest_path,
                drive=self.get_drive(event.dest_path),
                severity="WARNING",
                status=f"Baseline migration failed: {error}"
            )


# ============================================================
# DRIVE MONITORING
# ============================================================

def start_drive_monitor(drive, drive_type, observers, config):
    """
    Monitor only TransferTest and Destination.

    Other drives are discovered for connection/removal logging,
    but their contents are not monitored during this test stage.
    """

    project_drive = (
        os.path.splitdrive(PROJECT_ROOT)[0] + "\\"
    )

    if os.path.normcase(drive) != os.path.normcase(project_drive):

        print()
        print("[MONITORING SKIPPED]")
        print(f"Drive: {drive}")
        print("Reason: Outside the current project test scope.")

        return False

    accessible, status = check_drive_accessibility(drive)

    if not accessible:

        print()
        print("[MONITORING SKIPPED]")
        print(f"Drive: {drive}")
        print(f"Type: {drive_type}")
        print(f"Reason: {status}")

        log_system_event(
            "DRIVE_MONITORING_SKIPPED",
            (
                f"DRIVE={drive} | "
                f"DRIVE_TYPE={drive_type} | "
                f"REASON={status}"
            ),
            severity="INFO"
        )

        return False

    existing_paths = [
        folder
        for folder in MONITOR_PATHS
        if os.path.isdir(folder)
    ]

    if not existing_paths:

        print("[MONITORING SKIPPED] Test folders were not found.")

        log_system_event(
            "TEST_FOLDERS_NOT_FOUND",
            f"PROJECT_ROOT={PROJECT_ROOT}",
            severity="WARNING"
        )

        return False

    try:

        event_handler = FileMonitorHandler(config)
        observer = Observer()

        for folder in existing_paths:

            observer.schedule(
                event_handler,
                folder,
                recursive=True
            )

        observer.start()

        observers[drive] = observer

        print()
        print("[MONITORING STARTED]")
        print(f"Drive: {drive}")
        print(f"Type: {drive_type}")
        print("Monitored folders:")

        for folder in existing_paths:
            print(f"  - {folder}")

        log_system_event(
            "TEST_FOLDER_MONITORING_STARTED",
            (
                f"DRIVE={drive} | "
                f"FOLDERS={'; '.join(existing_paths)}"
            ),
            severity="INFO"
        )

        return True

    except Exception as error:

        print()
        print("[MONITORING ERROR]")
        print(f"Drive: {drive}")
        print(f"Error: {error}")

        log_system_event(
            "DRIVE_MONITORING_ERROR",
            (
                f"DRIVE={drive} | "
                f"DRIVE_TYPE={drive_type} | "
                f"ERROR={error}"
            ),
            severity="ERROR"
        )

        return False


def stop_drive_monitor(drive, observers):
    """Stop monitoring a drive."""

    observer = observers.get(drive)

    if observer is None:
        return

    try:
        observer.stop()
        observer.join(timeout=2)

    except Exception:
        pass

    observers.pop(drive, None)

    print()
    print("[MONITORING STOPPED]")
    print(f"Drive: {drive}")

    log_system_event(
        "DRIVE_MONITORING_STOPPED",
        f"DRIVE={drive}",
        severity="INFO"
    )


# ============================================================
# INTEGRATED MONITOR
# ============================================================

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

    print()
    print("INITIAL DRIVE DISCOVERY")
    print("-" * 70)

    for drive in sorted(previous_drives):

        drive_type = get_drive_type(drive)

        print(f"{drive} -> {drive_type}")

        start_drive_monitor(
            drive,
            drive_type,
            observers,
            config
        )

    print()
    print("-" * 70)

    print(
        "Test-folder monitoring is active "
        "(TransferTest and Destination)."
    )

    print("Drive and USB connection/removal detection is active.")
    print("Other drive contents are not monitored in this test stage.")
    print("Filesystem event filtering is active.")
    print("Modification debouncing is active.")
    print("SHA-256 and MD5 baseline hashing is active.")
    print("File integrity comparison is active.")
    print("Security policy detection is active (alert-only mode).")
    print("File operations are detected and logged, not blocked.")
    print("Press Ctrl+C to stop.")

    print("-" * 70)

    try:

        while True:

            time.sleep(2)

            current_drives = get_current_drives()

            # =================================================
            # NEW DRIVES
            # =================================================

            new_drives = current_drives - previous_drives

            for drive in sorted(new_drives):

                drive_type = get_drive_type(drive)

                accessible, status = check_drive_accessibility(drive)

                print()
                print("[DRIVE DETECTED]")
                print(f"Drive: {drive}")
                print(f"Type: {drive_type}")
                print(f"Accessibility: {status}")

                if drive_type == "REMOVABLE":

                    print(
                        "[USB DETECTED] "
                        "Removable drive connected."
                    )

                    log_system_event(
                        "USB_CONNECTED",
                        (
                            f"DRIVE={drive} | "
                            f"DRIVE_TYPE={drive_type} | "
                            f"ACCESSIBILITY={status}"
                        ),
                        severity="INFO"
                    )

                else:

                    log_system_event(
                        "DRIVE_CONNECTED",
                        (
                            f"DRIVE={drive} | "
                            f"DRIVE_TYPE={drive_type} | "
                            f"ACCESSIBILITY={status}"
                        ),
                        severity="INFO"
                    )

                start_drive_monitor(
                    drive,
                    drive_type,
                    observers,
                    config
                )

            # =================================================
            # REMOVED DRIVES
            # =================================================

            removed_drives = previous_drives - current_drives

            for drive in sorted(removed_drives):

                print()
                print("[DRIVE REMOVED]")
                print(f"Drive: {drive}")
                print("[STATUS] Drive is no longer available.")

                log_system_event(
                    "DRIVE_REMOVED",
                    (
                        f"DRIVE={drive} | "
                        f"STATUS=No longer available"
                    ),
                    severity="INFO"
                )

                stop_drive_monitor(
                    drive,
                    observers
                )

            previous_drives = current_drives

    except KeyboardInterrupt:

        print()
        print("=" * 70)
        print("Stopping integrated monitor...")
        print("=" * 70)

        for drive in list(observers.keys()):

            stop_drive_monitor(
                drive,
                observers
            )

        print()
        print("Integrated monitoring stopped.")


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    start_integrated_monitor()
