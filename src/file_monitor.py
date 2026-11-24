from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import time
import os

from logger import log_event
from hash_monitor import calculate_file_hashes
from hash_store import store_file_hashes


class FileMonitorHandler(FileSystemEventHandler):

    def get_timestamp(self):
        """
        Return the current local Windows date and time
        with milliseconds.
        """
        return datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]

    def get_drive(self, path):
        """
        Get the drive letter from a Windows path.
        """
        return os.path.splitdrive(path)[0] + "\\"

    def calculate_and_store_hash(self, file_path):
        """
        Calculate SHA-256 and MD5 hashes for a file
        and store them as the baseline integrity record.

        Returns the calculated hashes when successful.
        Returns None when hashing is not possible.
        """

        try:

            hashes = calculate_file_hashes(
                file_path
            )

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

    def on_created(self, event):

        if event.is_directory:
            return

        timestamp = self.get_timestamp()

        print(
            f"[{timestamp}] [CREATED] "
            f"{event.src_path}"
        )

        hashes = self.calculate_and_store_hash(
            event.src_path
        )

        if hashes is not None:

            print(
                f"[{timestamp}] [HASHED] "
                f"{event.src_path}"
            )

            log_event(
                event_type="FILE_HASHED",
                source_path=event.src_path,
                drive=self.get_drive(
                    event.src_path
                ),
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
                drive=self.get_drive(
                    event.src_path
                ),
                severity="WARNING",
                status="Unable to calculate baseline hash"
            )

        log_event(
            event_type="FILE_CREATED",
            source_path=event.src_path,
            drive=self.get_drive(
                event.src_path
            ),
            severity="INFO",
            status="Detected"
        )

    def on_modified(self, event):

        if event.is_directory:
            return

        timestamp = self.get_timestamp()

        print(
            f"[{timestamp}] [MODIFIED] "
            f"{event.src_path}"
        )

        log_event(
            event_type="FILE_MODIFIED",
            source_path=event.src_path,
            drive=self.get_drive(
                event.src_path
            ),
            severity="INFO",
            status="Detected"
        )

    def on_deleted(self, event):

        if event.is_directory:
            return

        timestamp = self.get_timestamp()

        print(
            f"[{timestamp}] [DELETED] "
            f"{event.src_path}"
        )

        log_event(
            event_type="FILE_DELETED",
            source_path=event.src_path,
            drive=self.get_drive(
                event.src_path
            ),
            severity="INFO",
            status="Detected"
        )

    def on_moved(self, event):

        if event.is_directory:
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
            drive=self.get_drive(
                event.dest_path
            ),
            severity="INFO",
            status="Detected"
        )


def start_monitor(path):

    event_handler = FileMonitorHandler()
    observer = Observer()

    observer.schedule(
        event_handler,
        path,
        recursive=True
    )

    observer.start()

    print("=" * 60)
    print("SECURE FILE TRANSFER MONITORING SYSTEM")
    print("=" * 60)
    print(
        f"Monitoring: {path}"
    )
    print("Monitoring started...")
    print("SHA-256 and MD5 baseline hashing enabled.")
    print("Press Ctrl+C to stop.")
    print("=" * 60)

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        print(
            "\nStopping monitor..."
        )

        observer.stop()

    observer.join()


if __name__ == "__main__":
    start_monitor(
        r"D:\FileMonitorLab"
    )