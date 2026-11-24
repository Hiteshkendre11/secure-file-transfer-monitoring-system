import time
import string
import os
import win32file

from logger import log_system_event


def get_current_drives():
    """
    Return all currently available Windows drive letters.
    """
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
    """
    Identify the type of a Windows drive.
    """
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


def check_drive_accessibility(drive):
    """
    Check whether a drive can currently be accessed.
    """
    try:
        os.listdir(drive)
        return True, "Accessible"

    except PermissionError:
        return False, "Access denied"

    except OSError as error:
        return False, str(error)


def watch_drives():
    """
    Continuously monitor Windows for drive connection/removal changes.
    """

    previous_drives = get_current_drives()

    print("=" * 70)
    print("SECURE FILE TRANSFER MONITORING SYSTEM")
    print("=" * 70)
    print("DRIVE CONNECTION MONITOR")
    print("-" * 70)

    print("Currently detected drives:")

    for drive in sorted(previous_drives):
        print(f"  {drive} - {get_drive_type(drive)}")

    print("-" * 70)
    print("Watching for drive changes...")
    print("Connect or remove a USB drive to test.")
    print("Press Ctrl+C to stop.")
    print("-" * 70)

    try:
        while True:
            time.sleep(2)

            current_drives = get_current_drives()

            # Detect newly connected drives
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
                    print("[USB DETECTED] Removable drive connected.")

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

            # Detect removed drives
            removed_drives = previous_drives - current_drives

            for drive in sorted(removed_drives):

                drive_type = "UNKNOWN"

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

            previous_drives = current_drives

    except KeyboardInterrupt:
        print()
        print("Drive connection monitor stopped.")


if __name__ == "__main__":
    watch_drives()