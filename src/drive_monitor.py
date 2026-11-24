import os
import string
import win32api
import win32file


def get_drive_type(drive):
    """
    Identify the Windows drive type.
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
    Check whether a drive is currently accessible.
    """
    try:
        os.listdir(drive)
        return True, "Accessible"

    except PermissionError:
        return False, "Access denied"

    except OSError as error:
        return False, str(error)


def discover_drives():
    """
    Discover all drive letters currently available in Windows.
    """
    drives = []

    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"

        try:
            drive_type = get_drive_type(drive)

            if drive_type == "NO_ROOT_DIR":
                continue

            accessible, status = check_drive_accessibility(drive)

            drives.append({
                "drive": drive,
                "type": drive_type,
                "accessible": accessible,
                "status": status
            })

        except Exception as error:
            drives.append({
                "drive": drive,
                "type": "UNKNOWN",
                "accessible": False,
                "status": str(error)
            })

    return drives


def display_drives():
    """
    Display discovered drives and their accessibility status.
    """
    print("=" * 70)
    print("SECURE FILE TRANSFER MONITORING SYSTEM")
    print("=" * 70)

    print("\nSYSTEM DRIVE DISCOVERY")
    print("-" * 70)

    drives = discover_drives()

    if not drives:
        print("No drives detected.")
        return

    for drive_info in drives:
        drive = drive_info["drive"]
        drive_type = drive_info["type"]
        accessible = drive_info["accessible"]
        status = drive_info["status"]

        if accessible:
            print(
                f"[ACCESSIBLE]   {drive:<5} "
                f"Type: {drive_type:<10} "
                f"Status: {status}"
            )
        else:
            print(
                f"[NOT ACCESSIBLE] {drive:<5} "
                f"Type: {drive_type:<10} "
                f"Status: {status}"
            )

    print("-" * 70)
    print(f"Total detected drives: {len(drives)}")


if __name__ == "__main__":
    display_drives()