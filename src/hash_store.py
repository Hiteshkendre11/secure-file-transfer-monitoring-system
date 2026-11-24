import json
import os
from datetime import datetime


# ============================================================
# HASH STORE CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

HASH_STORE_DIR = os.path.join(
    BASE_DIR,
    "logs"
)

HASH_STORE_FILE = os.path.join(
    HASH_STORE_DIR,
    "hash_store.json"
)


# ============================================================
# INITIALIZATION
# ============================================================

def initialize_hash_store():
    """
    Create the hash storage directory and file
    if they do not already exist.
    """

    os.makedirs(
        HASH_STORE_DIR,
        exist_ok=True
    )

    if not os.path.exists(HASH_STORE_FILE):

        with open(
            HASH_STORE_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                {},
                file,
                indent=4
            )


# ============================================================
# LOAD HASH STORE
# ============================================================

def load_hash_store():
    """
    Load all stored file hashes.
    """

    initialize_hash_store()

    try:

        with open(
            HASH_STORE_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

            if isinstance(data, dict):
                return data

            return {}

    except (
        json.JSONDecodeError,
        OSError
    ):

        return {}


# ============================================================
# SAVE HASH STORE
# ============================================================

def save_hash_store(data):
    """
    Save the complete hash store.
    """

    initialize_hash_store()

    temporary_file = (
        HASH_STORE_FILE + ".tmp"
    )

    with open(
        temporary_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4
        )

    os.replace(
        temporary_file,
        HASH_STORE_FILE
    )


# ============================================================
# STORE FILE HASHES
# ============================================================

def store_file_hashes(
    file_path,
    sha256,
    md5
):
    """
    Store SHA-256 and MD5 hashes for a file.
    """

    data = load_hash_store()

    normalized_path = os.path.abspath(
        file_path
    )

    data[normalized_path] = {
        "sha256": sha256,
        "md5": md5,
        "stored_at": datetime.now().isoformat(
            timespec="seconds"
        )
    }

    save_hash_store(data)


# ============================================================
# GET STORED FILE HASHES
# ============================================================

def get_file_hashes(file_path):
    """
    Return the stored hashes for a file.

    Returns None if the file has no stored baseline.
    """

    data = load_hash_store()

    normalized_path = os.path.abspath(
        file_path
    )

    return data.get(
        normalized_path
    )


# ============================================================
# REMOVE FILE HASH
# ============================================================

def remove_file_hash(file_path):
    """
    Remove a file's stored hash entry.
    """

    data = load_hash_store()

    normalized_path = os.path.abspath(
        file_path
    )

    if normalized_path in data:

        del data[normalized_path]

        save_hash_store(data)

        return True

    return False


# ============================================================
# TEST
# ============================================================

def main():

    print("=" * 70)
    print("SECURE FILE TRANSFER MONITORING SYSTEM")
    print("=" * 70)
    print("HASH STORE TEST")
    print("-" * 70)

    test_file = (
        r"D:\FileMonitorLabTest\hash_store_test.txt"
    )

    test_sha256 = (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    test_md5 = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )

    print(
        f"Test file: {test_file}"
    )

    print()

    # Store test hashes.
    store_file_hashes(
        test_file,
        test_sha256,
        test_md5
    )

    print(
        "[STORE] Hashes stored successfully."
    )

    # Retrieve test hashes.
    stored_hashes = get_file_hashes(
        test_file
    )

    print()

    print(
        "[RETRIEVE] Stored hash information:"
    )

    print(
        json.dumps(
            stored_hashes,
            indent=4
        )
    )

    print()

    # Verify retrieved values.
    if (
        stored_hashes is not None
        and stored_hashes["sha256"] == test_sha256
        and stored_hashes["md5"] == test_md5
    ):

        print(
            "[RESULT] Hash storage test PASSED."
        )

    else:

        print(
            "[RESULT] Hash storage test FAILED."
        )

    print()

    # Remove test entry.
    removed = remove_file_hash(
        test_file
    )

    if removed:

        print(
            "[CLEANUP] Test hash entry removed."
        )

    print("-" * 70)

    # Confirm removal.
    if get_file_hashes(test_file) is None:

        print(
            "[RESULT] Hash removal test PASSED."
        )

    else:

        print(
            "[RESULT] Hash removal test FAILED."
        )

    print("-" * 70)


if __name__ == "__main__":
    main()