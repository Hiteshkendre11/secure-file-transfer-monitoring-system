
import json
import os
import tempfile
import threading
from datetime import datetime


# ============================================================
# HASH STORE CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

HASH_STORE_DIR = os.path.join(
    BASE_DIR,
    "logs"
)

HASH_STORE_FILE = os.path.join(
    HASH_STORE_DIR,
    "hash_store.json"
)

# Prevent simultaneous read/write operations from conflicting.
_STORE_LOCK = threading.RLock()


# ============================================================
# PATH NORMALIZATION
# ============================================================

def normalize_path(file_path):
    """
    Return a normalized absolute file path.
    """

    return os.path.normcase(
        os.path.abspath(file_path)
    )


def find_existing_key(data, file_path):
    """
    Find an existing path key, including entries created
    by older versions of this hash store.
    """

    normalized_path = normalize_path(file_path)

    if normalized_path in data:
        return normalized_path

    for stored_path in data:
        if normalize_path(stored_path) == normalized_path:
            return stored_path

    return None


# ============================================================
# INITIALIZATION
# ============================================================

def initialize_hash_store():
    """
    Create the hash storage directory and JSON file
    if they do not already exist.
    """

    os.makedirs(
        HASH_STORE_DIR,
        exist_ok=True
    )

    if not os.path.exists(HASH_STORE_FILE):
        save_hash_store({})


# ============================================================
# LOAD HASH STORE
# ============================================================

def load_hash_store():
    """
    Load all stored file hashes.

    A corrupted JSON file raises an error rather than
    silently returning an empty store and hiding baselines.
    """

    with _STORE_LOCK:

        initialize_hash_store()

        try:
            with open(
                HASH_STORE_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            if not isinstance(data, dict):
                raise ValueError(
                    "Hash store must contain a JSON object."
                )

            return data

        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"Hash store JSON is corrupted: {HASH_STORE_FILE}"
            ) from error

        except OSError as error:
            raise RuntimeError(
                f"Unable to read hash store: {error}"
            ) from error


# ============================================================
# SAVE HASH STORE
# ============================================================

def save_hash_store(data):
    """
    Save the complete hash store safely.

    Uses a temporary file and atomic replacement to reduce
    the risk of incomplete JSON writes.
    """

    with _STORE_LOCK:

        os.makedirs(
            HASH_STORE_DIR,
            exist_ok=True
        )

        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=HASH_STORE_DIR,
                suffix=".tmp",
                delete=False
            ) as file:

                temporary_path = file.name

                json.dump(
                    data,
                    file,
                    indent=4
                )

                file.flush()
                os.fsync(file.fileno())

            os.replace(
                temporary_path,
                HASH_STORE_FILE
            )

        except OSError:
            if temporary_path and os.path.exists(temporary_path):
                try:
                    os.remove(temporary_path)
                except OSError:
                    pass

            raise


# ============================================================
# STORE FILE HASHES
# ============================================================

def store_file_hashes(file_path, sha256, md5):
    """
    Store SHA-256 and MD5 hashes for a file.
    """

    if not file_path:
        raise ValueError("File path cannot be empty.")

    if not sha256 or not md5:
        raise ValueError("Both SHA-256 and MD5 hashes are required.")

    with _STORE_LOCK:

        data = load_hash_store()

        normalized_path = normalize_path(file_path)

        existing_key = find_existing_key(
            data,
            file_path
        )

        if existing_key and existing_key != normalized_path:
            del data[existing_key]

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
    Return stored hashes for a file.

    Returns None if no baseline exists.
    """

    if not file_path:
        return None

    with _STORE_LOCK:

        data = load_hash_store()

        existing_key = find_existing_key(
            data,
            file_path
        )

        if existing_key is None:
            return None

        return data[existing_key]


# ============================================================
# REMOVE FILE HASH
# ============================================================

def remove_file_hash(file_path):
    """
    Remove a file's stored hash entry.
    """

    if not file_path:
        return False

    with _STORE_LOCK:

        data = load_hash_store()

        existing_key = find_existing_key(
            data,
            file_path
        )

        if existing_key is None:
            return False

        del data[existing_key]

        save_hash_store(data)

        return True


# ============================================================
# MOVE / RENAME FILE HASH
# ============================================================

def move_file_hash(old_path, new_path):
    """
    Move an existing hash baseline from the old file path
    to the new file path.

    This preserves the original SHA-256 and MD5 values
    when a monitored file is renamed or moved.
    """

    if not old_path or not new_path:
        return False

    old_normalized = normalize_path(old_path)
    new_normalized = normalize_path(new_path)

    if old_normalized == new_normalized:
        return get_file_hashes(new_path) is not None

    with _STORE_LOCK:

        data = load_hash_store()

        old_key = find_existing_key(
            data,
            old_path
        )

        if old_key is None:
            return False

        new_key = find_existing_key(
            data,
            new_path
        )

        # Preserve the old baseline under the new path.
        hashes = data[old_key]

        del data[old_key]

        if new_key and new_key != old_key:
            del data[new_key]

        data[new_normalized] = hashes

        save_hash_store(data)

        return True


# ============================================================
# TEST
# ============================================================

def main():

    print("=" * 70)
    print("SECURE FILE TRANSFER MONITORING SYSTEM")
    print("=" * 70)
    print("HASH STORE TEST")
    print("-" * 70)

    test_file = os.path.join(
        BASE_DIR,
        "TransferTest",
        "hash_store_test.txt"
    )

    renamed_file = os.path.join(
        BASE_DIR,
        "TransferTest",
        "hash_store_test_renamed.txt"
    )

    test_sha256 = "a" * 64
    test_md5 = "b" * 32

    # Store test hashes.
    store_file_hashes(
        test_file,
        test_sha256,
        test_md5
    )

    print("[PASS] Hash storage")

    # Retrieve test hashes.
    stored_hashes = get_file_hashes(test_file)

    if (
        stored_hashes
        and stored_hashes["sha256"] == test_sha256
        and stored_hashes["md5"] == test_md5
    ):
        print("[PASS] Hash retrieval")
    else:
        print("[FAIL] Hash retrieval")

    # Test rename migration.
    moved = move_file_hash(
        test_file,
        renamed_file
    )

    renamed_hashes = get_file_hashes(
        renamed_file
    )

    if (
        moved
        and renamed_hashes
        and renamed_hashes["sha256"] == test_sha256
        and renamed_hashes["md5"] == test_md5
    ):
        print("[PASS] Rename hash migration")
    else:
        print("[FAIL] Rename hash migration")

    # Test removal.
    removed = remove_file_hash(
        renamed_file
    )

    if removed and get_file_hashes(renamed_file) is None:
        print("[PASS] Hash removal")
    else:
        print("[FAIL] Hash removal")

    print("-" * 70)
    print("HASH STORE TEST COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()
