import hashlib
import os


def calculate_hash(file_path, algorithm="sha256"):
    """
    Calculate the cryptographic hash of a file.

    Supported algorithms:
    - sha256
    - md5
    """

    algorithm = algorithm.lower()

    if algorithm == "sha256":
        hash_function = hashlib.sha256

    elif algorithm == "md5":
        hash_function = hashlib.md5

    else:
        raise ValueError(
            f"Unsupported hashing algorithm: {algorithm}"
        )

    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    hash_object = hash_function()

    with open(file_path, "rb") as file:

        while True:
            data = file.read(1024 * 1024)

            if not data:
                break

            hash_object.update(data)

    return hash_object.hexdigest()


def calculate_file_hashes(file_path):
    """
    Calculate both SHA-256 and MD5 hashes for a file.
    """

    return {
        "sha256": calculate_hash(
            file_path,
            "sha256"
        ),
        "md5": calculate_hash(
            file_path,
            "md5"
        )
    }


def compare_hashes(
    original_hash,
    current_hash
):
    """
    Compare two hash values.

    Returns True when the hashes match.
    Returns False when the hashes differ.
    """

    return (
        original_hash.lower()
        == current_hash.lower()
    )


def compare_file_integrity(
    file_path,
    original_sha256,
    original_md5
):
    """
    Compare the current file hashes with
    previously recorded hashes.
    """

    current_hashes = calculate_file_hashes(
        file_path
    )

    sha256_match = compare_hashes(
        original_sha256,
        current_hashes["sha256"]
    )

    md5_match = compare_hashes(
        original_md5,
        current_hashes["md5"]
    )

    return {
        "file": file_path,
        "original_sha256": original_sha256,
        "current_sha256": current_hashes["sha256"],
        "sha256_match": sha256_match,
        "original_md5": original_md5,
        "current_md5": current_hashes["md5"],
        "md5_match": md5_match,
        "integrity_match": (
            sha256_match and md5_match
        )
    }


def main():

    print("=" * 70)
    print("SECURE FILE TRANSFER MONITORING SYSTEM")
    print("=" * 70)
    print("HASH INTEGRITY TEST")
    print("-" * 70)

    test_file = (
        r"D:\FileMonitorLabTest\hash_test.txt"
    )

    # Create a controlled test file.
    with open(
        test_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "Secure File Transfer Monitoring Test"
        )

    print(f"Test file: {test_file}")
    print()

    # Calculate initial hashes.
    initial_hashes = calculate_file_hashes(
        test_file
    )

    print("INITIAL HASHES")
    print("-" * 70)
    print(
        f"SHA-256: {initial_hashes['sha256']}"
    )
    print(
        f"MD5:     {initial_hashes['md5']}"
    )

    print()

    # Verify the unchanged file.
    integrity_result = compare_file_integrity(
        test_file,
        initial_hashes["sha256"],
        initial_hashes["md5"]
    )

    print("UNCHANGED FILE TEST")
    print("-" * 70)
    print(
        f"SHA-256 Match: "
        f"{integrity_result['sha256_match']}"
    )
    print(
        f"MD5 Match:     "
        f"{integrity_result['md5_match']}"
    )
    print(
        f"Integrity:     "
        f"{integrity_result['integrity_match']}"
    )

    print()

    # Modify the file.
    with open(
        test_file,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            "\nFile content modified."
        )

    # Compare the modified file.
    modified_result = compare_file_integrity(
        test_file,
        initial_hashes["sha256"],
        initial_hashes["md5"]
    )

    print("MODIFIED FILE TEST")
    print("-" * 70)
    print(
        f"SHA-256 Match: "
        f"{modified_result['sha256_match']}"
    )
    print(
        f"MD5 Match:     "
        f"{modified_result['md5_match']}"
    )
    print(
        f"Integrity:     "
        f"{modified_result['integrity_match']}"
    )

    print()
    print("-" * 70)

    if modified_result["integrity_match"]:
        print(
            "[RESULT] File integrity unchanged."
        )
    else:
        print(
            "[RESULT] File integrity changed."
        )

    print("-" * 70)


if __name__ == "__main__":
    main()