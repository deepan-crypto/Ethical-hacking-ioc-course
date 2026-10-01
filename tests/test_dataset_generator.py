"""
Unit Test: Synthetic Dataset Generator & Data Integrity

Verifies the integrity, formatting, ethical constraints, and simulated
attack patterns within sample_hashes.csv and sample_authentication_logs.csv.
"""

import csv
import re
from pathlib import Path
from data.generate_datasets import (
    generate_hashes_dataset,
    generate_authentication_logs_dataset,
    LAB_REUSED_ADMIN_HASH,
    LAB_WEAK_HASH_BLANK
)

HEX_32_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")


def test_hash_dataset_structure_and_constraints():
    """Validates that hash dataset conforms to lab security and ethical constraints."""
    csv_path = generate_hashes_dataset()
    assert csv_path.exists(), "sample_hashes.csv must exist"

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    assert len(reader) >= 20, "Should have at least 20 synthetic accounts"

    # Required headers
    expected_headers = {"username", "hash_type", "hash", "machine", "source", "timestamp"}
    assert set(reader[0].keys()) == expected_headers

    hashes = [row["hash"] for row in reader]
    usernames = [row["username"] for row in reader]

    # Check NTLM 32-char hex format
    for h in hashes:
        assert HEX_32_PATTERN.match(h), f"Hash '{h}' does not match 32-char hex NTLM format"

    # Check that planned reused admin hash appears under multiple accounts
    admin_hash_users = [row["username"] for row in reader if row["hash"] == LAB_REUSED_ADMIN_HASH]
    assert len(admin_hash_users) == 3, "Reused admin hash should be shared by 3 accounts"
    assert "administrator" in admin_hash_users
    assert "svc_backup" in admin_hash_users
    assert "temp_admin" in admin_hash_users

    # Check that weak blank hash is present
    blank_hash_users = [row["username"] for row in reader if row["hash"] == LAB_WEAK_HASH_BLANK]
    assert len(blank_hash_users) >= 1
    assert "guest_kiosk" in blank_hash_users


def test_authentication_logs_dataset_structure():
    """Validates authentication telemetry events and simulated attack signatures."""
    csv_path = generate_authentication_logs_dataset()
    assert csv_path.exists(), "sample_authentication_logs.csv must exist"

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    assert len(reader) >= 30, "Should have at least 30 authentication events"

    expected_headers = {"timestamp", "username", "source_machine", "destination_machine", "event_type", "status", "ip_address"}
    assert set(reader[0].keys()) == expected_headers

    event_types = {row["event_type"] for row in reader}
    assert "4624" in event_types, "Must include 4624 (Logon Success)"
    assert "4625" in event_types, "Must include 4625 (Logon Failure)"

    # Verify brute-force burst pattern for 'sarah_finance'
    sarah_failures = [row for row in reader if row["username"] == "sarah_finance" and row["status"] == "FAILURE"]
    assert len(sarah_failures) >= 5, "Sarah finance should exhibit 5 consecutive logon failures"

    # Verify password spraying signature from 10.0.0.99
    spray_events = [row for row in reader if row["ip_address"] == "10.0.0.99"]
    spray_users = {row["username"] for row in spray_events}
    assert len(spray_users) >= 5, "Password spraying signature must target >= 5 different accounts"

    # Verify private IP ranges (no public internet addresses)
    for row in reader:
        ip = row["ip_address"]
        assert ip.startswith("192.168.") or ip.startswith("10."), f"IP {ip} is not in private lab range"
