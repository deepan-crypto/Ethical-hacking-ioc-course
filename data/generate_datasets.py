"""
Synthetic Dataset Generator for Controlled Lab Simulation

1. What it does:
   Generates synthetic Windows NTLM-style password hash datasets and Windows Security
   authentication event logs (Event 4624 & 4625) with simulated benign and malicious patterns.

2. Why it is required:
   Ensures that security students and blue team analysts have safe, fully synthetic,
   reproducible lab data to test detection algorithms without exposing real credentials.

3. Cybersecurity concept demonstrated:
   Telemetry Simulation & Adversary Emulation.
   In modern detection engineering, blue teams validate detection rules by generating
   simulated benign baselines and inserting deliberate attack patterns (e.g., password reuse,
   brute-force bursts, password spraying, and off-hours privileged logins).

4. Example input:
   Running this script generates `data/sample_hashes.csv` and `data/sample_authentication_logs.csv`.

5. Example output:
   - 35+ synthetic hash records with intentional reuse and weak lab hashes.
   - 120+ authentication telemetry events covering baseline traffic and attack scenarios.
"""

import csv
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

# Paths
DATA_DIR = Path(__file__).resolve().parent
HASHES_CSV = DATA_DIR / "sample_hashes.csv"
AUTH_LOGS_CSV = DATA_DIR / "sample_authentication_logs.csv"

# Pre-computed synthetic NTLM hashes (safe lab test values)
# Note: NTLM is MD4(UTF-16LE(password)) - represented as 32 hex chars
LAB_WEAK_HASH_BLANK = "31d6cfe0d16ae931b73c59d7e0c089c0"        # Empty / blank
LAB_WEAK_HASH_PASSWORD = "8846f7eaee8fb117ad06bdd830b7586c"     # "password"
LAB_WEAK_HASH_ADMIN = "209c614c407035e1d4b182376bd6656a"        # "admin"
LAB_REUSED_ADMIN_HASH = "b45cffe0e4c5b3671234a4918732168a"      # Synthetic shared admin hash
LAB_REUSED_ENG_HASH = "d41d8cd98f00b204e9800998ecf8427e"        # Synthetic shared dev hash


def create_synthetic_hash(seed_name: str) -> str:
    """Generates a reproducible 32-character synthetic hex hash for lab simulation."""
    return hashlib.md5(f"LAB_SYNTHETIC_{seed_name}".encode("utf-8")).hexdigest()


def generate_hashes_dataset() -> Path:
    """
    Creates sample_hashes.csv containing fictional lab accounts,
    synthetic NTLM hashes, deliberate reuse scenarios, and weak test hashes.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    base_time = datetime(2026, 9, 1, 9, 0, 0)

    # Synthetic accounts design:
    # 1. Privileged reuse cluster (b45cffe0e4c5b3671234a4918732168a)
    #    - administrator, svc_backup, temp_admin
    # 2. Regular user reuse cluster (d41d8cd98f00b204e9800998ecf8427e)
    #    - john_dev, michael_ops, david_qa
    # 3. Known weak synthetic hashes
    #    - guest_kiosk (blank), intern_temp (password), test_account (admin)
    # 4. Normal unique accounts
    records = [
        # Cluster 1: High-Risk Privileged Hash Reuse
        ("administrator", "NTLM", LAB_REUSED_ADMIN_HASH, "LAB-DC-01", "LAB_ACTIVE_DIR", base_time + timedelta(minutes=5)),
        ("svc_backup", "NTLM", LAB_REUSED_ADMIN_HASH, "LAB-SRV-01", "LAB_ACTIVE_DIR", base_time + timedelta(minutes=10)),
        ("temp_admin", "NTLM", LAB_REUSED_ADMIN_HASH, "WORKSTATION-X", "LAB_LOCAL_SAM", base_time + timedelta(minutes=15)),

        # Cluster 2: Standard User Hash Reuse
        ("john_dev", "NTLM", LAB_REUSED_ENG_HASH, "LAB-PC-01", "LAB_ACTIVE_DIR", base_time + timedelta(minutes=20)),
        ("michael_ops", "NTLM", LAB_REUSED_ENG_HASH, "LAB-PC-02", "LAB_ACTIVE_DIR", base_time + timedelta(minutes=25)),
        ("david_qa", "NTLM", LAB_REUSED_ENG_HASH, "LAB-PC-03", "LAB_ACTIVE_DIR", base_time + timedelta(minutes=30)),

        # Cluster 3: Known Weak Synthetic Test Hashes
        ("guest_kiosk", "NTLM", LAB_WEAK_HASH_BLANK, "LAB-PC-01", "LAB_LOCAL_SAM", base_time + timedelta(minutes=35)),
        ("intern_temp", "NTLM", LAB_WEAK_HASH_PASSWORD, "LAB-PC-02", "LAB_ACTIVE_DIR", base_time + timedelta(minutes=40)),
        ("test_service", "NTLM", LAB_WEAK_HASH_ADMIN, "LAB-SRV-01", "LAB_ACTIVE_DIR", base_time + timedelta(minutes=45)),

        # Suspicious Machine & Source
        ("shadow_user", "NTLM", create_synthetic_hash("shadow_user"), "UNKNOWN-EXTERNAL", "UNAUTHORIZED_IMPORT", base_time + timedelta(minutes=50)),

        # Unique Benign Lab Users
        ("sarah_finance", "NTLM", create_synthetic_hash("sarah_finance"), "LAB-PC-04", "LAB_ACTIVE_DIR", base_time + timedelta(hours=1)),
        ("lisa_hr", "NTLM", create_synthetic_hash("lisa_hr"), "LAB-PC-05", "LAB_ACTIVE_DIR", base_time + timedelta(hours=1, minutes=10)),
        ("robert_eng", "NTLM", create_synthetic_hash("robert_eng"), "LAB-PC-06", "LAB_ACTIVE_DIR", base_time + timedelta(hours=1, minutes=20)),
        ("emily_sales", "NTLM", create_synthetic_hash("emily_sales"), "LAB-PC-07", "LAB_ACTIVE_DIR", base_time + timedelta(hours=1, minutes=30)),
        ("kevin_support", "NTLM", create_synthetic_hash("kevin_support"), "LAB-PC-08", "LAB_ACTIVE_DIR", base_time + timedelta(hours=1, minutes=40)),
        ("amanda_legal", "NTLM", create_synthetic_hash("amanda_legal"), "LAB-PC-09", "LAB_ACTIVE_DIR", base_time + timedelta(hours=1, minutes=50)),
        ("brian_network", "NTLM", create_synthetic_hash("brian_network"), "LAB-SRV-02", "LAB_ACTIVE_DIR", base_time + timedelta(hours=2)),
        ("rachel_marketing", "NTLM", create_synthetic_hash("rachel_marketing"), "LAB-PC-10", "LAB_ACTIVE_DIR", base_time + timedelta(hours=2, minutes=10)),
        ("alex_analyst", "NTLM", create_synthetic_hash("alex_analyst"), "LAB-PC-11", "LAB_ACTIVE_DIR", base_time + timedelta(hours=2, minutes=20)),
        ("daniel_dbadmin", "NTLM", create_synthetic_hash("daniel_dbadmin"), "LAB-SRV-03", "LAB_ACTIVE_DIR", base_time + timedelta(hours=2, minutes=30)),
        ("clara_research", "NTLM", create_synthetic_hash("clara_research"), "LAB-PC-12", "LAB_ACTIVE_DIR", base_time + timedelta(hours=2, minutes=40)),
        ("ethan_devops", "NTLM", create_synthetic_hash("ethan_devops"), "LAB-PC-13", "LAB_ACTIVE_DIR", base_time + timedelta(hours=2, minutes=50)),
        ("grace_manager", "NTLM", create_synthetic_hash("grace_manager"), "LAB-PC-14", "LAB_ACTIVE_DIR", base_time + timedelta(hours=3)),
        ("lucas_contractor", "NTLM", create_synthetic_hash("lucas_contractor"), "LAB-PC-15", "LAB_ACTIVE_DIR", base_time + timedelta(hours=3, minutes=10)),
        ("olivia_security", "NTLM", create_synthetic_hash("olivia_security"), "LAB-SOC-01", "LAB_ACTIVE_DIR", base_time + timedelta(hours=3, minutes=20)),
    ]

    with open(HASHES_CSV, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "hash_type", "hash", "machine", "source", "timestamp"])
        for user, htype, hval, machine, src, tstamp in records:
            writer.writerow([user, htype, hval, machine, src, tstamp.strftime("%Y-%m-%d %H:%M:%S")])

    return HASHES_CSV


def generate_authentication_logs_dataset() -> Path:
    """
    Creates sample_authentication_logs.csv containing simulated Windows Security
    Event IDs (4624 Logon Success, 4625 Logon Failure) modeling:
    - Normal business traffic
    - Brute Force Spikes (T1110.001)
    - Password Spraying (T1110.003)
    - Off-hours privileged logins (T1078/T1098)
    - Suspicious workstation lateral movement (T1021.002)
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    events = []
    base_time = datetime(2026, 9, 1, 8, 30, 0)

    # 1. Normal morning successful logons (4624)
    normal_users = [
        ("john_dev", "LAB-PC-01", "LAB-DC-01", "192.168.1.11"),
        ("sarah_finance", "LAB-PC-04", "LAB-FILE-01", "192.168.1.14"),
        ("michael_ops", "LAB-PC-02", "LAB-SRV-01", "192.168.1.12"),
        ("lisa_hr", "LAB-PC-05", "LAB-FILE-01", "192.168.1.15"),
        ("david_qa", "LAB-PC-03", "LAB-SRV-02", "192.168.1.13"),
        ("emily_sales", "LAB-PC-07", "LAB-DC-01", "192.168.1.17"),
        ("kevin_support", "LAB-PC-08", "LAB-SRV-01", "192.168.1.18"),
        ("olivia_security", "LAB-SOC-01", "LAB-DC-01", "192.168.1.30"),
    ]
    for idx, (user, src, dst, ip) in enumerate(normal_users):
        t = base_time + timedelta(minutes=idx * 6)
        events.append((t, user, src, dst, "4624", "SUCCESS", ip))

    # 2. Scenario A: Brute Force Spike (T1110.001) against 'sarah_finance'
    # 5 rapid failed logons within 3 minutes, then 1 success
    bf_time = datetime(2026, 9, 1, 10, 15, 0)
    for i in range(5):
        t = bf_time + timedelta(seconds=i * 25)
        events.append((t, "sarah_finance", "LAB-PC-04", "LAB-SRV-01", "4625", "FAILURE", "192.168.1.45"))
    events.append((bf_time + timedelta(minutes=3), "sarah_finance", "LAB-PC-04", "LAB-SRV-01", "4624", "SUCCESS", "192.168.1.45"))

    # 3. Scenario B: Password Spraying Attack (T1110.003) from single external IP 10.0.0.99
    # Rapid consecutive single failure across 5 different accounts
    spray_time = datetime(2026, 9, 1, 11, 40, 0)
    spray_targets = ["john_dev", "michael_ops", "david_qa", "lisa_hr", "robert_eng", "administrator"]
    for idx, user in enumerate(spray_targets):
        t = spray_time + timedelta(seconds=idx * 15)
        events.append((t, user, "UNKNOWN-HOST", "LAB-DC-01", "4625", "FAILURE", "10.0.0.99"))

    # 4. Scenario C: Off-Hours Privileged Login (T1078 / T1098)
    # 'administrator' authenticates at 02:45 AM from rogue machine WORKSTATION-X
    off_hour_time = datetime(2026, 9, 2, 2, 45, 0)
    events.append((off_hour_time, "administrator", "WORKSTATION-X", "LAB-DC-01", "4624", "SUCCESS", "192.168.1.250"))
    events.append((off_hour_time + timedelta(minutes=3), "administrator", "WORKSTATION-X", "LAB-FILE-01", "4624", "SUCCESS", "192.168.1.250"))

    # 5. Scenario D: Lateral Movement / High Frequency Authentication (T1021.002)
    # 'temp_admin' rapidly authenticating to multiple targets
    lat_time = datetime(2026, 9, 1, 14, 10, 0)
    lat_destinations = ["LAB-PC-01", "LAB-PC-02", "LAB-FILE-01", "LAB-SRV-01", "LAB-DC-01"]
    for idx, dst in enumerate(lat_destinations):
        t = lat_time + timedelta(minutes=idx * 2)
        events.append((t, "temp_admin", "WORKSTATION-X", dst, "4624", "SUCCESS", "192.168.1.250"))

    # 6. Additional normal baseline traffic to provide realistic distribution
    afternoon_time = datetime(2026, 9, 1, 15, 0, 0)
    for i in range(20):
        t = afternoon_time + timedelta(minutes=i * 5)
        user, src, dst, ip = normal_users[i % len(normal_users)]
        status = "SUCCESS" if i % 7 != 0 else "FAILURE"
        event_code = "4624" if status == "SUCCESS" else "4625"
        events.append((t, user, src, dst, event_code, status, ip))

    # Sort events chronologically
    events.sort(key=lambda x: x[0])

    with open(AUTH_LOGS_CSV, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "username", "source_machine", "destination_machine", "event_type", "status", "ip_address"])
        for tstamp, user, src_m, dst_m, etype, status, ip in events:
            writer.writerow([tstamp.strftime("%Y-%m-%d %H:%M:%S"), user, src_m, dst_m, etype, status, ip])

    return AUTH_LOGS_CSV


if __name__ == "__main__":
    h_path = generate_hashes_dataset()
    a_path = generate_authentication_logs_dataset()
    print(f"[+] Synthetic Hash dataset created: {h_path}")
    print(f"[+] Synthetic Authentication Logs dataset created: {a_path}")
