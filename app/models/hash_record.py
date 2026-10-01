"""
Hash Record ORM Model

1. What it does:
   Defines the database schema for imported Windows password hash records,
   including synthetic NTLM hash strings, cryptographic SHA-256 fingerprints,
   provenance metadata (host machine, source), and calculated risk scores.

2. Why it is required:
   Enables indexed storage, querying, and relationship mapping of password hash data.
   Allows tracking password reuse across accounts without exposing plaintext credentials.

3. Cybersecurity concept demonstrated:
   Cryptographic Fingerprinting & Credential Hygiene Analysis.
   In blue team operations, hashes are treated as sensitive artifacts. Calculating a
   SHA-256 fingerprint of the hash value allows security teams to share and track
   IOCs across SIEM/SOAR platforms without exposing the actual hash itself.

4. Example input:
   username="administrator", hash_type="NTLM", hash_value="31d6cfe0d16ae931b73c59d7e0c089c0",
   machine="LAB-DC-01", source="LAB_EXPORT", timestamp=datetime(2026, 9, 1, 10, 30)

5. Example output:
   HashRecord object with hash_fingerprint="7a86f9...", risk_score=50, risk_level="HIGH"
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from app.core.database import Base


class HashRecord(Base):
    __tablename__ = "hash_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(100), index=True, nullable=False)
    hash_type = Column(String(20), default="NTLM", nullable=False)
    hash_value = Column(String(128), index=True, nullable=False)  # Synthetic lab hash
    hash_fingerprint = Column(String(64), index=True, nullable=False)  # SHA-256 of hash_value
    machine = Column(String(100), index=True, nullable=False)
    source = Column(String(100), default="LAB_IMPORT", nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Risk & Behavioral Properties calculated by HashAnalyzer / RiskEngine
    is_reused = Column(Boolean, default=False, index=True)
    reuse_count = Column(Integer, default=1)
    risk_score = Column(Integer, default=0)  # 0 to 100
    risk_level = Column(String(20), default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    notes = Column(Text, nullable=True)

    def to_dict(self) -> dict:
        """Serializes the record to a dictionary for API/JSON responses."""
        return {
            "id": self.id,
            "username": self.username,
            "hash_type": self.hash_type,
            "hash_value": self.hash_value,
            "hash_fingerprint": self.hash_fingerprint,
            "machine": self.machine,
            "source": self.source,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else None,
            "is_reused": self.is_reused,
            "reuse_count": self.reuse_count,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "notes": self.notes or ""
        }
