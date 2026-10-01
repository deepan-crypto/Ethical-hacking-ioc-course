"""
Authentication Event ORM Model

1. What it does:
   Represents Windows security authentication telemetry (equivalent to Windows
   Security Event IDs 4624 [Logon Success] and 4625 [Logon Failure]).

2. Why it is required:
   Stores authentication logs so the IOC correlation engine can detect brute-force
   spikes, password spraying, out-of-hours logons, and lateral movement.

3. Cybersecurity concept demonstrated:
   Authentication Telemetry & Event Correlation. Windows domain environments log
   every logon attempt. Correlating logon failures (4625) followed by sudden successes (4624)
   helps detect credential guessing and Pass-the-Hash or stolen credential usage.

4. Example input:
   timestamp=datetime(2026, 9, 1, 10, 15), username="sarah_finance",
   source_machine="LAB-PC-02", destination_machine="LAB-SRV-01",
   event_type="4625", status="FAILURE", ip_address="192.168.1.45"

5. Example output:
   AuthenticationEvent object with is_suspicious=True, anomaly_reason="Failure burst detected"
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from app.core.database import Base


class AuthenticationEvent(Base):
    __tablename__ = "authentication_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, index=True, nullable=False)
    username = Column(String(100), index=True, nullable=False)
    source_machine = Column(String(100), index=True, nullable=False)
    destination_machine = Column(String(100), index=True, nullable=False)
    event_type = Column(String(50), nullable=False)  # "4624", "4625", etc.
    status = Column(String(20), index=True, nullable=False)  # "SUCCESS", "FAILURE"
    ip_address = Column(String(45), nullable=False)  # Synthetic private IPs

    # Behavioral flags
    is_suspicious = Column(Boolean, default=False, index=True)
    anomaly_reason = Column(Text, nullable=True)

    def to_dict(self) -> dict:
        """Serializes the event record for API/JSON responses."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else None,
            "username": self.username,
            "source_machine": self.source_machine,
            "destination_machine": self.destination_machine,
            "event_type": self.event_type,
            "status": self.status,
            "ip_address": self.ip_address,
            "is_suspicious": self.is_suspicious,
            "anomaly_reason": self.anomaly_reason or ""
        }
