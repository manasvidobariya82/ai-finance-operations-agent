"""Tamper-evident audit trail.

Each entry's hash covers its own content plus the previous entry's hash, so editing or deleting
any past entry breaks `verify()` from that point on. Writes that add audit entries go through
`write_section`, which serialises them within the process so the chain can't fork when two
requests commit at once. (A multi-process deployment would need a database-level lock or sequence
for the same guarantee.)
"""
import hashlib
import json
import threading
from contextlib import contextmanager
from typing import Optional

from sqlalchemy.orm import Session

from app.fraud_investigation.clock import now
from app.fraud_investigation.models import AuditLog

GENESIS_HASH = "0" * 64
_write_lock = threading.RLock()


@contextmanager
def write_section(db: Session):
    """Run a block of writes (including audit entries) under the process-wide write lock and
    commit it, or roll it back on error."""
    with _write_lock:
        try:
            yield
            db.commit()
        except Exception:
            db.rollback()
            raise


def _digest(prev_hash: str, timestamp: str, actor: str, action: str, entity_type: str, entity_id: str, details) -> str:
    payload = json.dumps(
        {
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "details": details,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


def record(
    db: Session, actor: str, action: str, entity_type: str, entity_id: str, details: Optional[dict] = None
) -> AuditLog:
    # Round-trip through JSON so what we hash is exactly what the JSON column stores and reads back.
    details = json.loads(json.dumps(details, default=str)) if details is not None else None
    with _write_lock:
        last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        prev_hash = last.hash if last else GENESIS_HASH
        timestamp = now()
        entry = AuditLog(
            timestamp=timestamp,
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
            prev_hash=prev_hash,
            hash=_digest(prev_hash, timestamp.isoformat(), actor, action, entity_type, entity_id, details),
        )
        db.add(entry)
        db.flush()
    return entry


def verify(db: Session) -> dict:
    prev_hash = GENESIS_HASH
    count = 0
    for entry in db.query(AuditLog).order_by(AuditLog.id).yield_per(500):
        expected = _digest(
            prev_hash, entry.timestamp.isoformat(), entry.actor, entry.action, entry.entity_type, entry.entity_id, entry.details
        )
        if entry.prev_hash != prev_hash or entry.hash != expected:
            return {"valid": False, "entries_checked": count, "first_invalid_id": entry.id}
        prev_hash = entry.hash
        count += 1
    return {"valid": True, "entries_checked": count, "first_invalid_id": None, "head_hash": prev_hash}
