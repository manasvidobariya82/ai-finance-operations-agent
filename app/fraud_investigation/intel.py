"""Lookups against the (approved) external-intelligence sources: IP reputation and watchlists.

Everything returned here carries its source so it can be recorded as evidence with provenance -
third-party intelligence is a lead to verify, not a fact.
"""
import re
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from typing import List, Optional

from sqlalchemy.orm import Session

from app.fraud_investigation import models

NAME_MATCH_THRESHOLD = 0.88
LEGAL_SUFFIXES = {"llc", "ltd", "limited", "fze", "inc", "co", "plc", "pvt", "private", "corp", "corporation"}
HIGH_RISK_USAGE = {"tor", "vpn", "datacenter"}


@dataclass
class WatchlistHit:
    list_name: str
    entity_type: str
    listed_value: str
    matched_value: str
    match_score: float
    source: str
    severity: str
    reason: Optional[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IntelContext:
    """External-intelligence facts about one transaction, as seen by the detection layer."""

    ip: Optional[dict]
    watchlist_hits: List[WatchlistHit]

    @property
    def ip_is_high_risk(self) -> bool:
        return bool(self.ip) and (self.ip["risk_score"] >= 75 or self.ip["usage_type"] in HIGH_RISK_USAGE)

    def hits_on(self, *list_names: str) -> List[WatchlistHit]:
        return [h for h in self.watchlist_hits if h.list_name in list_names]


def normalize_name(name: str) -> str:
    tokens = re.sub(r"[^a-z0-9 ]", " ", name.lower()).split()
    return " ".join(t for t in tokens if t not in LEGAL_SUFFIXES)


def name_similarity(a: str, b: str) -> float:
    na, nb = normalize_name(a), normalize_name(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    return SequenceMatcher(None, na, nb).ratio()


def ip_reputation(db: Session, ip_address: Optional[str]) -> Optional[dict]:
    if not ip_address:
        return None
    row = db.get(models.IpReputation, ip_address)
    if not row:
        return None
    return {
        "ip_address": row.ip_address,
        "risk_score": row.risk_score,
        "usage_type": row.usage_type,
        "isp": row.isp,
        "city": row.city,
        "country": row.country,
        "source": row.source,
        "last_updated": row.last_updated.isoformat() if row.last_updated else None,
    }


def _hit(entry: "models.WatchlistEntry", matched_value: str, score: float) -> WatchlistHit:
    return WatchlistHit(
        list_name=entry.list_name,
        entity_type=entry.entity_type,
        listed_value=entry.value,
        matched_value=matched_value,
        match_score=round(score, 3),
        source=entry.source,
        severity=entry.severity,
        reason=entry.reason,
    )


def screen_exact(db: Session, entity_type: str, value: Optional[str]) -> List[WatchlistHit]:
    if not value:
        return []
    entries = (
        db.query(models.WatchlistEntry)
        .filter(models.WatchlistEntry.entity_type == entity_type, models.WatchlistEntry.value == value)
        .all()
    )
    return [_hit(entry, value, 1.0) for entry in entries]


def screen_name(db: Session, name: Optional[str]) -> List[WatchlistHit]:
    """Fuzzy-match a name against name-type watchlist entries (sanctions lists)."""
    if not name:
        return []
    hits = []
    for entry in db.query(models.WatchlistEntry).filter(models.WatchlistEntry.entity_type == "name"):
        score = name_similarity(name, entry.value)
        if score >= NAME_MATCH_THRESHOLD:
            hits.append(_hit(entry, name, score))
    return hits


def screen_email_domain(db: Session, email: Optional[str]) -> List[WatchlistHit]:
    if not email or "@" not in email:
        return []
    return screen_exact(db, "email_domain", email.rsplit("@", 1)[1].lower())


def transaction_intel(db: Session, txn: "models.Transaction") -> IntelContext:
    hits: List[WatchlistHit] = []
    if txn.counterparty_id:
        counterparty = db.get(models.Counterparty, txn.counterparty_id)
        if counterparty:
            hits += screen_name(db, counterparty.name)
            hits += screen_exact(db, "account_number", counterparty.account_number)
    hits += screen_exact(db, "ip", txn.ip_address)
    hits += screen_exact(db, "device", txn.device_id)
    return IntelContext(ip=ip_reputation(db, txn.ip_address), watchlist_hits=hits)
