"""Point-in-time data access for feature computation.

Features must only see data that existed *before* the transaction being scored, otherwise the model
trains on information it won't have at serving time. Both the training path (everything loaded in
memory once) and the serving path (a few SQL queries per transaction) go through the same
`CustomerHistory` / `NetworkLookup` interfaces, so the feature code itself is shared and a parity
test can check the two lookups agree.
"""
from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Protocol, Tuple

from sqlalchemy import func, select, union_all
from sqlalchemy.orm import Session

from app.fraud_investigation import models


@dataclass(frozen=True)
class TxnRecord:
    id: str
    customer_id: str
    account_id: str
    counterparty_id: Optional[str]
    counterparty_kind: Optional[str]
    amount: float
    timestamp: datetime
    txn_type: str
    payment_method: Optional[str] = None
    channel: Optional[str] = None
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    is_fraud: Optional[bool] = None


@dataclass(frozen=True)
class EventRecord:
    event_type: str
    timestamp: datetime
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    details: Optional[dict] = None


@dataclass(frozen=True)
class CustomerProfile:
    id: str
    full_name: str
    created_at: datetime
    account_opened_at: datetime
    home_city: Optional[str]
    home_country: Optional[str]
    kyc_status: str
    prior_fraud_cases: int = 0


@dataclass
class CustomerHistory:
    profile: CustomerProfile
    transactions: List[TxnRecord] = field(default_factory=list)
    events: List[EventRecord] = field(default_factory=list)

    def __post_init__(self):
        self.transactions.sort(key=lambda t: t.timestamp)
        self.events.sort(key=lambda e: e.timestamp)
        self._txn_times = [t.timestamp for t in self.transactions]
        self._event_times = [e.timestamp for e in self.events]

    def transactions_before(self, ts: datetime, window: Optional[timedelta] = None) -> List[TxnRecord]:
        end = bisect_left(self._txn_times, ts)
        start = bisect_left(self._txn_times, ts - window) if window else 0
        return self.transactions[start:end]

    def events_before(self, ts: datetime, window: Optional[timedelta] = None) -> List[EventRecord]:
        end = bisect_left(self._event_times, ts)
        start = bisect_left(self._event_times, ts - window) if window else 0
        return self.events[start:end]

    def events_between(self, start: datetime, end: datetime) -> List[EventRecord]:
        return self.events[bisect_left(self._event_times, start) : bisect_left(self._event_times, end)]

    def transactions_between(self, start: datetime, end: datetime) -> List[TxnRecord]:
        return self.transactions[bisect_left(self._txn_times, start) : bisect_left(self._txn_times, end)]


class NetworkLookup(Protocol):
    """How many *other* customers used an entity before a point in time."""

    def device_customers(self, device_id: str, before: datetime, exclude_customer: str) -> int: ...

    def ip_customers(self, ip_address: str, before: datetime, exclude_customer: str) -> int: ...

    def counterparty_senders(self, counterparty_id: str, before: datetime, exclude_customer: str) -> int: ...


class InMemoryNetworkIndex:
    """Training-time NetworkLookup. Keeps, per entity, the first time each customer used it, sorted,
    so "distinct customers before ts" is a bisect instead of a scan."""

    def __init__(self):
        self._first_use: Dict[str, Dict[str, Dict[str, datetime]]] = {
            "device": defaultdict(dict),
            "ip": defaultdict(dict),
            "counterparty": defaultdict(dict),
        }
        self._sorted: Dict[Tuple[str, str], List[datetime]] = {}

    def add(self, kind: str, key: Optional[str], customer_id: str, ts: datetime) -> None:
        if not key:
            return
        users = self._first_use[kind][key]
        first = users.get(customer_id)
        if first is None or ts < first:
            users[customer_id] = ts
            self._sorted.pop((kind, key), None)

    def add_transaction(self, txn: TxnRecord) -> None:
        self.add("device", txn.device_id, txn.customer_id, txn.timestamp)
        self.add("ip", txn.ip_address, txn.customer_id, txn.timestamp)
        if txn.counterparty_kind == "beneficiary":
            self.add("counterparty", txn.counterparty_id, txn.customer_id, txn.timestamp)

    def add_event(self, customer_id: str, event: EventRecord) -> None:
        self.add("device", event.device_id, customer_id, event.timestamp)
        self.add("ip", event.ip_address, customer_id, event.timestamp)

    def _count(self, kind: str, key: Optional[str], before: datetime, exclude_customer: str) -> int:
        if not key or key not in self._first_use[kind]:
            return 0
        times = self._sorted.get((kind, key))
        if times is None:
            times = sorted(self._first_use[kind][key].values())
            self._sorted[(kind, key)] = times
        count = bisect_left(times, before)
        excluded_first = self._first_use[kind][key].get(exclude_customer)
        if excluded_first is not None and excluded_first < before:
            count -= 1
        return count

    def device_customers(self, device_id, before, exclude_customer):
        return self._count("device", device_id, before, exclude_customer)

    def ip_customers(self, ip_address, before, exclude_customer):
        return self._count("ip", ip_address, before, exclude_customer)

    def counterparty_senders(self, counterparty_id, before, exclude_customer):
        return self._count("counterparty", counterparty_id, before, exclude_customer)


class SqlNetworkLookup:
    """Serving-time NetworkLookup backed by indexed SQL queries."""

    def __init__(self, db: Session):
        self.db = db

    def _distinct_customers(self, column_name: str, value, before, exclude_customer, include_events=True) -> int:
        if not value:
            return 0
        txns = models.Transaction.__table__
        parts = [
            select(txns.c.customer_id).where(txns.c[column_name] == value, txns.c.timestamp < before)
        ]
        if include_events:
            events = models.AccountEvent.__table__
            parts.append(
                select(events.c.customer_id).where(events.c[column_name] == value, events.c.timestamp < before)
            )
        used = union_all(*parts).subquery()
        query = select(func.count(func.distinct(used.c.customer_id))).where(used.c.customer_id != exclude_customer)
        return self.db.execute(query).scalar_one()

    def device_customers(self, device_id, before, exclude_customer):
        return self._distinct_customers("device_id", device_id, before, exclude_customer)

    def ip_customers(self, ip_address, before, exclude_customer):
        return self._distinct_customers("ip_address", ip_address, before, exclude_customer)

    def counterparty_senders(self, counterparty_id, before, exclude_customer):
        return self._distinct_customers("counterparty_id", counterparty_id, before, exclude_customer, include_events=False)


# --- Loading from the database -----------------------------------------------------------------


def _counterparty_kinds(db: Session) -> Dict[str, str]:
    table = models.Counterparty.__table__
    return {row.id: row.kind for row in db.execute(select(table.c.id, table.c.kind))}


def _txn_record(row, kinds: Dict[str, str]) -> TxnRecord:
    return TxnRecord(
        id=row.id,
        customer_id=row.customer_id,
        account_id=row.account_id,
        counterparty_id=row.counterparty_id,
        counterparty_kind=kinds.get(row.counterparty_id),
        amount=row.amount,
        timestamp=row.timestamp,
        txn_type=row.txn_type,
        payment_method=row.payment_method,
        channel=row.channel,
        device_id=row.device_id,
        ip_address=row.ip_address,
        city=row.city,
        country=row.country,
        is_fraud=row.is_fraud,
    )


def txn_record(db: Session, txn: "models.Transaction") -> TxnRecord:
    kind = db.get(models.Counterparty, txn.counterparty_id).kind if txn.counterparty_id else None
    return _txn_record(txn, {txn.counterparty_id: kind})


def _event_record(row) -> EventRecord:
    return EventRecord(
        event_type=row.event_type,
        timestamp=row.timestamp,
        device_id=row.device_id,
        ip_address=row.ip_address,
        city=row.city,
        country=row.country,
        details=row.details,
    )


def _profiles(db: Session, customer_id: Optional[str] = None) -> Dict[str, CustomerProfile]:
    query = db.query(models.Customer, func.min(models.Account.opened_at)).join(
        models.Account, models.Account.customer_id == models.Customer.id
    )
    if customer_id:
        query = query.filter(models.Customer.id == customer_id)
    profiles = {}
    for customer, opened_at in query.group_by(models.Customer.id).all():
        profiles[customer.id] = CustomerProfile(
            id=customer.id,
            full_name=customer.full_name,
            created_at=customer.created_at,
            account_opened_at=opened_at,
            home_city=customer.home_city,
            home_country=customer.home_country,
            kyc_status=customer.kyc_status,
            prior_fraud_cases=customer.prior_fraud_cases or 0,
        )
    return profiles


def load_customer_history(db: Session, customer_id: str) -> CustomerHistory:
    profiles = _profiles(db, customer_id)
    if customer_id not in profiles:
        raise ValueError(f"Customer {customer_id} not found or has no account")
    kinds = _counterparty_kinds(db)
    txns = models.Transaction.__table__
    events = models.AccountEvent.__table__
    return CustomerHistory(
        profile=profiles[customer_id],
        transactions=[_txn_record(r, kinds) for r in db.execute(select(txns).where(txns.c.customer_id == customer_id))],
        events=[_event_record(r) for r in db.execute(select(events).where(events.c.customer_id == customer_id))],
    )


def load_all_histories(db: Session) -> Tuple[Dict[str, CustomerHistory], InMemoryNetworkIndex]:
    """Bulk-load every customer's history plus the network index, for training and drift checks."""
    profiles = _profiles(db)
    kinds = _counterparty_kinds(db)
    txns_by_customer: Dict[str, List[TxnRecord]] = defaultdict(list)
    events_by_customer: Dict[str, List[EventRecord]] = defaultdict(list)
    index = InMemoryNetworkIndex()

    for row in db.execute(select(models.Transaction.__table__)):
        record = _txn_record(row, kinds)
        txns_by_customer[record.customer_id].append(record)
        index.add_transaction(record)
    for row in db.execute(select(models.AccountEvent.__table__)):
        record = _event_record(row)
        events_by_customer[row.customer_id].append(record)
        index.add_event(row.customer_id, record)

    histories = {
        cid: CustomerHistory(profile, txns_by_customer.get(cid, []), events_by_customer.get(cid, []))
        for cid, profile in profiles.items()
    }
    return histories, index

