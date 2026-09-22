"""Builders for small, hand-made fraud scenarios.

The synthetic generator produces a realistic bank, which is what the model needs but not what a
test needs: a test should be able to point at the one fact that is supposed to change the outcome.
These builders make a customer with a boring, predictable baseline and then add exactly one
interesting transaction on top of it.
"""
from datetime import datetime, timedelta
from typing import List, Optional

from app.fraud_investigation import models

BASE = datetime(2026, 6, 1, 12, 0, 0)
HOME_DEVICE = "DEV-home0001"
HOME_IP = "198.51.100.10"


def customer(
    db,
    customer_id: str = "CUST-0001",
    *,
    opened_days_ago: int = 900,
    kyc_status: str = "verified",
    email: str = "kabir@mailbox.example",
    phone: str = "+919800000001",
    home_city: str = "Mumbai",
) -> models.Customer:
    row = models.Customer(
        id=customer_id,
        full_name=f"Test Customer {customer_id[-4:]}",
        email=email,
        phone=phone,
        address="1 MG Road",
        home_city=home_city,
        home_country="IN",
        kyc_status=kyc_status,
        created_at=BASE - timedelta(days=opened_days_ago),
    )
    db.add(row)
    db.add(
        models.Account(
            id=f"ACC-{customer_id[-4:]}",
            customer_id=customer_id,
            account_number=f"9{customer_id[-4:]}00112233",
            opened_at=BASE - timedelta(days=opened_days_ago),
        )
    )
    db.add(models.Device(id=HOME_DEVICE, platform="android", model="Pixel 7", first_seen=BASE - timedelta(days=400)))
    db.commit()
    return row


def beneficiary(db, ben_id: str, name: str, account_number: Optional[str] = None) -> models.Counterparty:
    row = models.Counterparty(
        id=ben_id, kind="beneficiary", name=name, account_number=account_number or f"5{ben_id[-4:]}99887766",
        bank="Metro National Bank", country="IN", status="active",
    )
    db.add(row)
    db.commit()
    return row


def merchant(db, mer_id: str = "MER-001", name: str = "Daily Grocers", category: str = "grocery") -> models.Counterparty:
    row = models.Counterparty(id=mer_id, kind="merchant", name=name, country="IN", category=category, status="active")
    db.add(row)
    db.commit()
    return row


def transaction(
    db,
    txn_id: str,
    customer_id: str,
    *,
    amount: float,
    when: datetime,
    counterparty_id: Optional[str] = None,
    txn_type: str = "transfer",
    payment_method: str = "imps",
    channel: str = "mobile_app",
    device_id: Optional[str] = HOME_DEVICE,
    ip_address: str = HOME_IP,
    city: str = "Mumbai",
    country: str = "IN",
    is_fraud: Optional[bool] = None,
    commit: bool = True,
) -> models.Transaction:
    row = models.Transaction(
        id=txn_id,
        account_id=f"ACC-{customer_id[-4:]}",
        customer_id=customer_id,
        counterparty_id=counterparty_id,
        amount=amount,
        currency="INR",
        timestamp=when,
        txn_type=txn_type,
        payment_method=payment_method,
        channel=channel,
        device_id=device_id,
        ip_address=ip_address,
        city=city,
        country=country,
        status="completed",
        is_fraud=is_fraud,
    )
    db.add(row)
    if commit:
        db.commit()
    return row


def event(
    db,
    customer_id: str,
    event_type: str,
    when: datetime,
    *,
    device_id: Optional[str] = HOME_DEVICE,
    ip_address: str = HOME_IP,
    city: str = "Mumbai",
    country: str = "IN",
    commit: bool = True,
) -> models.AccountEvent:
    row = models.AccountEvent(
        customer_id=customer_id,
        account_id=f"ACC-{customer_id[-4:]}",
        event_type=event_type,
        timestamp=when,
        device_id=device_id,
        ip_address=ip_address,
        city=city,
        country=country,
        details={},
    )
    db.add(row)
    if commit:
        db.commit()
    return row


def baseline(db, customer_id: str = "CUST-0001", *, days: int = 90, per_week: int = 4) -> List[models.Transaction]:
    """A dull, regular payment history: same device, same city, office hours, two known payees."""
    customer(db, customer_id)
    known_a = beneficiary(db, "BEN-00001", "Landlord Rentals")
    known_b = beneficiary(db, "BEN-00002", "Sunil Kumar")
    shop = merchant(db)

    rows = []
    start = BASE - timedelta(days=days)
    count = 0
    for day in range(0, days, max(1, 7 // per_week)):
        when = start + timedelta(days=day, hours=(count % 8) + 9, minutes=(count * 7) % 60)
        if when >= BASE:
            break
        count += 1
        if count % 3 == 0:
            rows.append(
                transaction(
                    db, f"TX-{count:06d}", customer_id, amount=5000 + (count % 5) * 1200, when=when,
                    counterparty_id=known_a.id if count % 2 else known_b.id, commit=False,
                )
            )
        else:
            rows.append(
                transaction(
                    db, f"TX-{count:06d}", customer_id, amount=900 + (count % 7) * 210, when=when,
                    counterparty_id=shop.id, txn_type="card_purchase", payment_method="card",
                    channel="pos", device_id=None, commit=False,
                )
            )
        event(db, customer_id, "login_success", when - timedelta(minutes=4), commit=False)
    db.commit()
    return rows


def takeover_transaction(db, customer_id: str = "CUST-0001") -> models.Transaction:
    """The classic pattern: forced entry, credentials changed, then money out to a new payee."""
    attacker_device, attacker_ip = "DEV-attacker1", "203.0.113.77"
    mule = beneficiary(db, "BEN-09001", "Farhan Reddy")
    when = BASE - timedelta(hours=6)

    for offset in range(5):
        event(
            db, customer_id, "login_failed", when - timedelta(minutes=90 + offset * 2),
            device_id=attacker_device, ip_address=attacker_ip, city="Amsterdam", country="NL", commit=False,
        )
    for kind, minutes in (("login_success", 60), ("password_reset", 45), ("device_added", 40), ("beneficiary_added", 20)):
        event(
            db, customer_id, kind, when - timedelta(minutes=minutes),
            device_id=attacker_device, ip_address=attacker_ip, city="Amsterdam", country="NL", commit=False,
        )
    db.commit()
    return transaction(
        db, "TX-900001", customer_id, amount=90000.0, when=when, counterparty_id=mule.id,
        device_id=attacker_device, ip_address=attacker_ip, city="Amsterdam", country="NL",
    )


def scam_transaction(db, customer_id: str = "CUST-0001") -> models.Transaction:
    """The same money, same size, same new payee - but the customer sent it themselves.

    Own device, home city, office hours, no credential change anywhere near it.
    """
    payee = beneficiary(db, "BEN-09002", "Quick Returns Investments")
    when = BASE - timedelta(hours=6)
    event(db, customer_id, "login_success", when - timedelta(minutes=25))
    event(db, customer_id, "beneficiary_added", when - timedelta(minutes=12))
    return transaction(db, "TX-900002", customer_id, amount=90000.0, when=when, counterparty_id=payee.id)
