"""ORM models for the fraud investigation system.

Timestamps in this module are naive datetimes in the bank's local time (see `clock.now`), so
hour-of-day features mean what an analyst expects ("03:14 AM") without per-row timezone handling.
"""
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text

from app.db import Base
from app.fraud_investigation.clock import now


# --- Core banking data -------------------------------------------------------------------------


class Customer(Base):
    __tablename__ = "customers"

    id = Column(String, primary_key=True)  # CUST-0001
    full_name = Column(String, nullable=False)
    email = Column(String, nullable=True, index=True)
    phone = Column(String, nullable=True, index=True)
    address = Column(String, nullable=True)
    home_city = Column(String, nullable=True)
    home_country = Column(String, nullable=True)
    segment = Column(String, default="retail")
    kyc_status = Column(String, default="verified")  # verified / pending / failed
    kyc_document = Column(String, nullable=True)
    kyc_verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=now)
    prior_fraud_cases = Column(Integer, default=0)


class Account(Base):
    __tablename__ = "accounts"

    id = Column(String, primary_key=True)  # ACC-0001
    customer_id = Column(String, ForeignKey("customers.id"), nullable=False, index=True)
    account_number = Column(String, nullable=False, unique=True)
    opened_at = Column(DateTime, nullable=False, default=now)
    currency = Column(String, default="INR")
    status = Column(String, default="active")  # active / restricted / frozen


class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True)  # DEV-xxxxxxxx (fingerprint)
    platform = Column(String, nullable=True)  # android / ios / web
    model = Column(String, nullable=True)
    first_seen = Column(DateTime, nullable=True)


class Counterparty(Base):
    """Anyone money is sent to: personal beneficiaries (bank accounts) and merchants."""

    __tablename__ = "counterparties"

    id = Column(String, primary_key=True)  # BEN-0001 / MER-001
    kind = Column(String, nullable=False)  # beneficiary / merchant
    name = Column(String, nullable=False)
    account_number = Column(String, nullable=True, index=True)
    bank = Column(String, nullable=True)
    country = Column(String, nullable=True)
    category = Column(String, nullable=True)  # merchant category
    status = Column(String, default="active")  # active / blocked


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(String, primary_key=True)  # TX-000001
    account_id = Column(String, ForeignKey("accounts.id"), nullable=False, index=True)
    customer_id = Column(String, ForeignKey("customers.id"), nullable=False, index=True)
    counterparty_id = Column(String, ForeignKey("counterparties.id"), nullable=True, index=True)
    amount = Column(Float, nullable=False)
    currency = Column(String, default="INR")
    timestamp = Column(DateTime, nullable=False, index=True)
    txn_type = Column(String, nullable=False)  # transfer / card_purchase / bill_payment
    payment_method = Column(String, nullable=True)  # upi / imps / neft / card
    channel = Column(String, nullable=True)  # mobile_app / web / pos
    device_id = Column(String, nullable=True, index=True)
    ip_address = Column(String, nullable=True, index=True)
    city = Column(String, nullable=True)
    country = Column(String, nullable=True)
    status = Column(String, default="completed")  # completed / held / reversed
    # Ground truth: historical chargeback/confirmed-fraud labels, or an analyst's case decision.
    # None = unknown. Never used as a model feature.
    is_fraud = Column(Boolean, nullable=True)
    # Synthetic-data tag for evaluation only (which injected scenario produced this row).
    scenario = Column(String, nullable=True)
    ingested_at = Column(DateTime, default=now)


class AccountEvent(Base):
    """Digital-behaviour events: logins, credential/MFA changes, devices, beneficiaries, profile."""

    __tablename__ = "account_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(String, ForeignKey("customers.id"), nullable=False, index=True)
    account_id = Column(String, nullable=True)
    # login_success / login_failed / password_reset / mfa_success / mfa_method_changed /
    # device_added / beneficiary_added / profile_updated
    event_type = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    device_id = Column(String, nullable=True, index=True)
    ip_address = Column(String, nullable=True, index=True)
    city = Column(String, nullable=True)
    country = Column(String, nullable=True)
    details = Column(JSON, nullable=True)
    scenario = Column(String, nullable=True)


# --- External intelligence ---------------------------------------------------------------------


class WatchlistEntry(Base):
    __tablename__ = "watchlist_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    list_name = Column(String, nullable=False)  # sanctions / internal_blocklist / disposable_email
    entity_type = Column(String, nullable=False)  # name / account_number / ip / device / email_domain
    value = Column(String, nullable=False, index=True)
    source = Column(String, nullable=False)
    severity = Column(String, default="high")
    reason = Column(String, nullable=True)
    added_at = Column(DateTime, default=now)


class IpReputation(Base):
    __tablename__ = "ip_reputation"

    ip_address = Column(String, primary_key=True)
    risk_score = Column(Integer, nullable=False)  # 0-100
    usage_type = Column(String, nullable=True)  # residential / mobile_cgnat / hotel / datacenter / vpn / tor
    isp = Column(String, nullable=True)
    city = Column(String, nullable=True)
    country = Column(String, nullable=True)
    source = Column(String, nullable=False)
    last_updated = Column(DateTime, default=now)


# --- Detection, investigation, decisions -------------------------------------------------------


class FraudAlert(Base):
    """One risk assessment per scored transaction. Low-risk ones are auto-closed but kept for
    monitoring and audit."""

    __tablename__ = "fraud_alerts"

    id = Column(String, primary_key=True)  # ALT-000001
    transaction_id = Column(String, ForeignKey("transactions.id"), nullable=False, index=True)
    customer_id = Column(String, nullable=False, index=True)
    account_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=now, index=True)

    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String, nullable=False)  # low / medium / high
    components = Column(JSON, nullable=False)  # per-detector scores + how they were combined
    reasons = Column(JSON, nullable=False)
    signals = Column(JSON, nullable=False)
    features = Column(JSON, nullable=False)
    rule_hits = Column(JSON, nullable=False)
    ml_explanation = Column(JSON, nullable=True)  # top SHAP feature contributions
    model_version = Column(String, nullable=True)

    triage_decision = Column(String, nullable=False)  # auto_close / investigate
    status = Column(String, nullable=False)  # auto_closed / case_open / linked_to_case / case_closed
    case_id = Column(String, nullable=True, index=True)


class FraudCase(Base):
    __tablename__ = "fraud_cases"

    id = Column(String, primary_key=True)  # CASE-10001
    alert_id = Column(String, ForeignKey("fraud_alerts.id"), nullable=False)
    alert_ids = Column(JSON, nullable=False)
    customer_id = Column(String, nullable=False, index=True)
    account_id = Column(String, nullable=False)
    transaction_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=now, index=True)
    updated_at = Column(DateTime, default=now)

    status = Column(String, default="open", index=True)  # open / pending_verification / escalated / closed
    priority = Column(String, nullable=False)  # high / medium
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String, nullable=False)
    primary_hypothesis = Column(String, nullable=True)
    fraud_type = Column(String, nullable=True)
    summary = Column(Text, nullable=True)
    case_file = Column(JSON, nullable=False)

    assigned_to = Column(String, nullable=True)
    decision = Column(String, nullable=True)  # fraud_confirmed / false_positive / inconclusive
    decided_by = Column(String, nullable=True)
    decided_at = Column(DateTime, nullable=True)
    decision_notes = Column(Text, nullable=True)
    actions = Column(JSON, nullable=False, default=list)


class CaseNote(Base):
    __tablename__ = "fraud_case_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, ForeignKey("fraud_cases.id"), nullable=False, index=True)
    author = Column(String, nullable=False)
    body = Column(Text, nullable=False)
    created_at = Column(DateTime, default=now)


class AuditLog(Base):
    """Append-only, hash-chained log: each row's hash covers its content and the previous hash, so
    editing or deleting any earlier row breaks verification from that point on."""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False)
    actor = Column(String, nullable=False)  # system / agent:<name> / analyst:<name>
    action = Column(String, nullable=False)
    entity_type = Column(String, nullable=False)
    entity_id = Column(String, nullable=False, index=True)
    details = Column(JSON, nullable=True)
    prev_hash = Column(String, nullable=False)
    hash = Column(String, nullable=False)


class FraudFeedback(Base):
    """AI recommendation vs. human decision, one row per closed case - the retraining signal."""

    __tablename__ = "fraud_feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, nullable=False, index=True)
    alert_id = Column(String, nullable=False)
    transaction_id = Column(String, nullable=False, index=True)
    model_version = Column(String, nullable=True)
    predicted_score = Column(Integer, nullable=False)
    predicted_level = Column(String, nullable=False)
    ai_primary_hypothesis = Column(String, nullable=True)
    analyst_decision = Column(String, nullable=False)
    label = Column(Boolean, nullable=True)  # True fraud / False legitimate / None inconclusive
    analyst = Column(String, nullable=False)
    created_at = Column(DateTime, default=now)


class FraudModelVersion(Base):
    __tablename__ = "fraud_model_versions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    version = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime, default=now)
    algorithm = Column(String, nullable=False)
    feature_names = Column(JSON, nullable=False)
    metrics = Column(JSON, nullable=False)
    reference_stats = Column(JSON, nullable=False)  # training-time feature bins, for drift (PSI)
    training_rows = Column(Integer, nullable=False)
    feedback_rows = Column(Integer, default=0)
    artifact_path = Column(String, nullable=False)
    is_active = Column(Boolean, default=False, index=True)
    notes = Column(Text, nullable=True)
