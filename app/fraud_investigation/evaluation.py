"""Threshold evaluation for R014 ("large first payment to a brand-new beneficiary") on labelled data.

R014 exists for authorised push payment scams, which no other rule sees, and it also fires on
genuine payments - most first payments to a new payee are somebody paying a new landlord. How that
trade-off moves with the amount threshold can only be measured where both sides are labelled, so
this replays a synthetic bank - labelled APP scams plus legitimate look-alikes (`HARD_NEGATIVES`) -
through the real feature code, rule engine and behavioural detector, and reports for each
candidate threshold:

- recall on the APP scams, and precision over everything the rule flags;
- where the false positives come from;
- which other rules fire on the same transactions, i.e. what R014 adds rather than re-flags;
- how many transactions and cases it moves from auto-close into the review queue, the score change
  it causes, and how many transactions it helps escalate to high risk.

"Before" is R001-R013; "after" adds R014 at the candidate threshold. Scores come from the rule
engine and the behavioural detector - the configuration `pipeline.assess` uses with no trained model
and no graph, which is the one the regression tests pin. The graph detector is left out on purpose:
it taints every device, IP and payee that appears on a transaction labelled as fraud, so over
labelled data it scores each fraud transaction as linked to confirmed fraud because of its own
label. A trained model can already have put some of these transactions in review, so the review
queue and case numbers are an upper bound on what R014 moves. Its effect on a single transaction
does not depend on the model: whenever it fires, the strong-detector minimum in `scoring.combine`
puts the score at no less than 85% of its 0.4 weight - medium risk - with or without one.

The first `DEFAULT_WARMUP_DAYS` of the generated history serve as history only and are not scored.
The generator's customers have paid their regular payees for years, but the database holds 90 days,
so early in the window the first payment in the data to a long-standing landlord reads as a first
payment ever - and with no warm-up those dominate R014's false positives. The labelled scams and
their look-alikes are all placed after the warm-up.

Two limits on reading the numbers. Recall is a property of the injected scams, which sit at 4-8x
the customer's average, so it shows which part of that range a threshold gives up rather than
predicting real-world recall. Precision depends on how many scams are injected per look-alike,
which is a modelling choice; the false-positive count on legitimate traffic, and its breakdown by
source, is the number that carries over.

Nothing here changes the shipped rule: candidate thresholds use a copy of its condition
(`r014_fires`), and `Evaluation.shipped_rule_disagreements` checks the copy against the real rule
on every transaction.

    python -m app.fraud_investigation.evaluation --customers 400
"""
import argparse
import statistics
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Sequence

from sqlalchemy.orm import Session

from app.fraud_investigation import models
from app.fraud_investigation.detection.behavior import assess_deviation, build_profile
from app.fraud_investigation.detection.rules import RULES, evaluate_rules, rule_score
from app.fraud_investigation.features import compute_features
from app.fraud_investigation.history import TxnRecord, load_all_histories
from app.fraud_investigation.intel import IntelContext, ip_reputation, screen_exact, screen_name
from app.fraud_investigation.pipeline import CASE_LINK_WINDOW
from app.fraud_investigation.scoring import combine, triage
from app.fraud_investigation.synthetic import APP_SCAM

DEFAULT_THRESHOLDS = (3.0, 4.0, 5.0, 6.0)
SHIPPED_THRESHOLD = 4.0
DEFAULT_WARMUP_DAYS = 30
# A fixed end date keeps a report reproducible: the generator's bill-payment days follow the calendar.
EVALUATION_END = datetime(2026, 9, 1)

R014 = next(rule for rule in RULES if rule.id == "R014")
R014_HIT = {"id": R014.id, "name": R014.name, "severity": R014.severity, "weight": R014.weight, "floor": R014.floor}

# Legitimate cohorts built next to the APP scams, each probing one part of R014's condition.
HARD_NEGATIVES = {
    "legit_large_new_payee": "Genuine large first payment to a new payee (indistinguishable from a scam)",
    "legit_business_supplier": "Business paying a new supplier a large invoice",
    "legit_new_beneficiary": "New payee, normal-sized payment",
    "legit_large_known_payee": "Large payment to a payee paid before",
}
ORDINARY = "ordinary"  # a transaction no scenario produced: everyday traffic


def r014_fires(features: Dict[str, float], threshold: float) -> bool:
    """R014's condition, with the amount multiple as a parameter."""
    return (
        features["is_transfer"] == 1
        and features["recipient_is_new"] == 1
        and features["has_history"] == 1
        and features["amount_vs_customer_avg"] >= threshold
    )


@dataclass
class Row:
    """One transaction with everything a threshold decision needs, computed once."""

    transaction_id: str
    customer_id: str
    timestamp: datetime
    scenario: str
    is_fraud: bool
    features: Dict[str, float]
    other_hits: List[dict]  # R001-R013
    shipped_r014: bool  # the real rule's verdict
    behavior: float

    @property
    def is_app_scam(self) -> bool:
        return self.scenario == APP_SCAM

    @property
    def other_rule_ids(self) -> List[str]:
        return [hit["id"] for hit in self.other_hits]

    def score(self, with_r014: bool) -> dict:
        hits = self.other_hits + [R014_HIT] if with_r014 else self.other_hits
        components = {"ml": None, "rules": rule_score(hits), "graph": None, "behavior": self.behavior, "anomaly": None}
        return combine(components, hits)


class IntelLookup:
    """`intel.transaction_intel` with each lookup cached on its own key.

    The same payee, IP and device recur across thousands of transactions, so screening each once
    turns the slowest part of a replay into a few hundred queries. `transaction_intel` stays the
    reference: a test checks the two agree.
    """

    def __init__(self, db: Session):
        self.db = db
        self._counterparty: Dict[Optional[str], list] = {}
        self._exact: Dict[tuple, list] = {}
        self._ip: Dict[Optional[str], Optional[dict]] = {}

    def __call__(self, txn: TxnRecord) -> IntelContext:
        if txn.counterparty_id not in self._counterparty:
            counterparty = self.db.get(models.Counterparty, txn.counterparty_id) if txn.counterparty_id else None
            self._counterparty[txn.counterparty_id] = (
                screen_name(self.db, counterparty.name) + screen_exact(self.db, "account_number", counterparty.account_number)
                if counterparty
                else []
            )
        for key in (("ip", txn.ip_address), ("device", txn.device_id)):
            if key not in self._exact:
                self._exact[key] = screen_exact(self.db, *key)
        if txn.ip_address not in self._ip:
            self._ip[txn.ip_address] = ip_reputation(self.db, txn.ip_address)
        hits = self._counterparty[txn.counterparty_id] + self._exact[("ip", txn.ip_address)] + self._exact[("device", txn.device_id)]
        return IntelContext(ip=self._ip[txn.ip_address], watchlist_hits=hits)


def build_population(db: Session) -> List[Row]:
    """Replay every transaction through the point-in-time features, the rules and the behavioural
    detector, on the same bulk path as backlog scoring: one history load, one network index."""
    histories, network = load_all_histories(db)
    scenarios = dict(db.query(models.Transaction.id, models.Transaction.scenario))
    intel = IntelLookup(db)

    rows = []
    for history in histories.values():
        for txn in history.transactions:
            features = compute_features(txn, history, network).values
            hits = evaluate_rules(features, intel(txn))
            rows.append(
                Row(
                    transaction_id=txn.id,
                    customer_id=txn.customer_id,
                    timestamp=txn.timestamp,
                    scenario=scenarios.get(txn.id) or ORDINARY,
                    is_fraud=bool(txn.is_fraud),
                    features=features,
                    other_hits=[hit for hit in hits if hit["id"] != R014.id],
                    shipped_r014=any(hit["id"] == R014.id for hit in hits),
                    behavior=assess_deviation(txn, build_profile(history, txn))["score"],
                )
            )
    rows.sort(key=lambda row: (row.timestamp, row.transaction_id))
    return rows


def count_cases(review: Iterable[Row]) -> int:
    """Cases the pipeline would open for these review-queue transactions, scored in time order.

    Mirrors `pipeline.investigate`: an alert joins the customer's open case when the transaction
    that opened it is at most `CASE_LINK_WINDOW` older, and opens a new case otherwise.
    """
    last_anchor: Dict[str, datetime] = {}
    cases = 0
    for row in sorted(review, key=lambda r: (r.timestamp, r.transaction_id)):
        anchor = last_anchor.get(row.customer_id)
        if anchor is None or row.timestamp - anchor > CASE_LINK_WINDOW:
            last_anchor[row.customer_id] = row.timestamp
            cases += 1
    return cases


def _rate(numerator: int, denominator: int) -> Optional[float]:
    return numerator / denominator if denominator else None


def evaluate_threshold(rows: Sequence[Row], threshold: float, baseline: Dict[str, dict]) -> dict:
    fired = [row for row in rows if r014_fires(row.features, threshold)]
    positives = sum(1 for row in rows if row.is_app_scam)
    legitimate = sum(1 for row in rows if not row.is_fraud)

    caught = [row for row in fired if row.is_app_scam]
    other_fraud = [row for row in fired if row.is_fraud and not row.is_app_scam]
    false_positives = [row for row in fired if not row.is_fraud]

    after = {row.transaction_id: row.score(with_r014=True) for row in fired}
    moved = [
        row for row in fired
        if triage(baseline[row.transaction_id]["risk_level"]) == "auto_close"
        and triage(after[row.transaction_id]["risk_level"]) == "investigate"
    ]
    escalated_to_high = [
        row for row in fired
        if baseline[row.transaction_id]["risk_level"] != "high" and after[row.transaction_id]["risk_level"] == "high"
    ]
    review_before = [row for row in rows if triage(baseline[row.transaction_id]["risk_level"]) == "investigate"]

    def score_change(subset: List[Row]) -> Optional[float]:
        if not subset:
            return None
        return statistics.fmean(
            after[row.transaction_id]["risk_score"] - baseline[row.transaction_id]["risk_score"] for row in subset
        )

    return {
        "threshold": threshold,
        "fired": len(fired),
        "app_scams_caught": len(caught),
        "app_scams_missed": positives - len(caught),
        "other_fraud_flagged": len(other_fraud),
        "false_positives": len(false_positives),
        "recall": _rate(len(caught), positives),
        "precision": _rate(len(caught), len(fired)),
        "fraud_precision": _rate(len(caught) + len(other_fraud), len(fired)),
        "false_positive_rate": _rate(len(false_positives), legitimate),
        "false_positives_by_source": dict(Counter(row.scenario for row in false_positives)),
        "app_scams_only_r014_catches": sum(1 for row in caught if not row.other_hits),
        "fired_with_no_other_rule": sum(1 for row in fired if not row.other_hits),
        "co_firing_rules": dict(Counter(rule_id for row in fired for rule_id in row.other_rule_ids)),
        "moved_to_review": len(moved),
        "moved_to_review_by_label": {
            "app_scam": sum(1 for row in moved if row.is_app_scam),
            "other_fraud": sum(1 for row in moved if row.is_fraud and not row.is_app_scam),
            "legitimate": sum(1 for row in moved if not row.is_fraud),
        },
        "review_queue_before": len(review_before),
        "review_queue_after": len(review_before) + len(moved),
        "cases_before": count_cases(review_before),
        "cases_after": count_cases(review_before + moved),
        "escalated_to_high": len(escalated_to_high),
        "escalated_to_high_with_no_other_rule": sum(1 for row in escalated_to_high if not row.other_hits),
        "high_risk_on_r014_alone": sum(
            1 for row in fired if not row.other_hits and after[row.transaction_id]["risk_level"] == "high"
        ),
        "mean_score_change": score_change(fired),
        "mean_score_change_app_scams": score_change(caught),
        "mean_score_change_false_positives": score_change(false_positives),
    }


@dataclass
class Evaluation:
    thresholds: List[dict]
    population: dict
    shipped_rule_disagreements: List[str] = field(default_factory=list)

    def at(self, threshold: float) -> dict:
        return next(item for item in self.thresholds if item["threshold"] == threshold)


def evaluate(
    db: Session,
    thresholds: Sequence[float] = DEFAULT_THRESHOLDS,
    rows: Optional[List[Row]] = None,
    warmup_days: int = DEFAULT_WARMUP_DAYS,
) -> Evaluation:
    """Evaluate each threshold over every transaction after the warm-up (see the module docstring).

    `rows` lets several evaluations share one replay, which is the expensive part.
    """
    everything = rows if rows is not None else build_population(db)
    history_start = min((row.timestamp for row in everything), default=None)
    rows = [row for row in everything if row.timestamp >= history_start + timedelta(days=warmup_days)]
    baseline = {row.transaction_id: row.score(with_r014=False) for row in rows}
    by_scenario = Counter(row.scenario for row in rows)
    population = {
        "transactions": len(rows),
        "warmup_days": warmup_days,
        "warmup_transactions": len(everything) - len(rows),
        "customers": len({row.customer_id for row in rows}),
        "app_scams": by_scenario.get(APP_SCAM, 0),
        "legitimate": sum(1 for row in rows if not row.is_fraud),
        "other_fraud": sum(1 for row in rows if row.is_fraud and not row.is_app_scam),
        "hard_negatives": {name: by_scenario.get(name, 0) for name in HARD_NEGATIVES},
        "app_scam_multiples": sorted(
            round(row.features["amount_vs_customer_avg"], 2) for row in rows if row.is_app_scam
        ),
    }
    return Evaluation(
        thresholds=[evaluate_threshold(rows, threshold, baseline) for threshold in sorted(thresholds)],
        population=population,
        shipped_rule_disagreements=[
            row.transaction_id for row in everything if r014_fires(row.features, SHIPPED_THRESHOLD) != row.shipped_r014
        ],
    )


# --- report ------------------------------------------------------------------------------------------


def _pct(value: Optional[float], places: int = 1) -> str:
    return "n/a" if value is None else f"{value:.{places}%}"


def _signed(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value:+.1f}"


def _label(threshold: float) -> str:
    return f"{threshold:g}x" + (" (shipped)" if threshold == SHIPPED_THRESHOLD else "")


def _table(header: List[str], body: List[List[str]]) -> List[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    return lines + ["| " + " | ".join(cells) + " |" for cells in body]


def format_report(evaluation: Evaluation, title: str = "R014 threshold evaluation") -> str:
    pop, results = evaluation.population, evaluation.thresholds
    columns = [_label(item["threshold"]) for item in results]
    multiples = pop["app_scam_multiples"]
    lines = [
        f"# {title}",
        "",
        f"{pop['transactions']:,} transactions from {pop['customers']} customers: {pop['app_scams']} labelled APP scams, "
        f"{pop['other_fraud']} other fraud transactions, {pop['legitimate']:,} legitimate. The first {pop['warmup_days']} days "
        f"({pop['warmup_transactions']:,} transactions) are history only.",
        f"APP scams sit at {multiples[0]:.2f}x-{multiples[-1]:.2f}x the customer's 90-day average."
        if multiples else "No APP scams in this population.",
        "Hard negatives: " + ", ".join(f"{name} {count}" for name, count in pop["hard_negatives"].items()) + ".",
        "Scored with the rule engine and behavioural detector (no trained model, no graph); "
        "before = R001-R013, after = R001-R013 + R014 at the threshold.",
        "",
        "## Detection",
        "",
    ]
    lines += _table(
        ["Metric"] + columns,
        [
            ["Transactions flagged"] + [str(r["fired"]) for r in results],
            ["APP scams caught"] + [f"{r['app_scams_caught']} / {pop['app_scams']}" for r in results],
            ["Recall (APP scams)"] + [_pct(r["recall"]) for r in results],
            ["Precision (APP scams)"] + [_pct(r["precision"]) for r in results],
            ["Precision (any fraud)"] + [_pct(r["fraud_precision"]) for r in results],
            ["False positives (legitimate)"] + [str(r["false_positives"]) for r in results],
            ["False-positive rate"] + [_pct(r["false_positive_rate"], 3) for r in results],
            ["Other fraud also flagged"] + [str(r["other_fraud_flagged"]) for r in results],
        ],
    )
    lines += ["", "## Workload and score", ""]
    lines += _table(
        ["Metric"] + columns,
        [
            ["Moved from auto-close to review"] + [str(r["moved_to_review"]) for r in results],
            ["... APP scams / other fraud / legitimate"]
            + [
                f"{r['moved_to_review_by_label']['app_scam']} / {r['moved_to_review_by_label']['other_fraud']} / "
                f"{r['moved_to_review_by_label']['legitimate']}"
                for r in results
            ],
            ["Review queue (transactions), before -> after"] + [f"{r['review_queue_before']} -> {r['review_queue_after']}" for r in results],
            ["Cases, before -> after"] + [f"{r['cases_before']} -> {r['cases_after']}" for r in results],
            ["New cases"] + [str(r["cases_after"] - r["cases_before"]) for r in results],
            ["Mean score change, all flagged"] + [_signed(r["mean_score_change"]) for r in results],
            ["Mean score change, APP scams"] + [_signed(r["mean_score_change_app_scams"]) for r in results],
            ["Mean score change, false positives"] + [_signed(r["mean_score_change_false_positives"]) for r in results],
            ["Escalated to high risk"] + [str(r["escalated_to_high"]) for r in results],
            ["High risk with R014 the only rule"] + [str(r["high_risk_on_r014_alone"]) for r in results],
        ],
    )
    lines += ["", "## Where the false positives come from", ""]
    sources = sorted({source for r in results for source in r["false_positives_by_source"]}, key=lambda s: (s == ORDINARY, s))
    lines += _table(
        ["Source"] + columns,
        [
            [source if source != ORDINARY else "ordinary traffic"] + [str(r["false_positives_by_source"].get(source, 0)) for r in results]
            for source in sources
        ]
        or [["(none)"] + ["0" for _ in results]],
    )
    lines += ["", "## Overlap with the other rules", ""]
    rule_ids = sorted({rule_id for r in results for rule_id in r["co_firing_rules"]})
    names = {rule.id: rule.name for rule in RULES}
    lines += _table(
        ["Also fired on the same transaction"] + columns,
        [["No other rule"] + [str(r["fired_with_no_other_rule"]) for r in results]]
        + [["APP scams only R014 catches"] + [f"{r['app_scams_only_r014_catches']} / {r['app_scams_caught']}" for r in results]]
        + [[f"{rule_id} {names[rule_id]}"] + [str(r["co_firing_rules"].get(rule_id, 0)) for r in results] for rule_id in rule_ids],
    )
    if evaluation.shipped_rule_disagreements:
        lines += [
            "",
            f"WARNING: the threshold copy disagrees with the shipped R014 on "
            f"{len(evaluation.shipped_rule_disagreements)} transactions; these numbers do not describe the shipped rule.",
        ]
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db import Base
    from app.fraud_investigation import synthetic

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--customers", type=int, default=400)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--thresholds", type=float, nargs="+", default=list(DEFAULT_THRESHOLDS))
    parser.add_argument("--warmup-days", type=int, default=DEFAULT_WARMUP_DAYS)
    parser.add_argument("--output", help="also write the report to this file")
    args = parser.parse_args(argv)

    # A throwaway in-memory bank, so the evaluation never touches the application database.
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    try:
        synthetic.generate(db, synthetic.SyntheticConfig(customers=args.customers, seed=args.seed, end=EVALUATION_END))
        report = format_report(
            evaluate(db, args.thresholds, warmup_days=args.warmup_days),
            title=f"R014 threshold evaluation ({args.customers} customers, seed {args.seed})",
        )
    finally:
        db.close()
    print(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(report)


if __name__ == "__main__":
    main()
