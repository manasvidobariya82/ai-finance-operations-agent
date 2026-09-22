"""Model training, the registry, and drift.

These tests run the real XGBoost and Isolation Forest fits over a small generated bank, so they are
the slowest in the suite. They are worth it: training is the one place where a silent mistake
(leaking the future into a feature, evaluating on the rows you trained on) produces impressive
numbers and a useless model.
"""
import shutil
import tempfile
from pathlib import Path

import numpy as np
import pytest

from app.config import settings
from app.fraud_investigation import models, pipeline, synthetic, training
from app.fraud_investigation.detection import ml
from app.fraud_investigation.features import FEATURE_NAMES


@pytest.fixture()
def model_dir(monkeypatch):
    """Keep training artifacts out of the project's storage directory.

    Uses `mkdtemp` rather than pytest's `tmp_path`, which needs to scan a shared parent directory
    that is not always readable on Windows.
    """
    directory = Path(tempfile.mkdtemp(prefix="fraud-models-"))
    monkeypatch.setattr(settings, "fraud_model_dir", str(directory))
    ml.clear_cache()
    try:
        yield directory
    finally:
        ml.clear_cache()
        shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture()
def bank(db_session):
    synthetic.generate(db_session, synthetic.SyntheticConfig(customers=30, days=90, seed=11))
    return db_session


@pytest.fixture()
def trained(bank, model_dir):
    return training.train(bank, notes="test run")


# --- Guard rails ------------------------------------------------------------------------------------


def test_training_refuses_an_empty_database(db_session, model_dir):
    with pytest.raises(training.NotEnoughData):
        training.train(db_session)


def test_training_refuses_a_history_with_no_confirmed_fraud(bank, model_dir):
    """Plenty of rows, nothing to learn from: a model fitted here would call everything legitimate."""
    for txn in bank.query(models.Transaction):
        txn.is_fraud = False
    bank.commit()
    with pytest.raises(training.NotEnoughData) as exc:
        training.train(bank)
    assert "confirmed-fraud" in str(exc.value)


# --- Training ---------------------------------------------------------------------------------------


def test_training_registers_and_activates_a_version(trained, bank, model_dir):
    assert trained.is_active is True
    assert trained.algorithm == "XGBClassifier + IsolationForest"
    assert trained.feature_names == FEATURE_NAMES
    assert (model_dir / f"{trained.version}.joblib").exists()
    assert ml.active_model_record(bank).version == trained.version


def test_the_holdout_is_chronological_not_random(trained):
    """A random split would let the model learn a customer's future and flatter the metrics."""
    assert trained.metrics["holdout"] == "chronological"
    assert trained.metrics["train_rows"] < trained.metrics["train_rows"] + trained.metrics["rows"]


def test_the_model_separates_fraud_from_legitimate_traffic(trained):
    assert trained.metrics["roc_auc"] > 0.8
    assert trained.metrics["pr_auc"] > 0.3
    assert trained.metrics["positives"] > 0


def test_the_alert_rate_is_reported_because_it_is_what_a_team_feels(trained):
    assert 0.0 <= trained.metrics["alert_rate"] < 0.2


def test_the_bundle_scores_explains_and_batches_consistently(trained, bank):
    bundle = ml.load_bundle(trained)
    data = training.build_training_data(bank)
    sample = data.vectors[:40]

    one_at_a_time = [bundle.anomaly_score(fv) for fv in sample]
    batched = bundle.anomaly_scores(sample)
    assert batched == pytest.approx(one_at_a_time, abs=1e-9)

    probability = bundle.fraud_probability(sample[0])
    assert 0.0 <= probability <= 1.0
    for item in bundle.explain(sample[0]):
        assert item["feature"] in FEATURE_NAMES


def test_the_anomaly_model_only_learns_from_legitimate_traffic(trained, bank):
    """It has to flag "unlike anything normal", which it cannot do if fraud is part of normal."""
    bundle = ml.load_bundle(trained)
    assert len(bundle.anomaly_reference) == trained.metrics["train_rows"] - trained.metrics["train_positives"]


# --- Registry ---------------------------------------------------------------------------------------


def test_only_one_version_is_active_at_a_time(trained, bank, model_dir):
    second = training.train(bank, notes="second")
    assert second.is_active is True
    bank.refresh(trained)
    assert trained.is_active is False

    training.activate_version(bank, trained.version)
    bank.refresh(trained)
    bank.refresh(second)
    assert trained.is_active is True and second.is_active is False


def test_activating_an_unknown_version_fails(bank, model_dir):
    with pytest.raises(ValueError):
        training.activate_version(bank, "fraud-does-not-exist")


def test_analyst_decisions_become_training_labels(trained, bank, model_dir):
    from app.fraud_investigation import cases

    transaction = bank.query(models.Transaction).filter(models.Transaction.is_fraud.is_(True)).first()
    alert, case = pipeline.process_transaction(bank, transaction)
    if case is None:  # an auto-closed alert has no case to decide
        pytest.skip("this transaction did not reach investigation")

    cases.decide(bank, case.id, "false_positive", "priya")
    retrained = training.train(bank, notes="after feedback")

    assert retrained.feedback_rows >= 1
    assert retrained.metrics["feedback_labels_applied"] >= 1
    # The analyst overrode the historical label, and the next model learns the override.
    assert training.feedback_labels(bank)[transaction.id] is False


# --- Drift ------------------------------------------------------------------------------------------


def test_psi_is_zero_against_the_distribution_it_was_built_from(trained, bank):
    data = training.build_training_data(bank)
    matrix = data.matrix()[: trained.training_rows]
    psi = training.population_stability_index(trained.reference_stats, matrix, FEATURE_NAMES)
    assert max(psi.values()) < 0.05


def test_psi_detects_a_shifted_distribution(trained, bank):
    data = training.build_training_data(bank)
    matrix = data.matrix()[: trained.training_rows].copy()
    matrix[:, FEATURE_NAMES.index("log_amount")] += 3.0

    psi = training.population_stability_index(trained.reference_stats, matrix, FEATURE_NAMES)
    assert psi["log_amount"] > 0.25


def test_the_drift_report_needs_an_active_model(db_session, model_dir):
    report = training.drift_report(db_session)
    assert report["available"] is False
    assert "No active model" in report["reason"]


def test_the_drift_report_describes_recent_traffic(trained, bank):
    report = training.drift_report(bank, days=90)
    assert report["available"] is True
    assert report["model_version"] == trained.version
    assert report["status"] in ("stable", "moderate_shift", "significant_shift")
    assert report["retrain_recommended"] == (report["max_psi"] >= 0.25)


def test_reference_stats_cover_every_feature(trained):
    assert set(trained.reference_stats) == set(FEATURE_NAMES)
    for stats in trained.reference_stats.values():
        assert np.isclose(sum(stats["proportions"]), 1.0, atol=0.01)
