from app.pipeline.approval import decide_approval


def test_recommended_reject_wins_outright():
    assert decide_approval(False, False, 5, "reject", 10.0) == "rejected"


def test_validation_errors_force_pending():
    assert decide_approval(True, False, 0, "auto_approve", 10.0) == "pending"


def test_duplicate_forces_pending():
    assert decide_approval(False, True, 0, "auto_approve", 10.0) == "pending"


def test_high_fraud_score_forces_pending():
    assert decide_approval(False, False, 90, "manual_review", 10.0) == "pending"


def test_clean_small_invoice_auto_approved():
    assert decide_approval(False, False, 5, "auto_approve", 50.0) == "auto_approved"


def test_clean_large_invoice_needs_review():
    assert decide_approval(False, False, 5, "auto_approve", 50000.0) == "pending"
