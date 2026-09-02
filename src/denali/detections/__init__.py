"""Deterministic runtime detection rules."""

from denali.detections.engine import (
    ENTRA_CONSENT_RULE_UID,
    ENTRA_FAILURE_RULE_UID,
    UNREVIEWED_MODEL_RULE_UID,
    evaluate_repeated_failed_ai_signins,
    evaluate_unreviewed_ai_consent,
    evaluate_unreviewed_model_invocation,
)

__all__ = [
    "ENTRA_CONSENT_RULE_UID",
    "ENTRA_FAILURE_RULE_UID",
    "UNREVIEWED_MODEL_RULE_UID",
    "evaluate_repeated_failed_ai_signins",
    "evaluate_unreviewed_ai_consent",
    "evaluate_unreviewed_model_invocation",
]
