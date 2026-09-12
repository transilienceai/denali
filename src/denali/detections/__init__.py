"""Deterministic runtime detection rules."""

from denali.detections.engine import (
    AWS_RISKY_SEQUENCE_RULE_UID,
    AWS_UNAPPROVED_TOOL_RULE_UID,
    AWS_UNDECLARED_MODEL_RULE_UID,
    ENTRA_CONSENT_RULE_UID,
    ENTRA_FAILURE_RULE_UID,
    UNREVIEWED_MODEL_RULE_UID,
    evaluate_aws_risky_action_sequence,
    evaluate_aws_unapproved_tool_invocation,
    evaluate_aws_undeclared_model_invocation,
    evaluate_repeated_failed_ai_signins,
    evaluate_unreviewed_ai_consent,
    evaluate_unreviewed_model_invocation,
)

__all__ = [
    "AWS_RISKY_SEQUENCE_RULE_UID",
    "AWS_UNAPPROVED_TOOL_RULE_UID",
    "AWS_UNDECLARED_MODEL_RULE_UID",
    "ENTRA_CONSENT_RULE_UID",
    "ENTRA_FAILURE_RULE_UID",
    "UNREVIEWED_MODEL_RULE_UID",
    "evaluate_aws_risky_action_sequence",
    "evaluate_aws_unapproved_tool_invocation",
    "evaluate_aws_undeclared_model_invocation",
    "evaluate_repeated_failed_ai_signins",
    "evaluate_unreviewed_ai_consent",
    "evaluate_unreviewed_model_invocation",
]
