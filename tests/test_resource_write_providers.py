from __future__ import annotations

import copy

import pytest

from denali.resource_writes.providers import AwsInlineRemediator
from denali.resource_writes.templates import RemediationError, sha256


class Iam:
    def __init__(self, current, *, timeout=False, external_after=False):
        self.current = copy.deepcopy(current)
        self.timeout, self.external_after = timeout, external_after
        self.put_calls = 0

    def get_role_policy(self, **kwargs):
        assert kwargs == {"RoleName": "AIWorker", "PolicyName": "InvokeModel"}
        return {"PolicyDocument": copy.deepcopy(self.current)}

    def put_role_policy(self, **kwargs):
        import json

        self.put_calls += 1
        self.current = json.loads(kwargs["PolicyDocument"])
        if self.external_after:
            self.current["ExternalWriter"] = "changed"
        if self.timeout:
            raise TimeoutError("provider-token-must-not-leak")


def inputs():
    before, proposed = {"Statement": []}, {"Statement": [{"Resource": "approved"}]}
    lease = {
        "resource": {
            "target_role_arn": "arn:aws:iam::123456789012:role/AIWorker",
            "policy_name": "InvokeModel",
        }
    }
    plan = {"before_sha256": sha256(before), "proposed_sha256": sha256(proposed)}
    return before, proposed, lease, plan


def test_aws_single_attempt_and_readback():
    before, proposed, lease, plan = inputs()
    fake = Iam(before)
    result = AwsInlineRemediator(lease, fake).execute_once(plan, proposed)
    assert result["policy_sha256"] == plan["proposed_sha256"]
    assert fake.put_calls == 1


def test_aws_drift_never_writes():
    before, proposed, lease, plan = inputs()
    before["external"] = True
    fake = Iam(before)
    with pytest.raises(RemediationError, match="aws_policy_drift"):
        AwsInlineRemediator(lease, fake).execute_once(plan, proposed)
    assert fake.put_calls == 0


def test_aws_timeout_reconciliation_is_read_only_not_blind_retry():
    before, proposed, lease, plan = inputs()
    fake = Iam(before, timeout=True)
    provider = AwsInlineRemediator(lease, fake)
    with pytest.raises(RemediationError, match="aws_write_outcome_unknown") as caught:
        provider.execute_once(plan, proposed)
    assert "provider-token" not in str(caught.value)
    assert provider.reconcile(plan)["policy_sha256"] == plan["proposed_sha256"]
    assert fake.put_calls == 1


def test_aws_external_concurrent_writer_is_not_automatically_overwritten():
    before, proposed, lease, plan = inputs()
    fake = Iam(before, external_after=True)
    provider = AwsInlineRemediator(lease, fake)
    with pytest.raises(RemediationError, match="manual_resolution"):
        provider.execute_once(plan, proposed)
    assert fake.put_calls == 1
    assert fake.current["ExternalWriter"] == "changed"
