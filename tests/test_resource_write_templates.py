from __future__ import annotations

import copy

import pytest

from denali.resource_writes.templates import (
    RemediationError,
    git_blob_sha,
    github_patch,
    tighten_inline_policy,
)


def github_finding(command="ConverseCommand", path="src/invoke.ts", line=2):
    return {
        "rule_uid": "DENALI-REPO-AI-GRD-001",
        "state": "open",
        "evaluation_result": "fail",
        "attributes": {"source_path": path, "source_line": line},
        "evidence": {"payload": {"command": command}},
    }


PARAMETERS = {"guardrail_id": "abc123", "guardrail_version": "1"}


@pytest.mark.parametrize(
    "command",
    [
        "ConverseCommand",
        "ConverseStreamCommand",
        "InvokeModelCommand",
        "InvokeModelWithResponseStreamCommand",
    ],
)
def test_github_template_inserts_only_approved_guardrail_fields(command):
    content = (
        f'import {{ {command} }} from "@aws-sdk/client-bedrock-runtime";\n'
        f'const request = new {command}({{modelId: "approved", body: input}});\n'
    ).encode()
    proposed, diff = github_patch(github_finding(command), content, PARAMETERS)
    assert b'guardrailIdentifier: "abc123"' in proposed
    assert b'guardrailVersion: "1"' in proposed
    assert (
        content.replace(
            b"{modelId:",
            b'{guardrailConfig: { guardrailIdentifier: "abc123", guardrailVersion: "1" }, modelId:',
        )
        == proposed
        if command.startswith("Converse")
        else (proposed.endswith(b'modelId: "approved", body: input});\n'))
    )
    assert diff.startswith("--- a/src/invoke.ts")
    assert git_blob_sha(content) != git_blob_sha(proposed)


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/test.ts",
        "src/../danger.ts",
        "vendor/x.ts",
        "src/node_modules/file.ts",
        "src/key.pem",
        "src/x.tsx",
    ],
)
def test_forbidden_github_paths_fail_closed(path):
    with pytest.raises(RemediationError, match="source_path_not_eligible"):
        github_patch(github_finding(path=path), b"", PARAMETERS)


@pytest.mark.parametrize("fragment", ["...config", "guardrailConfig: custom", "`template`"])
def test_ambiguous_or_existing_configuration_is_not_overwritten(fragment):
    content = (
        'import { ConverseCommand } from "@aws-sdk/client-bedrock-runtime";\n'
        f"new ConverseCommand({{{fragment}}});\n"
    ).encode()
    with pytest.raises(RemediationError):
        github_patch(github_finding(), content, PARAMETERS)


@pytest.mark.parametrize(
    "fragment",
    [
        "[key]: runtimeValue",
        '"guardrailIdentifier": existing',
        "'guardrailVersion': existing",
        "get guardrailIdentifier() { return existing; }",
        "guardrailIdentifier() { return existing; }",
        "body",
        r"\u0067uardrailIdentifier: existing",
    ],
)
def test_property_shapes_that_can_override_guardrails_are_never_executable(fragment):
    content = (
        'import { InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";\n'
        'new InvokeModelCommand({modelId: "approved", ' + fragment + "});\n"
    ).encode()
    with pytest.raises(RemediationError):
        github_patch(github_finding("InvokeModelCommand"), content, PARAMETERS)


def test_known_credential_material_is_never_returned_in_a_preview_diff():
    content = (
        b'import { InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";\n'
        b'new InvokeModelCommand({modelId: "approved"});\n'
        b'const api_key = "sk-proj-simulated-secret-value-00000";\n'
    )
    with pytest.raises(RemediationError, match="source_requires_secret_review") as caught:
        github_patch(github_finding("InvokeModelCommand"), content, PARAMETERS)
    assert "simulated-secret" not in str(caught.value)


@pytest.mark.parametrize(
    "parameters",
    [
        {"guardrail_id": "abc", "guardrail_version": "DRAFT"},
        {"guardrail_id": 'abc"; malicious()', "guardrail_version": "1"},
        {**PARAMETERS, "patch": "arbitrary"},
    ],
)
def test_no_arbitrary_patch_or_expression_authority(parameters):
    with pytest.raises(RemediationError, match="invalid_guardrail_selection"):
        github_patch(github_finding(), b"", parameters)


def aws_inputs():
    resource = {
        "target_role_arn": "arn:aws:iam::123456789012:role/AIWorker",
        "account_id": "123456789012",
        "policy_name": "InvokeApprovedModel",
    }
    finding = {
        "rule_uid": "DENALI-AWS-AI-IAM-001",
        "state": "open",
        "evaluation_result": "fail",
        "attributes": {"role_arn": resource["target_role_arn"]},
        "evidence": {
            "payload": {
                "configured_model_ids": ["anthropic.example-v1"],
                "matching_policy_statements": [
                    {
                        "policy_kind": "inline",
                        "policy_name": "InvokeApprovedModel",
                        "resources": ["arn:aws:bedrock:us-east-1::foundation-model/*"],
                    }
                ],
            }
        },
    }
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Invocation",
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel"],
                "Resource": "arn:aws:bedrock:us-east-1::foundation-model/*",
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            },
            {"Sid": "Unrelated", "Effect": "Deny", "Action": "s3:*", "Resource": "*"},
        ],
    }
    parameters = {
        "model_arns": ["arn:aws:bedrock:us-east-1::foundation-model/anthropic.example-v1"]
    }
    return finding, document, parameters, resource


def test_aws_narrows_only_existing_bedrock_allow_and_preserves_other_structure():
    finding, document, parameters, resource = aws_inputs()
    original = copy.deepcopy(document)
    proposed, diff = tighten_inline_policy(finding, document, parameters, resource)
    assert document == original
    assert proposed["Statement"][0]["Resource"] == parameters["model_arns"]
    assert proposed["Statement"][0]["Condition"] == original["Statement"][0]["Condition"]
    assert proposed["Statement"][1] == original["Statement"][1]
    assert '-      "Resource"' in diff


@pytest.mark.parametrize("fragment", ["[a]nthropic*", "[!b]nthropic*", "[a-z]nthropic*"])
def test_iam_literal_brackets_never_become_shell_character_class_authority(fragment):
    finding, document, parameters, resource = aws_inputs()
    document["Statement"][0]["Resource"] = "arn:aws:bedrock:us-east-1::foundation-model/" + fragment
    with pytest.raises(RemediationError, match="model_resource_not_subset"):
        tighten_inline_policy(finding, document, parameters, resource)


def test_iam_star_question_semantics_and_policy_variables_fail_closed():
    finding, document, parameters, resource = aws_inputs()
    document["Statement"][0]["Resource"] = (
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.exampl?-v1"
    )
    proposed, _ = tighten_inline_policy(finding, document, parameters, resource)
    assert proposed["Statement"][0]["Resource"] == parameters["model_arns"]
    document["Statement"][0]["Resource"] = (
        "arn:aws:bedrock:us-east-1::foundation-model/${aws:PrincipalTag/model}*"
    )
    with pytest.raises(RemediationError, match="policy_variables_not_supported"):
        tighten_inline_policy(finding, document, parameters, resource)


def test_iam_many_stars_use_bounded_nonrecursive_matching():
    from denali.resource_writes.templates import _iam_resource_matches

    assert not _iam_resource_matches("a" * 128, "*a" * 100 + "z")
    assert _iam_resource_matches("anthropic.example-v1", "***anthropic.*?-v1**")


@pytest.mark.parametrize(
    "change",
    [
        "managed_policy",
        "other_role",
        "mixed_actions",
        "not_action",
        "wrong_account",
        "unobserved_model",
        "other_region",
        "no_wildcard",
    ],
)
def test_aws_never_broadens_or_changes_unrelated_authority(change):
    finding, document, parameters, resource = aws_inputs()
    if change == "managed_policy":
        finding["evidence"]["payload"]["matching_policy_statements"][0]["policy_kind"] = "attached"
    elif change == "other_role":
        resource["target_role_arn"] += "Other"
    elif change == "mixed_actions":
        document["Statement"][0]["Action"].append("iam:*")
    elif change == "not_action":
        document["Statement"][0]["NotAction"] = "s3:*"
    elif change == "wrong_account":
        parameters["model_arns"] = [
            "arn:aws:bedrock:us-east-1:999999999999:inference-profile/anthropic.example-v1"
        ]
    elif change == "unobserved_model":
        parameters["model_arns"][0] += "-new"
    elif change == "other_region":
        parameters["model_arns"][0] = parameters["model_arns"][0].replace("us-east-1", "eu-west-1")
    else:
        document["Statement"][0]["Resource"] = parameters["model_arns"][0]
    with pytest.raises(RemediationError):
        tighten_inline_policy(finding, document, parameters, resource)
