"""Unresolved reusable templates are not evidence of failed source collection."""

import json
from pathlib import Path

import pytest

from denali.connectors.code_to_cloud import (
    CodeToCloudConnector,
    DeploymentTarget,
    _deployment_declarations,
)
from denali.connectors.static_deployment_values import (
    StaticResolutionLimit,
    cloudformation_document,
    cloudformation_value,
)
from denali.domain import CoverageState, DeploymentIdentifier, DeploymentIdentity


def test_generated_cloudformation_names_are_explicit_unmatched_candidates(tmp_path: Path):
    (tmp_path / "onboarding.yaml").write_text("""
Resources:
  SetupCallback:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Environment:
        Variables:
          REGION: !Ref AWS::Region
  RoleBootstrap:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
""")
    target = DeploymentTarget(
        natural_key="arn:aws:lambda:us-east-1:123456789012:function:generated-name",
        display_name="generated-name",
        service="lambda",
        evidence_locator="aws://synthetic",
        evidence_payload={},
        identity=DeploymentIdentity(
            "aws",
            "serverless_function",
            (
                DeploymentIdentifier("account_id", "123456789012"),
                DeploymentIdentifier("region", "us-east-1"),
                DeploymentIdentifier("cloudformation_logical_id", "SetupCallback"),
                DeploymentIdentifier("function_name", "generated-name"),
            ),
        ),
    )
    batch = CodeToCloudConnector(
        tmp_path, repository_name="github.com/fixture/onboarding", targets=(target,)
    ).collect()
    assert {coverage.state for coverage in batch.coverage} == {CoverageState.COMPLETE}
    assert batch.relationships == ()
    candidates = batch.assets[0].attributes["correlation_candidates"]
    assert len(candidates) == 2
    assert all(
        item["status"] == "unmatched" and item["resolution_state"] == "unknown"
        for item in candidates
    )
    assert all(item["deployment_identifier"] == "" for item in candidates)
    assert candidates[0]["unresolved_fields"] == ["account_id", "region", "function_name"]
    assert all(item["matched_workload_count"] == 0 for item in candidates)
    assert batch.assets[0].attributes["correlation_summary"]["unmatched"] == 2


def test_explicit_source_scope_can_resolve_literal_intrinsics_and_not_runtime_parameters():
    text = """
Metadata:
  Denali:
    AccountId: !Join ['', ['123456', '789012']]
    Region: !Sub '${Area}-east-1'
      # No runtime-derived value: this substitution intentionally stays unknown.
Resources:
  Agent:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub 'agent-${AWS::Region}'
"""
    declarations, warnings = _deployment_declarations(text, "template.yaml")
    assert warnings == []
    assert declarations[0].unresolved_fields == ("region", "function_name")
    explicit = text.replace("!Sub '${Area}-east-1'", "!Sub ['${Area}-east-1', {Area: us}]")
    declarations, warnings = _deployment_declarations(explicit, "template.yaml")
    assert warnings == []
    declaration = declarations[0]
    assert declaration.unresolved_fields == ()
    assert declaration.identity.values("account_id") == ("123456789012",)
    assert declaration.identity.values("region") == ("us-east-1",)
    assert declaration.identity.values("function_name") == ("agent-us-east-1",)


def test_parameter_defaults_are_not_deployed_parameter_values():
    declarations, warnings = _deployment_declarations(
        """
Metadata:
  Denali: {AccountId: '123456789012', Region: us-east-1}
Parameters:
  FunctionName:
    Type: String
    Default: default-only-name
Resources:
  Agent:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Ref FunctionName
""",
        "template.yml",
    )
    assert warnings == []
    assert declarations[0].unresolved_fields == ("function_name",)
    assert declarations[0].identity.values("function_name") == ()


def test_unresolved_pseudo_parameters_never_use_observed_cloud_scope():
    declarations, warnings = _deployment_declarations(
        """
Metadata:
  Denali:
    AccountId: !Ref AWS::AccountId
    Region: !Ref AWS::Region
Resources:
  Agent:
    Type: AWS::Lambda::Function
    Properties: {FunctionName: fixture-agent}
""",
        "template.yaml",
    )
    assert warnings == []
    assert declarations[0].unresolved_fields == ("account_id", "region")
    assert declarations[0].identity.values("account_id") == ()
    assert declarations[0].identity.values("region") == ()


def test_json_and_yaml_intrinsics_have_the_same_static_semantics():
    json_template = """{
      "Metadata": {"Denali": {"AccountId": "123456789012", "Region": "us-east-1"}},
      "Resources": {"Agent": {"Type": "AWS::Lambda::Function", "Properties": {
        "FunctionName": {"Fn::Sub": ["${Prefix}-${AWS::Region}", {"Prefix": "fixture"}]}
      }}}
    }"""
    declarations, warnings = _deployment_declarations(json_template, "template.json")
    assert warnings == []
    assert declarations[0].identity.values("function_name") == ("fixture-us-east-1",)


def test_different_conditional_names_remain_ambiguous_not_a_literal_guess():
    value = cloudformation_value({"Fn::If": ["IsProd", "prod-agent", "dev-agent"]})
    assert value.state == "ambiguous" and value.value is None
    equal = cloudformation_value({"Fn::If": ["IsProd", "same-agent", "same-agent"]})
    assert equal.state == "literal" and equal.value == "same-agent"
    assert (
        cloudformation_value(
            {"Fn::FindInMap": ["Names", "Prod", "Name"]},
            mappings={"Names": {"Prod": {"Name": "prod-agent"}}},
        ).value
        == "prod-agent"
    )


@pytest.mark.parametrize(
    "text",
    [
        "Resources: {Agent: {Type: AWS::Lambda::Function, Type: AWS::Lambda::Function}}",
        "Resources: &resources {Agent: *resources}",
        "Resources: {Agent: !!python/object/apply:os.system ['do-not-execute']}",
        "Resources: {Agent: [unterminated}",
    ],
)
def test_malformed_duplicate_recursive_and_constructor_yaml_stays_partial(text, tmp_path):
    (tmp_path / "template.yaml").write_text(text)
    batch = CodeToCloudConnector(tmp_path, targets=(), repository_name="fixture").collect()
    assert batch.relationships == ()
    assert {coverage.state for coverage in batch.coverage} == {CoverageState.PARTIAL}
    assert "could not be statically parsed" in batch.coverage[0].detail


def test_value_budgets_and_unknown_functions_fail_closed_without_execution():
    assert cloudformation_value({"Fn::ImportValue": "external-name"}).value is None
    assert cloudformation_value({"Fn::GetAtt": ["Agent", "Arn"]}).value is None
    assert cloudformation_value({"Fn::Sub": "${AWS::AccountId}"}).value is None
    assert cloudformation_value({"Fn::Sub": "${!Literal}"}).value is None
    assert cloudformation_value({"Fn::Join": ["", ["x"] * 129]}).value is None
    assert cloudformation_value("x" * 1_025).value is None
    with pytest.raises(ValueError, match="statically parsed"):
        cloudformation_document('{"Resources":{},"Resources":{}}', json_input=True)


def test_mapping_cycles_and_fanout_have_one_global_resolution_budget():
    reference = {"Fn::FindInMap": ["Names", "Branch", "Value"]}
    recursive = {"Fn::Join": ["", [reference] * 128]}
    budget = [1_000]
    value = cloudformation_value(
        reference,
        mappings={"Names": {"Branch": {"Value": recursive}}},
        _budget=budget,
    )
    assert value.value is None
    assert 0 < budget[0] < 1_000  # Cycle rejected before recursively expanding each branch.
    other = {"Fn::FindInMap": ["Names", "Other", "Value"]}
    assert (
        cloudformation_value(
            reference,
            mappings={"Names": {"Branch": {"Value": other}, "Other": {"Value": reference}}},
        ).value
        is None
    )
    branching = "literal"
    for _ in range(12):
        branching = {"Fn::If": ["Condition", branching, branching]}
    budget = [100]
    with pytest.raises(StaticResolutionLimit):
        cloudformation_value(branching, _budget=budget)
    assert -100 < budget[0] < 0


@pytest.mark.parametrize("branches", [1, 2])
def test_expression_depth_and_operation_limits_keep_coverage_explicitly_partial(tmp_path, branches):
    length = 40 if branches == 1 else 12
    rows = {f"n{length}": {"Value": "fixture-agent"}}
    for index in range(length):
        reference = {"Fn::FindInMap": ["Names", f"n{index + 1}", "Value"]}
        rows[f"n{index}"] = {
            "Value": reference if branches == 1 else {"Fn::If": ["Condition", reference, reference]}
        }
    document = {
        "Metadata": {"Denali": {"AccountId": "123456789012", "Region": "us-east-1"}},
        "Mappings": {"Names": rows},
        "Resources": {
            "Agent": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Fn::FindInMap": ["Names", "n0", "Value"]},
                },
            }
        },
    }
    (tmp_path / "template.json").write_text(json.dumps(document))
    batch = CodeToCloudConnector(tmp_path, targets=(), repository_name="fixture").collect()
    assert batch.relationships == ()
    assert {coverage.state for coverage in batch.coverage} == {CoverageState.PARTIAL}
    assert "static expression resolution limit reached" in batch.coverage[0].detail


def test_dense_json_is_rejected_before_the_decoder_allocates_a_tree(monkeypatch):
    import denali.connectors.static_deployment_values as values

    def no_decode(*_args, **_kwargs):
        raise AssertionError("JSON decoder must not allocate this tree")

    monkeypatch.setattr(values.json, "loads", no_decode)
    dense = '{"Resources": {}, "Data": [' + ",".join(["0"] * 50_001) + "]}"
    with pytest.raises(ValueError, match="statically parsed"):
        values.cloudformation_document(dense, json_input=True)


def test_dense_yaml_is_rejected_during_composition_before_conversion(monkeypatch):
    import denali.connectors.static_deployment_values as values

    def no_convert(*_args, **_kwargs):
        raise AssertionError("YAML composer must stop before allocating the entire tree")

    monkeypatch.setattr(values, "_yaml_value", no_convert)
    dense = "Resources: {}\nData: [" + ",".join(["0"] * 50_001) + "]"
    with pytest.raises(ValueError, match="statically parsed"):
        values.cloudformation_document(dense)
