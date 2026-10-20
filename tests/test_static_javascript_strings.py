"""CDK string resolution never runs JavaScript or borrows a shadowed binding."""

from pathlib import Path

import pytest

from denali.connectors.code_to_cloud import (
    CodeToCloudConnector,
    DeploymentTarget,
    _deployment_declarations,
)
from denali.domain import DeploymentIdentifier, DeploymentIdentity


def declarations(expression, prefix="", tail=""):
    source = (
        prefix
        + "\nnew lambda.Function(this, 'Agent', { functionName: "
        + expression
        + ", entry: 'src/handler.ts' });\n"
        + tail
    )
    return _deployment_declarations(source, "infra/stack.ts")


@pytest.mark.parametrize(
    "expression,prefix",
    [
        ("'fixture-agent'", ""),
        ('"fixture-agent"', ""),
        ("'fixture-' + 'agent'", ""),
        ("`fixture-agent`", ""),
        ("name", "const name = 'fixture-agent';"),
        ("functionName", "const prefix = 'fixture'; const functionName = prefix + '-agent';"),
        ("`${prefix}-agent`", "const prefix = 'fixture';"),
        ("prefix + '-agent'", "const prefix = 'fixture';"),
    ],
)
def test_fully_static_direct_names_resolve_without_execution(expression, prefix):
    found, warnings = declarations(expression, prefix)
    assert warnings == []
    assert len(found) == 1
    assert found[0].deployment_name == "fixture-agent"


@pytest.mark.parametrize(
    "expression,prefix,tail",
    [
        ("'fixture-' + dynamic", "", ""),
        ("makeName()", "", ""),
        ("process.env.FUNCTION_NAME", "", ""),
        ("`${process.env.PREFIX}-agent`", "", ""),
        ("name", "let name = 'fixture-agent';", ""),
        ("name", "const name = 'fixture-agent'; function example(name) {", "}"),
        ("name", "const name = 'fixture-agent'; function example() {", "var name = dynamic; }"),
        ("name", "const name = 'fixture-agent'; function example() { const name = dynamic;", "}"),
        ("name", "const name = 'fixture-agent';", "name = dynamic;"),
        ("name", "const name = 'fixture-agent';", "name += '-changed';"),
        ("later", "", "const later = 'fixture-agent';"),
        ("name", "const name = other; const other = name;", ""),
    ],
)
def test_dynamic_mutable_shadowed_and_conflicting_values_remain_unresolved(
    expression, prefix, tail
):
    found, warnings = declarations(expression, prefix, tail)
    assert found == []
    assert len(warnings) == 1
    assert "functionName is not literal" in warnings[0]


@pytest.mark.parametrize(
    "properties",
    [
        "environment: { functionName: 'fixture-agent' }",
        "functionName: 'fixture-agent', functionName: dynamic",
        "...props, functionName: 'fixture-agent'",
        "functionName: 'fixture-agent', ...props",
        "[dynamic]: value, functionName: 'fixture-agent'",
        "functionName: 'fixture-agent'.replace('fixture', 'other')",
    ],
)
def test_nested_duplicate_spread_and_partial_literal_properties_are_not_proof(properties):
    found, warnings = _deployment_declarations(
        "new lambda.Function(this, 'Agent', {" + properties + "});", "infra/stack.ts"
    )
    assert found == []
    assert len(warnings) == 1


def test_a_constructor_inside_a_string_or_comment_is_not_a_real_declaration():
    found, _warnings = _deployment_declarations(
        """const sample = "new lambda.Function(this, 'Agent', { functionName: 'fixture-agent' });";
        // new lambda.Function(this, 'Commented', { functionName: 'fixture-comment' });
        """,
        "infra/stack.ts",
    )
    assert found == []


def test_module_const_shorthand_is_resolved_only_when_immutable_and_unshadowed():
    found, warnings = _deployment_declarations(
        "const functionName = 'fixture-agent'; "
        "new lambda.Function(this, 'Agent', { functionName });",
        "infra/stack.ts",
    )
    assert warnings == []
    assert found[0].deployment_name == "fixture-agent"


@pytest.mark.parametrize(
    "overwrite",
    [
        "get functionName() { return 'different'; }",
        "set functionName(value) {}",
        "async functionName() { return 'different'; }",
        "functionName() { return 'different'; }",
        "get ['functionName']() { return 'different'; }",
    ],
)
def test_accessors_and_methods_never_preserve_a_false_literal_match(tmp_path: Path, overwrite):
    (tmp_path / "stack.ts").write_text(
        "new lambda.Function(this, 'Agent', {functionName: 'fixture-agent', " + overwrite + "});"
    )
    target = DeploymentTarget(
        natural_key="fixture-target",
        display_name="fixture-agent",
        service="lambda",
        evidence_locator="aws://fixture",
        evidence_payload={},
        identity=DeploymentIdentity(
            "aws",
            "serverless_function",
            (
                DeploymentIdentifier("cloudformation_logical_id", "AgentABC123"),
                DeploymentIdentifier("function_name", "fixture-agent"),
            ),
        ),
    )
    batch = CodeToCloudConnector(tmp_path, repository_name="fixture", targets=(target,)).collect()
    assert batch.relationships == ()
    assert "functionName is not literal" in batch.coverage[0].detail


def test_constant_fanout_has_one_shared_resolution_budget():
    prefix = "const v0 = 'x';"
    for index in range(1, 12):
        prefix += f"const v{index} = v{index - 1} + v{index - 1};"
    found, warnings = declarations("v11", prefix)
    assert found == []
    assert "functionName is not literal" in warnings[0]
