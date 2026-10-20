"""Bounded static CloudFormation values, without running template constructors.

Deployment-time parameters, generated resource names and ambient AWS identity are
not source facts. Only fully literal expressions can become correlation inputs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

_MAX_TEMPLATE_BYTES = 2_000_000
_MAX_NODES = 50_000
_MAX_DEPTH = 32
_MAX_VALUE_LENGTH = 1_024
_MAX_PARTS = 128
_SUBSTITUTION = re.compile(r"\$\{([^{}]+)\}")


class StaticResolutionLimit(ValueError):
    """A safety bound stopped analysis, rather than a runtime-only source value."""

    def __init__(self) -> None:
        super().__init__("static_expression_resolution_limit")


class _BoundedLoader(yaml.SafeLoader):
    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._static_nodes = 0
        self._static_depth = 0

    def compose_node(self, parent: Node | None, index: Any) -> Node:
        self._static_nodes += 1
        self._static_depth += 1
        try:
            if (
                self._static_nodes > _MAX_NODES
                or self._static_depth > _MAX_DEPTH
                or self.check_event(yaml.AliasEvent)
            ):
                raise ValueError("template structure exceeds limits")
            return super().compose_node(parent, index)
        finally:
            self._static_depth -= 1


def _json_preflight(text: str) -> None:
    """Bound structure before the strict decoder allocates dictionaries/lists."""

    depth = nodes = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            nodes += 1
        elif char in "]}":
            depth -= 1
        elif char in ",:":
            nodes += 1
        if depth > _MAX_DEPTH or nodes > _MAX_NODES:
            raise ValueError("template structure exceeds limits")


@dataclass(frozen=True, slots=True)
class StaticValue:
    value: str | None
    state: Literal["literal", "unknown", "ambiguous"] = "unknown"


def _literal(value: Any) -> StaticValue:
    if (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_VALUE_LENGTH
        and not any(ord(char) < 32 for char in value)
        and "${" not in value
        and "{{" not in value
        and "Token[" not in value
    ):
        return StaticValue(value, "literal")
    return StaticValue(None)


def cloudformation_document(text: str, *, json_input: bool = False) -> dict[str, Any] | None:
    """Read metadata/IaC structure only; aliases and duplicate keys fail closed."""

    if len(text.encode()) > _MAX_TEMPLATE_BYTES:
        raise ValueError("CloudFormation template exceeds the static parsing limit")
    try:
        if json_input:
            _json_preflight(text)
            document = json.loads(text, object_pairs_hook=_unique_object)
            _bounded_json(document)
        else:
            node = yaml.compose(text, Loader=_BoundedLoader)
            document = _yaml_value(node, set(), [0]) if node is not None else None
    except (yaml.YAMLError, json.JSONDecodeError, RecursionError, ValueError):
        raise ValueError("CloudFormation template could not be statically parsed") from None
    if not isinstance(document, dict) or not isinstance(document.get("Resources"), dict):
        return None
    return document


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate template key")
        result[key] = value
    return result


def _bounded_json(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if depth > _MAX_DEPTH or count[0] > _MAX_NODES:
        raise ValueError("template structure exceeds limits")
    children = (
        value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    )
    for child in children:
        _bounded_json(child, depth + 1, count)


def _yaml_value(node: Node, seen: set[int], count: list[int], depth: int = 0) -> Any:
    count[0] += 1
    if depth > _MAX_DEPTH or count[0] > _MAX_NODES or id(node) in seen:
        raise ValueError("template aliases or structure exceed limits")
    seen.add(id(node))
    normal_tags = {
        f"tag:yaml.org,2002:{kind}"
        for kind in (
            "str",
            "seq",
            "map",
            "int",
            "float",
            "bool",
            "null",
            "timestamp",
        )
    }
    if not node.tag.startswith("!") and node.tag not in normal_tags:
        raise ValueError("unsupported template tag")
    if isinstance(node, ScalarNode):
        value: Any = node.value if node.tag == "tag:yaml.org,2002:str" else None
    elif isinstance(node, SequenceNode):
        value = [_yaml_value(child, seen, count, depth + 1) for child in node.value]
    elif isinstance(node, MappingNode):
        pairs = []
        for key, child in node.value:
            if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                raise ValueError("template keys must be literal strings")
            pairs.append((key.value, _yaml_value(child, seen, count, depth + 1)))
        value = _unique_object(pairs)
    else:
        raise ValueError("unsupported template structure")
    if node.tag.startswith("!"):
        name = node.tag[1:]
        # Compose never constructs arbitrary YAML tags, including Python objects.
        # Unknown intrinsic names remain unresolvable values, never source code.
        payload = node.value if isinstance(node, ScalarNode) else value
        return {"Ref" if name == "Ref" else f"Fn::{name}": payload}
    if not node.tag.startswith("tag:yaml.org,2002:"):
        raise ValueError("unsupported template tag")
    return value


def cloudformation_value(
    value: Any,
    *,
    bindings: dict[str, str] | None = None,
    mappings: dict[str, Any] | None = None,
    _depth: int = 0,
    _budget: list[int] | None = None,
    _mapping_path: frozenset[tuple[str, ...]] = frozenset(),
) -> StaticValue:
    """Resolve a small typed expression subset; never assume parameter defaults.

    Bindings are explicit source metadata only. In particular, an observed cloud
    target must never supply AWS::AccountId/Region or a template parameter value.
    """

    _budget = [4_096] if _budget is None else _budget
    _budget[0] -= 1
    if _depth > _MAX_DEPTH or _budget[0] < 0:
        raise StaticResolutionLimit()
    if isinstance(value, str):
        return _literal(value)
    if not isinstance(value, dict) or len(value) != 1:
        return StaticValue(None)
    bindings = bindings or {}
    mappings = mappings or {}

    def resolve(item: Any) -> StaticValue:
        return cloudformation_value(
            item,
            bindings=bindings,
            mappings=mappings,
            _depth=_depth + 1,
            _budget=_budget,
            _mapping_path=_mapping_path,
        )

    if "Ref" in value:
        name = value["Ref"]
        return _literal(bindings.get(name)) if isinstance(name, str) else StaticValue(None)
    if "Fn::Sub" in value:
        expression = value["Fn::Sub"]
        variables: dict[str, Any] = {}
        if isinstance(expression, list) and len(expression) == 2:
            expression, variables = expression
        if not isinstance(expression, str) or not isinstance(variables, dict):
            return StaticValue(None)
        if len(expression) > _MAX_VALUE_LENGTH or len(variables) > _MAX_PARTS:
            return StaticValue(None)
        unknown = False

        def substitute(match: re.Match[str]) -> str:
            nonlocal unknown
            key = match.group(1)
            resolved = resolve(variables[key]) if key in variables else _literal(bindings.get(key))
            if resolved.value is None:
                unknown = True
                return ""
            return resolved.value

        result = _SUBSTITUTION.sub(substitute, expression)
        return StaticValue(None) if unknown else _literal(result)
    if "Fn::Join" in value:
        expression = value["Fn::Join"]
        if (
            not isinstance(expression, list)
            or len(expression) != 2
            or not isinstance(expression[0], str)
            or len(expression[0]) > _MAX_VALUE_LENGTH
            or not isinstance(expression[1], list)
            or len(expression[1]) > _MAX_PARTS
        ):
            return StaticValue(None)
        parts = [resolve(item) for item in expression[1]]
        if any(part.value is None for part in parts):
            return StaticValue(None)
        return _literal(expression[0].join(part.value for part in parts if part.value is not None))
    if "Fn::FindInMap" in value:
        expression = value["Fn::FindInMap"]
        if not isinstance(expression, list) or len(expression) != 3:
            return StaticValue(None)
        keys = [resolve(item).value for item in expression]
        if any(key is None for key in keys):
            return StaticValue(None)
        mapping_key = tuple(key for key in keys if key is not None)
        if mapping_key in _mapping_path:
            return StaticValue(None)
        found: Any = mappings
        for key in keys:
            found = found.get(key) if isinstance(found, dict) else None
        return cloudformation_value(
            found,
            bindings=bindings,
            mappings=mappings,
            _depth=_depth + 1,
            _budget=_budget,
            _mapping_path=_mapping_path | {mapping_key},
        )
    if "Fn::If" in value:
        expression = value["Fn::If"]
        if not isinstance(expression, list) or len(expression) != 3:
            return StaticValue(None)
        yes, no = resolve(expression[1]), resolve(expression[2])
        if yes.value is not None and yes == no:
            return yes
        return StaticValue(
            None, "ambiguous" if yes.value is not None and no.value is not None else "unknown"
        )
    return StaticValue(None)
