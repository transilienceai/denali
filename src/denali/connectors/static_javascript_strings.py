"""Conservative string-only CDK properties; this is not a JavaScript evaluator."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")
_MAX_TOKENS = 50_000
_MAX_OUTPUT = 1_024


@dataclass(frozen=True, slots=True)
class _Token:
    value: str
    start: int
    end: int
    depth: int
    string: bool = False


def _tokens(source: str) -> list[_Token]:
    result = []
    stack = []
    index = 0
    while index < len(source):
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise ValueError("unclosed comment")
            index = end + 2
            continue
        start = index
        string = char in "'\"`"
        if string:
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == char:
                    index += 1
                    break
                else:
                    index += 1
            else:
                raise ValueError("unclosed string")
        else:
            match = _IDENTIFIER.match(source, index)
            index = match.end() if match else index + 1
        value = source[start:index]
        if not string and value in ")}]":
            if not stack or {"(": ")", "{": "}", "[": "]"}[stack.pop()] != value:
                raise ValueError("unbalanced syntax")
        result.append(_Token(value, start, index, len(stack), string))
        if not string and value in "({[":
            stack.append(value)
        # Slash expressions may be regular expressions, not executable syntax we
        # can safely disambiguate. Do not discover constructors inside regexes.
        if not string and value == "/":
            raise ValueError("unsupported slash expression")
        if len(result) > _MAX_TOKENS:
            raise ValueError("static token budget exceeded")
    if stack:
        raise ValueError("unbalanced syntax")
    return result


def javascript_string_property(
    source: str, object_start: int, object_end: int, key: str
) -> str | None:
    """Resolve one direct object property from strings and unshadowed module consts.

    Constants must precede the use and have no earlier references (which could
    introduce a shadowing parameter), conflicting declarations or assignments.
    Runtime calls, member access, environment values and imported symbols are not
    interpreted. Conservative rejection is preferable to a wrong deployment edge.
    """

    try:
        tokens = _tokens(source)
        opening = next(token for token in tokens if token.start == object_start)
        if opening.value != "{":
            return None
        body = [token for token in tokens if object_start < token.start < object_end]
        depth = opening.depth + 1
        expressions: list[list[_Token]] = []
        index = 0
        while index < len(body):
            token = body[index]
            if token.depth != depth or token.value == ",":
                index += 1
                continue
            # Spreads and computed keys can overwrite the declared property.
            if token.value in {".", "["}:
                return None
            end = index + 1
            while end < len(body) and not (body[end].depth == depth and body[end].value == ","):
                end += 1
            name = _string_literal(token.value) if token.string else token.value
            plain_property = index + 1 < end and body[index + 1].value == ":"
            shorthand = index + 1 == end and not token.string and _IDENTIFIER.fullmatch(name)
            # Accessors/methods can overwrite an earlier functionName property.
            # Accept only the two exact object-member forms we understand.
            if not plain_property and not shorthand:
                return None
            if name == key:
                if plain_property:
                    expressions.append(body[index + 2 : end])
                elif shorthand:
                    expressions.append([token])
                else:
                    return None
            index = end + 1
        if len(expressions) != 1:
            return None
        value = _expression(expressions[0], tokens, source, object_start, set(), [256])
        if value and len(value) <= _MAX_OUTPUT and not any(ord(char) < 32 for char in value):
            if "${" not in value and "Token[" not in value:
                return value
    except (ValueError, StopIteration, RecursionError):
        pass
    return None


def _string_literal(value: str) -> str | None:
    if len(value) < 2 or value[0] != value[-1]:
        return None
    if value.startswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    # Keep the grammar small: plain single-quoted strings/backticks only.
    return value[1:-1] if value[0] in "'`" and "\\" not in value else None


def _binding(
    name: str,
    tokens: list[_Token],
    source: str,
    before: int,
    seen: set[str],
    budget: list[int],
) -> str | None:
    budget[0] -= 1
    if budget[0] < 0 or name in seen or len(seen) >= 16:
        return None
    declarations = [
        index
        for index in range(1, len(tokens))
        if not tokens[index].string
        and tokens[index].value == name
        and tokens[index - 1].value in {"const", "let", "var", "function", "class"}
    ]
    if len(declarations) != 1:
        return None
    index = declarations[0]
    declaration = tokens[index]
    occurrences = [
        token
        for token in tokens
        if not token.string and token.value == name and token.start < before
    ]
    if (
        tokens[index - 1].value != "const"
        or declaration.depth != 0
        or declaration.start >= before
        or len(occurrences) != 1
        or index + 1 >= len(tokens)
        or tokens[index + 1].value != "="
    ):
        return None
    for position, token in enumerate(tokens[:-1]):
        if token.value != name or token.string or token.start == declaration.start:
            continue
        next_value = tokens[position + 1].value
        if next_value == "=" or (
            next_value in {"+", "-"}
            and position + 2 < len(tokens)
            and tokens[position + 2].value in {next_value, "="}
        ):
            return None
    end = index + 2
    while end < len(tokens) and not (tokens[end].depth == 0 and tokens[end].value == ";"):
        if tokens[end].start >= before:
            return None
        end += 1
    return _expression(
        tokens[index + 2 : end],
        tokens,
        source,
        declaration.start,
        seen | {name},
        budget,
    )


def _expression(
    parts: list[_Token],
    tokens: list[_Token],
    source: str,
    before: int,
    seen: set[str],
    budget: list[int],
) -> str | None:
    if not parts or len(parts) > 256:
        return None
    values = []
    expect_term = True
    for token in parts:
        if not expect_term:
            if token.value != "+" or token.string:
                return None
            expect_term = True
            continue
        if token.string:
            value = _string_literal(token.value)
            if value is not None and token.value.startswith("`"):
                unresolved = False

                def replace(match: re.Match[str]) -> str:
                    nonlocal unresolved
                    name = match.group(1)
                    resolved = (
                        _binding(name, tokens, source, before, seen, budget)
                        if _IDENTIFIER.fullmatch(name)
                        else None
                    )
                    if resolved is None:
                        unresolved = True
                        return ""
                    return resolved

                value = re.sub(r"\$\{([^{}]+)\}", replace, value)
                if unresolved or "${" in value:
                    return None
        elif _IDENTIFIER.fullmatch(token.value):
            value = _binding(token.value, tokens, source, before, seen, budget)
        else:
            return None
        if value is None:
            return None
        values.append(value)
        if sum(map(len, values)) > _MAX_OUTPUT:
            return None
        expect_term = False
    return None if expect_term else "".join(values)
