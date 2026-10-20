"""Bounded, non-executing Python source parsing for static repository evidence.

Native grammar always wins. Legacy syntax is accepted only when a fixed set of
syntax translations produces a complete AST without moving source line numbers.
Neither customer source nor translated source is written or executed.
"""

from __future__ import annotations

import ast
import io
import sys
import time
import tokenize
import warnings
from collections.abc import Iterable, Iterator
from typing import Any

MAX_PYTHON_SOURCE_BYTES = 2_000_000
MAX_LEGACY_TOKENS = 100_000
MAX_LEGACY_NESTING = 96
LEGACY_PARSE_SECONDS = 2.0
_LEGACY_FIXERS = (
    "fix_print",
    "fix_except",
    "fix_raise",
    "fix_exec",
    "fix_numliterals",
    "fix_repr",
    "fix_ne",
)


class PythonSourceError(ValueError):
    """A stable diagnostic containing no parser messages or customer text."""

    def __init__(self, category: str, line: int = 0) -> None:
        self.category = category
        self.line = line
        super().__init__(category)


def decode_python_source(raw: bytes) -> str:
    """Honor Python's BOM/coding cookie instead of silently replacing bytes."""

    if len(raw) > MAX_PYTHON_SOURCE_BYTES:
        raise PythonSourceError("source_size_limit")
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding)
        # Python's parser uses universal newlines, including inside literals.
        return text.replace("\r\n", "\n").replace("\r", "\n")
    except (SyntaxError, UnicodeError, LookupError):
        raise PythonSourceError("invalid_source_encoding") from None
    except MemoryError:
        raise PythonSourceError("parser_complexity_limit") from None


def _native_tree(text: str, filename: str) -> ast.Module:
    # Python may include a customer source line in a SyntaxWarning. Diagnostics
    # are projected explicitly by the caller, never emitted by the interpreter.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.simplefilter("ignore", DeprecationWarning)
        return ast.parse(text, filename=filename)


def parse_python_source(text: str, *, filename: str) -> ast.Module:
    """Parse a full file; never repair an invalid block or fall back to regex."""

    if len(text) > MAX_PYTHON_SOURCE_BYTES:
        raise PythonSourceError("source_size_limit")
    try:
        return _native_tree(text, filename)
    except SyntaxError as error:
        line = error.lineno or 0
        category = (
            "invalid_indentation"
            if isinstance(error, IndentationError)
            else "invalid_or_unsupported_syntax"
        )
    except (RecursionError, MemoryError):
        raise PythonSourceError("parser_complexity_limit") from None
    except ValueError:
        raise PythonSourceError("invalid_source_text") from None

    try:
        return _legacy_tree(text, filename)
    except PythonSourceError as error:
        if error.category != "invalid_or_unsupported_syntax":
            raise PythonSourceError(error.category, line) from None
        raise PythonSourceError(category, line) from None
    except (RecursionError, MemoryError):
        raise PythonSourceError("parser_complexity_limit", line) from None


class _LegacyBudget:
    def __init__(self) -> None:
        self.deadline = time.monotonic() + LEGACY_PARSE_SECONDS

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise PythonSourceError("legacy_parser_time_limit")

    def checked(self, values: Iterable[Any]) -> Iterator[Any]:
        for value in values:
            self.check()
            yield value


def _legacy_tree(text: str, filename: str) -> ast.Module:
    budget = _LegacyBudget()
    _check_legacy_tokens(text, budget)
    try:
        # Lazy import: current Python syntax never depends on a legacy grammar.
        from fissix.refactor import RefactoringTool
    except (ImportError, OSError):
        raise PythonSourceError("legacy_parser_unavailable") from None

    class StaticSyntaxTool(RefactoringTool):
        def log_error(self, *_args: Any, **_kwargs: Any) -> None:
            # Fissix errors can contain the offending source token. Never log,
            # store, or propagate those messages, including in exception chains.
            error = sys.exception()
            if isinstance(error, PythonSourceError):
                raise error from None
            raise PythonSourceError("invalid_or_unsupported_syntax") from None

        def log_message(self, *_args: Any) -> None:
            pass

        def log_debug(self, *_args: Any) -> None:
            pass

        def traverse_by(self, fixers: Any, traversal: Iterable[Any]) -> None:
            super().traverse_by(fixers, budget.checked(traversal))

    try:
        tool = StaticSyntaxTool([f"fissix.fixes.{fixer}" for fixer in _LEGACY_FIXERS])
        # Bound traversal during both legacy grammar parsing and transformations,
        # not just after an expensive conversion. The fixed source/token/depth
        # limits also bound individual parser/fixer operations between checks.
        parse_tokens = tool.driver.parse_tokens
        tool.driver.parse_tokens = lambda tokens, debug=False: parse_tokens(
            budget.checked(tokens), debug
        )
        match_nodes = tool.BM.run
        tool.BM.run = lambda nodes: match_nodes(budget.checked(nodes))
        normalized = text if text.endswith("\n") else text + "\n"
        tree = tool.refactor_string(normalized, "<static-python-source>")
        budget.check()
        if tree is None:
            raise PythonSourceError("invalid_or_unsupported_syntax")
        translated = str(tree)
        if translated.count("\n") != normalized.count("\n"):
            # Some exception/tuple fixers insert assignments on new lines.
            # Reject those translations: evidence must point into original text.
            raise PythonSourceError("legacy_source_line_mapping_unsupported")
        parsed = _native_tree(translated, filename)
        budget.check()
        return parsed
    except PythonSourceError:
        raise
    except (SyntaxError, ValueError, TypeError):
        raise PythonSourceError("invalid_or_unsupported_syntax") from None


def _check_legacy_tokens(text: str, budget: _LegacyBudget) -> None:
    nesting = 0
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for count, token in enumerate(budget.checked(tokens), start=1):
            if count > MAX_LEGACY_TOKENS:
                raise PythonSourceError("legacy_parser_token_limit")
            if token.type == tokenize.INDENT or (
                token.type == tokenize.OP and token.string in {"(", "[", "{"}
            ):
                nesting += 1
                if nesting > MAX_LEGACY_NESTING:
                    raise PythonSourceError("legacy_parser_depth_limit")
            elif token.type == tokenize.DEDENT or (
                token.type == tokenize.OP and token.string in {")", "]", "}"}
            ):
                nesting -= 1
    except (tokenize.TokenError, IndentationError, SyntaxError):
        raise PythonSourceError("invalid_or_unsupported_syntax") from None
