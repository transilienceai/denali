from __future__ import annotations

import ast
import builtins
from pathlib import Path

import pytest

from denali.connectors import python_source
from denali.connectors.python_source import (
    MAX_PYTHON_SOURCE_BYTES,
    PythonSourceError,
    decode_python_source,
    parse_python_source,
)
from denali.connectors.repository import (
    INVENTORY_PLANE,
    MAX_SOURCE_BYTES,
    RELATIONSHIP_PLANE,
    RepositoryConnector,
)
from denali.domain import AssetKind, CoverageState


def test_native_syntax_does_not_load_or_use_legacy_parser(monkeypatch) -> None:
    def no_legacy(*_args):
        raise AssertionError("native syntax must not use legacy grammar")

    monkeypatch.setattr(python_source, "_legacy_tree", no_legacy)
    tree = parse_python_source(
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('Native')\n"
        "match server:\n"
        "    case None:\n"
        "        pass\n",
        filename="native.py",
    )
    assert isinstance(tree, ast.Module)


@pytest.mark.parametrize(
    "statement",
    [
        "print 'legacy'",
        "print >>output, 'legacy',",
        "try:\n    pass\nexcept Exception, error:\n    print error",
        "raise ValueError, 'legacy'",
        "exec 'x = 1' in globals(), locals()",
        "number = 0755",
        "number = 65535L",
        "representation = `value`",
        "different = value <> other",
    ],
)
def test_valid_legacy_syntax_parses_without_execution(statement: str) -> None:
    tree = parse_python_source(statement, filename="legacy.py")
    assert isinstance(tree, ast.Module)


def test_legacy_source_is_not_executed_or_modified(tmp_path: Path) -> None:
    sentinel = tmp_path / "must-not-exist"
    text = f"open({str(sentinel)!r}, 'w').write('never')\nprint 'legacy'\n"
    path = tmp_path / "source.py"
    path.write_text(text)
    parse_python_source(text, filename="source.py")
    assert not sentinel.exists()
    assert path.read_text() == text


def test_legacy_evidence_keeps_original_source_lines(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "print 'legacy'\n"
        "import langchain\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "server = FastMCP('Legacy')\n"
        "@server.tool(name='find_item')\n"
        "def find_item():\n"
        "    return 'ok'\n"
    )
    batch = RepositoryConnector(tmp_path, repository_name="local:legacy").collect()
    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    framework = next(item for item in batch.assets if item.asset.kind is AssetKind.AI_FRAMEWORK)
    server = next(item for item in batch.assets if item.asset.kind is AssetKind.MCP_SERVER)
    tool = next(item for item in batch.assets if item.asset.kind is AssetKind.AI_TOOL)
    assert framework.evidence.payload["line"] == 2
    assert framework.evidence.payload["snippet"] == "import langchain"
    assert server.evidence.payload["line"] == 4
    assert tool.evidence.payload["line"] == 6


def test_legacy_line_inserting_translation_remains_partial(tmp_path: Path) -> None:
    (tmp_path / "legacy.py").write_text(
        "try:\n    pass\nexcept Exception, (first, second):\n    print first\n"
    )
    batch = RepositoryConnector(tmp_path, repository_name="local:legacy").collect()
    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert "legacy_source_line_mapping_unsupported" in batch.coverage[0].detail
    assert not batch.may_withdraw(INVENTORY_PLANE)
    assert not batch.may_withdraw(RELATIONSHIP_PLANE)


@pytest.mark.parametrize(
    "text,category",
    [
        ("def unfinished(\n", "invalid_or_unsupported_syntax"),
        ("def broken():\nreturn 'invalid'\n", "invalid_indentation"),
        ("password = 'synthetic-sensitive-value' @@@\n", "invalid_or_unsupported_syntax"),
        ("value = '\x00'\n", "invalid_or_unsupported_syntax"),
    ],
)
def test_genuinely_unparseable_source_stays_partial_and_sanitized(
    tmp_path: Path, text: str, category: str, caplog, capsys
) -> None:
    (tmp_path / "broken.py").write_text(text)
    batch = RepositoryConnector(tmp_path, repository_name="local:broken").collect()
    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert category in batch.coverage[0].detail
    assert "synthetic-sensitive-value" not in batch.coverage[0].detail
    assert not caplog.text
    output = capsys.readouterr()
    assert output.out == output.err == ""


@pytest.mark.parametrize(
    "raw",
    [
        b"\xef\xbb\xbfimport langchain\n",
        b"# coding: latin-1\n# caf\xe9\nimport langchain\n",
        b"# coding: utf-8\r\nimport langchain\r\n",
    ],
)
def test_python_source_encoding_uses_language_cookie_and_bom(
    tmp_path: Path, raw: bytes
) -> None:
    (tmp_path / "encoded.py").write_bytes(raw)
    batch = RepositoryConnector(tmp_path, repository_name="local:encoded").collect()
    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    assert any(item.asset.kind is AssetKind.AI_FRAMEWORK for item in batch.assets)


@pytest.mark.parametrize("raw", [b"# coding: not-a-real-codec\n", b"name = '\xff'\n"])
def test_invalid_encoding_is_partial_not_replacement_text(tmp_path: Path, raw: bytes) -> None:
    (tmp_path / "encoded.py").write_bytes(raw)
    batch = RepositoryConnector(tmp_path, repository_name="local:encoded").collect()
    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert "invalid_source_encoding" in batch.coverage[0].detail


def test_valid_source_between_one_and_two_megabytes_is_analyzed(tmp_path: Path) -> None:
    assert MAX_SOURCE_BYTES == MAX_PYTHON_SOURCE_BYTES == 2_000_000
    (tmp_path / "large.py").write_text("#" + "x" * 1_100_000 + "\nimport langchain\n")
    batch = RepositoryConnector(tmp_path, repository_name="local:large").collect()
    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    assert any(item.asset.kind is AssetKind.AI_FRAMEWORK for item in batch.assets)


def test_source_over_existing_blob_limit_remains_explicitly_partial(tmp_path: Path) -> None:
    (tmp_path / "large.py").write_text("#" + "x" * MAX_SOURCE_BYTES)
    batch = RepositoryConnector(tmp_path, repository_name="local:large").collect()
    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert f"larger than {MAX_SOURCE_BYTES} bytes" in batch.coverage[0].detail


def test_missing_legacy_dependency_never_authorizes_complete(monkeypatch) -> None:
    original_import = builtins.__import__

    def unavailable(name, *args, **kwargs):
        if name == "fissix.refactor":
            raise ImportError("synthetic sensitive import detail")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", unavailable)
    with pytest.raises(PythonSourceError, match="^legacy_parser_unavailable$"):
        parse_python_source("print 'legacy'\n", filename="legacy.py")


@pytest.mark.parametrize("error", [MemoryError, RecursionError])
def test_native_parser_complexity_failure_is_safe(monkeypatch, error) -> None:
    def limited(*_args, **_kwargs):
        raise error("synthetic private parser detail")

    monkeypatch.setattr(python_source.ast, "parse", limited)
    with pytest.raises(PythonSourceError, match="^parser_complexity_limit$"):
        parse_python_source("x = 1\n", filename="source.py")


def test_legacy_time_budget_never_reports_complete(monkeypatch) -> None:
    ticks = iter([1.0, 10.0])
    monkeypatch.setattr(python_source.time, "monotonic", lambda: next(ticks))
    with pytest.raises(PythonSourceError, match="^legacy_parser_time_limit$"):
        parse_python_source("print 'legacy'\n", filename="legacy.py")


def test_large_invalid_source_has_bounded_legacy_token_work() -> None:
    text = "print 'legacy'\n" + "value = 1\n" * 30_000
    with pytest.raises(PythonSourceError, match="^legacy_parser_token_limit$"):
        parse_python_source(text, filename="many_tokens.py")


def test_deep_legacy_source_has_bounded_nesting_work() -> None:
    text = "print 'legacy'\nvalue = " + "(" * 200 + "0" + ")" * 200 + "\n"
    with pytest.raises(PythonSourceError, match="^legacy_parser_depth_limit$"):
        parse_python_source(text, filename="deep.py")


def test_invalid_escape_warning_does_not_print_customer_text(capsys, caplog) -> None:
    parse_python_source("value = '\\m synthetic-sensitive-value'\n", filename="source.py")
    assert not caplog.text
    output = capsys.readouterr()
    assert output.out == output.err == ""


def test_decode_helper_rejects_oversized_input() -> None:
    with pytest.raises(PythonSourceError, match="^source_size_limit$"):
        decode_python_source(b"#" * (MAX_PYTHON_SOURCE_BYTES + 1))
