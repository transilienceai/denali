"""Offline PR evidence gate; never generates, enables or authorizes capabilities."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

RECORD_PREFIX = "docs/platform/changes/"
FIELDS = {
    "version",
    "product",
    "change",
    "reason",
    "capabilities",
    "contract_files",
    "documentation_files",
    "test_files",
    "cli",
    "gateway",
}
EVIDENCE_FIELDS = {"contract_files", "documentation_files", "test_files"}


def strict_json(raw: str) -> object:
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique_pairs)


def changed_paths(base: str) -> set[str]:
    raw = subprocess.check_output(["git", "diff", "--name-only", "-z", base + "...HEAD"])
    return {name.decode("utf-8", errors="surrogateescape") for name in raw.split(b"\0") if name}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def reason(value: object) -> bool:
    return isinstance(value, str) and 20 <= len(value.strip()) <= 4000


def paths(root: Path, value: object, label: str) -> list[str]:
    require(isinstance(value, list), f"{label} must be a list")
    require(len(value) <= 100, f"{label} is too large")
    result = []
    for name in value:
        require(isinstance(name, str) and 0 < len(name) <= 500, f"invalid {label} path")
        require(not name.startswith("/") and "\\" not in name, f"invalid {label} path")
        require(
            all(part not in ("", ".", "..") for part in name.split("/")), f"invalid {label} path"
        )
        require(
            not any(part.startswith(".env") for part in name.split("/")),
            "credentials are not evidence",
        )
        path = root / name
        require(not path.is_symlink() and path.is_file(), f"{label} evidence file is missing")
        require(path.resolve().is_relative_to(root.resolve()), "evidence escapes the repository")
        result.append(name)
    require(len(set(result)) == len(result), f"duplicate {label} paths")
    return result


def validate_record(
    root: Path, data: object, product: str, changed: set[str], evidence_paths: dict
) -> None:
    require(isinstance(data, dict) and set(data) == FIELDS, "record fields do not match v1")
    require(type(data["version"]) is int and data["version"] == 1, "unsupported record version")
    require(data["product"] == product, "record product does not match this repository")
    require(
        data["change"] in ("add", "update", "no_external_change"), "invalid change classification"
    )
    require(reason(data["reason"]), "explain the capability impact with a meaningful reason")
    capabilities = data["capabilities"]
    require(isinstance(capabilities, list) and len(capabilities) <= 200, "invalid capability list")
    names = set()
    for capability in capabilities:
        require(
            isinstance(capability, dict) and set(capability) == {"name", "kind", "scopes"},
            "capability fields do not match v1",
        )
        name = capability["name"]
        require(
            isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_-]{1,100}", name) is not None,
            "invalid capability name",
        )
        require(name not in names, "duplicate capability name")
        names.add(name)
        require(
            capability["kind"]
            in ("read", "write", "authenticated_handoff", "not_externally_exposed"),
            "invalid capability classification",
        )
        scopes = capability["scopes"]
        require(isinstance(scopes, list) and len(scopes) <= 20, "invalid permission list")
        require(
            all(
                isinstance(scope, str) and re.fullmatch(r"[a-z][a-z0-9_:-]{1,100}", scope)
                for scope in scopes
            ),
            "invalid permission name",
        )
        require(len(set(scopes)) == len(scopes), "duplicate permissions")
        if capability["kind"] != "not_externally_exposed":
            require(bool(scopes), "external capabilities need explicit permissions")
    evidence = {label: paths(root, data[label], label) for label in sorted(EVIDENCE_FIELDS)}
    all_evidence = [name for names in evidence.values() for name in names]
    require(len(set(all_evidence)) == len(all_evidence), "evidence roles must use distinct files")
    for label, names in evidence.items():
        for name in names:
            require(not name.startswith(RECORD_PREFIX), "delivery records are not evidence")
            require(
                any(fnmatch.fnmatchcase(name, pattern) for pattern in evidence_paths[label]),
                f"{label} path is outside its policy-owned evidence category",
            )
    for label, choices in (
        ("cli", {"generic_tools", "release_required", "none"}),
        ("gateway", {"adapter_update", "none"}),
    ):
        decision = data[label]
        require(
            isinstance(decision, dict) and set(decision) == {"impact", "reason"},
            f"invalid {label} decision",
        )
        require(
            decision["impact"] in choices and reason(decision["reason"]),
            f"explain the {label} compatibility decision",
        )
    if data["change"] != "no_external_change":
        require(bool(capabilities), "changed external features must list their capabilities")
        for label, names in evidence.items():
            require(
                bool(names) and all(name in changed for name in names),
                f"{label} must name files changed in this PR",
            )
    else:
        require(not capabilities, "no_external_change must not declare changed capabilities")
        require(not all_evidence, "no_external_change must use empty evidence arrays")
        require(
            data["cli"]["impact"] == "none" and data["gateway"]["impact"] == "none",
            "no_external_change cannot require a gateway or CLI update",
        )


def check(root: Path, config: object, changed: set[str]) -> int:
    require(
        isinstance(config, dict)
        and set(config) == {"version", "product", "watched_paths", "evidence_paths"},
        "policy fields do not match v1",
    )
    require(type(config["version"]) is int and config["version"] == 1, "unsupported policy version")
    product = config["product"]
    require(
        isinstance(product, str) and re.fullmatch(r"[a-z][a-z0-9_-]{1,60}", product) is not None,
        "invalid product",
    )
    patterns = config["watched_paths"]
    require(isinstance(patterns, list) and 0 < len(patterns) <= 100, "invalid watched paths")
    require(
        all(
            isinstance(p, str) and p and not p.startswith("/") and ".." not in p.split("/")
            for p in patterns
        ),
        "invalid watched path",
    )
    evidence_paths = config["evidence_paths"]
    require(
        isinstance(evidence_paths, dict) and set(evidence_paths) == EVIDENCE_FIELDS,
        "invalid evidence categories",
    )
    for choices in evidence_paths.values():
        require(
            isinstance(choices, list) and 0 < len(choices) <= 100, "invalid evidence path patterns"
        )
        require(
            all(
                isinstance(p, str) and p and not p.startswith("/") and ".." not in p.split("/")
                for p in choices
            ),
            "invalid evidence path pattern",
        )
    relevant = {name for name in changed if any(fnmatch.fnmatchcase(name, p) for p in patterns)}
    records = sorted(
        name for name in changed if name.startswith(RECORD_PREFIX) and name.endswith(".json")
    )
    if relevant:
        require(
            bool(records),
            "runtime/contract changes require a new or updated docs/platform/changes/*.json",
        )
    for name in records:
        record_path = paths(root, [name], "delivery record")[0]
        require((root / record_path).stat().st_size <= 65536, "delivery record is too large")
        validate_record(
            root, strict_json((root / record_path).read_text()), product, changed, evidence_paths
        )
    return len(records)


def self_test() -> None:
    import tempfile
    import unittest

    class GateTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory()
            self.addCleanup(self.temp.cleanup)
            self.root = Path(self.temp.name)
            self.evidence_paths = {
                "contract_files": ["contracts/**"],
                "documentation_files": ["docs/**"],
                "test_files": ["tests/**"],
            }
            self.config = {
                "version": 1,
                "product": "test",
                "watched_paths": ["src/**"],
                "evidence_paths": self.evidence_paths,
            }
            self.record = {
                "version": 1,
                "product": "test",
                "change": "update",
                "reason": "Expose the reviewed product capability through the shared gateway.",
                "capabilities": [
                    {"name": "test_summary", "kind": "read", "scopes": ["results:read"]}
                ],
                "contract_files": ["contracts/contract.json"],
                "documentation_files": ["docs/guide.md"],
                "test_files": ["tests/test_case.py"],
                "cli": {
                    "impact": "generic_tools",
                    "reason": "Existing supported consent permits live tool discovery.",
                },
                "gateway": {
                    "impact": "adapter_update",
                    "reason": "A reviewed fixed product receiver is registered in Platform.",
                },
            }
            for name in ("contracts/contract.json", "docs/guide.md", "tests/test_case.py"):
                (self.root / name).parent.mkdir(parents=True, exist_ok=True)
                (self.root / name).touch()
            self.changed = {
                "src/service.py",
                "contracts/contract.json",
                "docs/guide.md",
                "tests/test_case.py",
            }

        def validate(self, changed=None, product="test"):
            validate_record(
                self.root,
                self.record,
                product,
                self.changed if changed is None else changed,
                self.evidence_paths,
            )

        def test_runtime_without_receipt_fails(self):
            with self.assertRaises(ValueError):
                check(self.root, self.config, self.changed)

        def test_docs_only_does_not_need_receipt(self):
            self.assertEqual(check(self.root, self.config, {"guide.md"}), 0)

        def test_changed_contract_docs_tests_accept(self):
            self.validate()

        def test_stale_evidence_fails(self):
            with self.assertRaises(ValueError):
                self.validate({"src/service.py"})

        def test_missing_evidence_fails(self):
            self.record["test_files"] = ["missing.py"]
            with self.assertRaises(ValueError):
                self.validate()

        def test_traversal_fails(self):
            self.record["contract_files"] = ["../contract.json"]
            with self.assertRaises(ValueError):
                self.validate()

        def test_unknown_fields_fail(self):
            self.record["auto_enable"] = True
            with self.assertRaises(ValueError):
                self.validate()

        def test_wrong_product_fails(self):
            with self.assertRaises(ValueError):
                self.validate(product="another")

        def test_internal_reason_accepts_without_exposure(self):
            self.record.update(
                change="no_external_change",
                capabilities=[],
                contract_files=[],
                documentation_files=[],
                test_files=[],
            )
            self.record["cli"]["impact"] = "none"
            self.record["gateway"]["impact"] = "none"
            self.validate({"src/internal.py"})

        def test_exposed_scope_required(self):
            self.record["capabilities"][0]["scopes"] = []
            with self.assertRaises(ValueError):
                self.validate()

        def test_no_external_cannot_list_changed_capabilities(self):
            self.record["change"] = "no_external_change"
            with self.assertRaises(ValueError):
                self.validate()

        def test_shared_evidence_fails(self):
            for label in EVIDENCE_FIELDS:
                self.record[label] = ["docs/guide.md"]
            with self.assertRaises(ValueError):
                self.validate()

        def test_wrong_evidence_category_fails(self):
            self.record["test_files"] = ["README.md"]
            (self.root / "README.md").touch()
            self.changed.add("README.md")
            with self.assertRaises(ValueError):
                self.validate()

        def test_record_cannot_be_evidence(self):
            record = RECORD_PREFIX + "feature.json"
            (self.root / record).parent.mkdir(parents=True)
            (self.root / record).touch()
            self.record["documentation_files"] = [record]
            self.changed.add(record)
            with self.assertRaises(ValueError):
                self.validate()

        def test_internal_stale_evidence_fails(self):
            self.record.update(change="no_external_change", capabilities=[])
            self.record["cli"]["impact"] = "none"
            self.record["gateway"]["impact"] = "none"
            with self.assertRaises(ValueError):
                self.validate()

        def test_duplicate_json_keys_fail(self):
            with self.assertRaises(ValueError):
                strict_json('{"version": 1, "version": 2}')

        def test_unicode_git_names_are_not_quoted(self):
            from unittest.mock import patch

            with patch("subprocess.check_output", return_value="src/café.py\0".encode()):
                changed = changed_paths("a" * 40)
            self.assertEqual(changed, {"src/café.py"})
            with self.assertRaises(ValueError):
                check(self.root, self.config, changed)

    result = unittest.TextTestRunner().run(
        unittest.defaultTestLoader.loadTestsFromTestCase(GateTests)
    )
    if not result.wasSuccessful():
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="immutable PR base commit")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        require(
            isinstance(args.base, str) and re.fullmatch(r"[0-9a-f]{40,64}", args.base) is not None,
            "--base must be a full immutable Git commit",
        )
        root = Path(
            subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
        )
        subprocess.run(
            ["git", "rev-parse", "--verify", args.base + "^{commit}"],
            check=True,
            capture_output=True,
        )
        changed = changed_paths(args.base)
        count = check(
            root, strict_json((root / "docs/platform/delivery-policy.json").read_text()), changed
        )
        print(
            f"Platform delivery evidence valid ({count} changed records). "
            "No capability was enabled."
        )
        return 0
    except (ValueError, TypeError, OSError, json.JSONDecodeError, subprocess.CalledProcessError):
        print(
            "Platform delivery check failed. Run --self-test, then review the v1 policy, "
            "changed delivery record and contract/docs/test evidence.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
