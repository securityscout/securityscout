"""Tests for the verdict JSON schema we ship in data/verdict.schema.json.

These verify the schema is a valid JSON Schema 2020-12 and that it enforces
the contracts the orchestrator and verifier rely on (TP requires PoC, FP
requires blocker, audit_trail.files_read non-empty, confidence in [0, 1]).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "data" / "verdict.schema.json"


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _base_verdict() -> dict:
    """Minimal-valid verdict used as a starting point for negative tests."""
    return {
        "finding_id": "test-finding-001",
        "verdict": "true_positive",
        "confidence": 0.9,
        "actual_sink_location": "src/foo.java:42",
        "vuln_class": "CWE-918",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L",
        "taint_trace": [
            {"step": "source", "file": "src/Controller.java", "line": 10, "note": "user-supplied URL"},
            {"step": "sink", "file": "src/foo.java", "line": 42, "note": "HttpGet(url) executes"},
        ],
        "sanitizers_in_path": [],
        "poc": {
            "path": "poc/test-finding-001/",
            "command": "cd poc/test-finding-001 && mvn -q test",
            "exit_code": 0,
            "evidence_excerpt": "Tests run: 4, Failures: 0, Errors: 0",
        },
        "audit_trail": {
            "files_read": ["src/foo.java:1-200"],
            "commands_run": ["mvn -q test"],
            "tool_call_count": 12,
            "wall_time_seconds": 87,
        },
        "agent_meta": {
            "model": "claude-opus-4-7-thinking-xhigh",
            "posture": "argue_tp",
            "pass_number": 1,
        },
    }


def _python_tp_verdict() -> dict:
    """A second TP shape with a Python target + pytest PoC — proves the schema
    is language-agnostic.
    """
    return {
        "finding_id": "PT-PHP-API-001",
        "verdict": "true_positive",
        "confidence": 0.85,
        "actual_sink_location": "app/routes/users.py:73",
        "vuln_class": "CWE-89",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "taint_trace": [
            {"step": "source", "file": "app/routes/users.py", "line": 51,
             "note": "request.args['id'] read without validation"},
            {"step": "sink", "file": "app/routes/users.py", "line": 73,
             "note": "f-string interpolated into raw SQL passed to cursor.execute"},
        ],
        "sanitizers_in_path": [],
        "poc": {
            "path": "poc/PT-PHP-API-001/",
            "command": "cd poc/PT-PHP-API-001 && pytest -q",
            "exit_code": 0,
            "evidence_excerpt": "1 passed in 0.41s — payload `' OR 1=1 --` returned all users",
        },
        "audit_trail": {
            "files_read": ["app/routes/users.py:1-120"],
            "commands_run": ["pytest -q"],
            "tool_call_count": 9,
            "wall_time_seconds": 52,
        },
        "agent_meta": {
            "model": "claude-4.6-opus-high-thinking",
            "posture": "argue_fp",
            "pass_number": 2,
        },
    }


def _node_fp_verdict() -> dict:
    """FP verdict against a Node/Express target — proves polyglot blocker shape."""
    return {
        "finding_id": "TRACKING-FRONT-001",
        "verdict": "false_positive",
        "confidence": 0.92,
        "actual_sink_location": "src/api/profile.ts:128",
        "vuln_class": "CWE-79",
        "cvss_vector": None,
        "taint_trace": [
            {"step": "source", "file": "src/api/profile.ts", "line": 110,
             "note": "req.query.name flows toward template render"},
            {"step": "sanitizer", "file": "src/api/profile.ts", "line": 119,
             "note": "DOMPurify.sanitize() applied before render"},
            {"step": "sink", "file": "src/api/profile.ts", "line": 128,
             "note": "rendered into ReactDOMServer.renderToString"},
        ],
        "sanitizers_in_path": [
            {"file": "src/api/profile.ts", "line": 119, "function": "DOMPurify.sanitize",
             "applied_to": "name", "sufficient_for_class": True,
             "reason": "DOMPurify with default config strips all <script>/<iframe>/event-handlers; rendered into JSX which double-escapes."},
        ],
        "poc": None,
        "blocker": {
            "file": "src/api/profile.ts",
            "line": 119,
            "construct": "DOMPurify.sanitize(name, { USE_PROFILES: { html: true } })",
            "reasoning": "User input passes through DOMPurify v3 with the html profile before any rendering. JSX additionally HTML-escapes when interpolated as text. Bypasses considered: mXSS (DOMPurify handles); SVG namespace (sanitized); data: URLs (sanitized). No realistic bypass.",
        },
        "audit_trail": {
            "files_read": ["src/api/profile.ts:90-150", "package.json:1-60"],
            "commands_run": ["npm ls dompurify"],
            "tool_call_count": 7,
            "wall_time_seconds": 38,
        },
        "agent_meta": {
            "model": "claude-opus-4-7-thinking-xhigh",
            "posture": "argue_fp",
            "pass_number": 1,
        },
    }


def test_schema_is_valid_draft_2020_12(schema: dict) -> None:
    Draft202012Validator.check_schema(schema)


def test_valid_tp_verdict_passes(schema: dict) -> None:
    Draft202012Validator(schema).validate(_base_verdict())


def test_tp_requires_poc(schema: dict) -> None:
    bad = _base_verdict()
    bad["poc"] = None
    errors = list(Draft202012Validator(schema).iter_errors(bad))
    assert errors, "TP verdict with null poc should fail validation"


def test_fp_requires_blocker(schema: dict) -> None:
    bad = _base_verdict()
    bad["verdict"] = "false_positive"
    bad["poc"] = None
    bad["cvss_vector"] = None
    errors = list(Draft202012Validator(schema).iter_errors(bad))
    assert errors, "FP verdict without blocker should fail validation"


def test_fp_with_blocker_passes(schema: dict) -> None:
    good = _base_verdict()
    good["verdict"] = "false_positive"
    good["poc"] = None
    good["cvss_vector"] = None
    good["blocker"] = {
        "file": "src/UrlUtils.java",
        "line": 68,
        "construct": "UrlUtils.validateUrlSafe(url)",
        "reasoning": "all 8 callers gate on validateUrlSafe before fetch (audited the call sites)",
    }
    Draft202012Validator(schema).validate(good)


def test_audit_trail_must_be_non_empty(schema: dict) -> None:
    bad = _base_verdict()
    bad["audit_trail"]["files_read"] = []
    errors = list(Draft202012Validator(schema).iter_errors(bad))
    assert errors, "Empty files_read should fail (the agent reasoned from memory)"


def test_confidence_range_enforced(schema: dict) -> None:
    bad = _base_verdict()
    bad["confidence"] = 1.5
    errors = list(Draft202012Validator(schema).iter_errors(bad))
    assert errors
    bad["confidence"] = -0.1
    errors = list(Draft202012Validator(schema).iter_errors(bad))
    assert errors


def test_indeterminate_verdict_does_not_require_poc(schema: dict) -> None:
    good = _base_verdict()
    good["verdict"] = "indeterminate"
    good["confidence"] = 0.3
    good["poc"] = None
    good["cvss_vector"] = None
    Draft202012Validator(schema).validate(good)


def test_python_pytest_tp_passes(schema: dict) -> None:
    """A TP verdict with a Python + pytest PoC must validate identically to Java."""
    Draft202012Validator(schema).validate(_python_tp_verdict())


def test_node_fp_with_dompurify_blocker_passes(schema: dict) -> None:
    """An FP verdict against a Node/TS target with a DOMPurify blocker must validate."""
    Draft202012Validator(schema).validate(_node_fp_verdict())


def _harness_proof() -> dict:
    return {
        "kind": "harness",
        "artifact_uri": "poc/test-finding-001/",
        "artifact_sha256": "ab" * 32,
        "replay": {
            "command": "cd poc/test-finding-001 && mvn -q test",
            "exit_code": 0,
        },
    }


def test_tp_requires_proof_poc_only_fixture_still_validates(schema: dict) -> None:
    validator = Draft202012Validator(schema)

    proof_only = _base_verdict()
    del proof_only["poc"]
    proof_only["proof"] = _harness_proof()
    errors = list(validator.iter_errors(proof_only))
    assert not errors, "TP with proof and no poc should validate"

    neither = _base_verdict()
    neither["poc"] = None
    errors = list(validator.iter_errors(neither))
    assert errors, "TP with neither proof nor poc should fail"

    validator.validate(_base_verdict())
