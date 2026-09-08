"""Harness replay. Owns proof.replay.passed and done → needs_review."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

from triage.config import CONFIG, REPO_ROOT
from triage.db import init_schema, session
from triage.seeds import worktree_for
from triage.status import TransitionConflict, apply_transition, cas_status

_SCHEMA_PATH = REPO_ROOT / "data" / "verdict.schema.json"
_REPLAY_TIMEOUT_S = 90
_TP_PREFIX = "true_positive"


def alias_poc_to_proof(verdict: dict) -> dict:
    proof = verdict.get("proof")
    if isinstance(proof, dict):
        return verdict
    poc = verdict.get("poc")
    if not isinstance(poc, dict):
        return verdict
    verdict["proof"] = {
        "kind": "harness",
        "artifact_uri": poc.get("path"),
        "replay": {
            "command": poc.get("command"),
            "exit_code": poc.get("exit_code"),
        },
    }
    return verdict


def strip_replay_passed(verdict: dict) -> dict:
    proof = verdict.get("proof")
    if isinstance(proof, dict):
        replay = proof.get("replay")
        if isinstance(replay, dict):
            replay.pop("passed", None)
    return verdict


def _validator() -> Draft202012Validator:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _load_envelope(raw: str | None) -> dict:
    if not raw:
        raise ValueError("finding has no verdict_json")
    envelope = json.loads(raw)
    if "consolidated" not in envelope:
        raise ValueError("verdict_json missing consolidated")
    return envelope


def _row_status(conn, finding_id: str):
    row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if row is None:
        raise ValueError(f"finding not found: {finding_id}")
    return row


def _run_harness(command: str, worktree: Path) -> subprocess.CompletedProcess:
    # Host subprocess of the cited command is the replay. argv allowlist
    # and a sandbox are a later process; sanitizer cites stay advisory.
    argv = shlex.split(command)
    if not argv:
        raise ValueError("proof.replay.command is empty")
    if Path(argv[0]).name in {"python", "python3"}:
        argv[0] = sys.executable
    return subprocess.run(
        argv,
        cwd=worktree,
        capture_output=True,
        text=True,
        timeout=_REPLAY_TIMEOUT_S,
        check=False,
        stdin=subprocess.DEVNULL,
    )


def _sanitizer_ok(worktree: Path, sanitizers: list) -> tuple[bool, list[str]]:
    misses: list[str] = []
    for item in sanitizers:
        rel = item["file"]
        line_no = int(item["line"])
        needle = item["function"]
        path = worktree / rel
        if not path.is_file():
            misses.append(f"{rel}:{line_no} missing file")
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line_no < 1 or line_no > len(lines):
            misses.append(f"{rel}:{line_no} out of range")
            continue
        if needle not in lines[line_no - 1]:
            misses.append(f"{rel}:{line_no} {needle!r} not on line")
    return (not misses, misses)


def verify_finding(
    finding_id: str,
    db_path: Path | str,
    *,
    worktree: Path | str | None = None,
) -> dict:
    with session(db_path) as conn:
        row = _row_status(conn, finding_id)
        if row["status"] != "verifying":
            raise ValueError(f"finding {finding_id} is {row['status']}, want verifying")
        envelope = _load_envelope(row["verdict_json"])
        tree = worktree_for(row, Path(worktree) if worktree is not None else None)

    consolidated = alias_poc_to_proof(envelope["consolidated"])
    errors = [e.message for e in _validator().iter_errors(consolidated)]
    replay_meta: dict = {"command": None, "expected_exit": None, "actual_exit": None, "passed": False}
    sanitizer_ok = True
    sanitizer_misses: list[str] = []

    if errors:
        result = {
            "schema_ok": False,
            "schema_errors": errors,
            "replay": replay_meta,
            "sanitizer_ok": False,
        }
        with session(db_path) as conn:
            nxt = apply_transition("verifying", "error")
            cur = conn.execute(
                """
                UPDATE findings
                   SET verifier_json = ?, status = ?
                 WHERE id = ? AND status = 'verifying'
                """,
                (json.dumps(result), nxt, finding_id),
            )
            if cur.rowcount == 0:
                raise TransitionConflict(finding_id, "verifying")
        return result

    proof = consolidated.get("proof") if isinstance(consolidated.get("proof"), dict) else {}
    replay = proof.get("replay") if isinstance(proof.get("replay"), dict) else {}
    command = replay.get("command")
    expected = replay.get("exit_code")
    kind = proof.get("kind")
    replay_meta["command"] = command
    replay_meta["expected_exit"] = expected
    replay_meta["kind"] = kind
    passed = False
    if kind != "harness":
        replay_meta["error"] = "proof.kind is not harness"
    elif command and expected is not None:
        try:
            proc = _run_harness(str(command), tree)
            replay_meta["actual_exit"] = proc.returncode
            passed = proc.returncode == int(expected)
        except subprocess.TimeoutExpired:
            replay_meta["actual_exit"] = None
            replay_meta["timeout"] = True
            passed = False
        except (ValueError, OSError) as e:
            replay_meta["error"] = str(e)
            passed = False

    sanitizers = consolidated.get("sanitizers_in_path") or []
    if isinstance(sanitizers, list) and sanitizers:
        sanitizer_ok, sanitizer_misses = _sanitizer_ok(tree, sanitizers)

    replay_meta["passed"] = passed
    if isinstance(consolidated.get("proof"), dict):
        consolidated["proof"].setdefault("replay", {})
        consolidated["proof"]["replay"]["passed"] = passed
        if command:
            consolidated["proof"]["replay"]["command"] = command
        if expected is not None:
            consolidated["proof"]["replay"]["exit_code"] = expected
        consolidated["proof"]["replay"].setdefault("log_uri", None)

    envelope["consolidated"] = consolidated
    result = {
        "schema_ok": True,
        "replay": replay_meta,
        "sanitizer_ok": sanitizer_ok,
        "sanitizer_misses": sanitizer_misses,
    }

    with session(db_path) as conn:
        nxt = apply_transition("verifying", "done")
        cur = conn.execute(
            """
            UPDATE findings
               SET verdict_json = ?, verifier_json = ?, status = ?
             WHERE id = ? AND status = 'verifying'
            """,
            (
                json.dumps(envelope, ensure_ascii=False),
                json.dumps(result),
                nxt,
                finding_id,
            ),
        )
        if cur.rowcount == 0:
            raise TransitionConflict(finding_id, "verifying")
        verdict = consolidated.get("verdict") or ""
        if passed and isinstance(verdict, str) and verdict.startswith(_TP_PREFIX):
            cas_status(conn, finding_id, "done", "needs_review")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage.verifier")
    parser.add_argument("--db", default=str(CONFIG.db_path))
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--workdir")
    args = parser.parse_args(argv)
    init_schema(args.db)
    try:
        verify_finding(
            args.finding_id,
            args.db,
            worktree=Path(args.workdir) if args.workdir else None,
        )
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as e:
        print(e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
