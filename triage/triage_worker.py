"""Two-pass triage worker. Critic is not the TP gate."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from triage.config import CONFIG, REPO_ROOT
from triage.db import init_schema, session
from triage.model_spawn import spawn as spawn_model
from triage.recon import load_recon
from triage.seeds import worktree_for
from triage.status import TransitionConflict, apply_transition, cas_status
from triage.verifier import alias_poc_to_proof, strip_replay_passed

_ARGUE_TP = REPO_ROOT / "prompts" / "triage-argue-tp.prompt.md"
_ARGUE_FP = REPO_ROOT / "prompts" / "triage-argue-fp.prompt.md"


@dataclass
class AgentContext:
    finding: dict
    posture: str
    model: str
    recon: dict
    worktree: Path
    prompt: str


AgentFn = Callable[[AgentContext], dict]


def _row_dict(row) -> dict:
    return {k: row[k] for k in row.keys()}


def _anchor(row: dict, worktree: Path) -> bool:
    path = worktree / str(row["file"])
    if not path.is_file():
        return False
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    line = int(row["line"])
    if line < 1 or line > len(lines):
        return False
    return bool(lines[line - 1].strip())


def _render_prompt(template: Path, row: dict, recon: dict, worktree: Path) -> str:
    text = template.read_text(encoding="utf-8")
    replacements = {
        "{{FINDING_ID}}": str(row["id"]),
        "{{REPO_LOCAL}}": str(worktree),
        "{{SHA}}": str(row["sha"]),
        "{{FILE}}": str(row["file"]),
        "{{LINE}}": str(row["line"]),
        "{{RULE_ID}}": str(row["rule_id"]),
        "{{SEVERITY}}": str(row["severity"] or ""),
        "{{DESCRIPTION}}": str(row["description"] or ""),
        "{{SCANNER_URL}}": str(row["scanner_url"] or ""),
        "{{RECON_JSON}}": json.dumps(recon, ensure_ascii=False),
    }
    for token, value in replacements.items():
        text = text.replace(token, value)
    return text


def _prepare_verdict(raw: dict, finding_id: str) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("agent spawn did not return an object")
    verdict = copy.deepcopy(raw)
    verdict["finding_id"] = finding_id
    alias_poc_to_proof(verdict)
    strip_replay_passed(verdict)
    return verdict


def _has_proof(verdict: dict) -> bool:
    proof = verdict.get("proof")
    if not isinstance(proof, dict):
        return False
    replay = proof.get("replay")
    return isinstance(replay, dict) and bool(replay.get("command"))


def consolidate(pass1: dict, pass2: dict) -> dict:
    if pass1.get("verdict") == pass2.get("verdict"):
        p1, p2 = _has_proof(pass1), _has_proof(pass2)
        if p2 and not p1:
            winner = pass2
        elif p1 and not p2:
            winner = pass1
        else:
            winner = pass2 if pass2.get("verdict") == "false_positive" else pass1
        return copy.deepcopy(winner)
    if _has_proof(pass1) and not _has_proof(pass2):
        return copy.deepcopy(pass1)
    if _has_proof(pass2):
        return copy.deepcopy(pass2)
    if isinstance(pass2.get("blocker"), dict):
        return copy.deepcopy(pass2)
    out = copy.deepcopy(pass2)
    out["verdict"] = "indeterminate"
    return out


def _default_spawn(ctx: AgentContext) -> dict:
    return spawn_model(ctx)


def _write_pass(verdicts_dir: Path, finding_id: str, pass_no: int, verdict: dict) -> None:
    verdicts_dir.mkdir(parents=True, exist_ok=True)
    path = verdicts_dir / f"{finding_id}-pass{pass_no}.json"
    path.write_text(json.dumps(verdict, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _run_passes(
    finding_id: str,
    db_path: Path | str,
    *,
    finding: dict,
    tree: Path,
    runner: AgentFn,
    recon: dict | None,
    out_dir: Path,
) -> None:
    if not _anchor(finding, tree):
        with session(db_path) as conn:
            cas_status(conn, finding_id, "triaging", "stale")
        return

    recon_doc = recon if recon is not None else load_recon(db_path, finding["repo_url"], finding["sha"])
    if recon_doc is None:
        recon_doc = {}

    ctx1 = AgentContext(
        finding=finding,
        posture="argue_tp",
        model=CONFIG.model_pass1,
        recon=recon_doc,
        worktree=tree,
        prompt=_render_prompt(_ARGUE_TP, finding, recon_doc, tree),
    )
    pass1 = _prepare_verdict(runner(ctx1), finding_id)
    pass1.setdefault("agent_meta", {})
    pass1["agent_meta"]["posture"] = "argue_tp"
    pass1["agent_meta"]["pass_number"] = 1
    _write_pass(out_dir, finding_id, 1, pass1)

    ctx2 = AgentContext(
        finding=finding,
        posture="argue_fp",
        model=CONFIG.model_pass2,
        recon=recon_doc,
        worktree=tree,
        prompt=_render_prompt(_ARGUE_FP, finding, recon_doc, tree),
    )
    pass2 = _prepare_verdict(runner(ctx2), finding_id)
    pass2.setdefault("agent_meta", {})
    pass2["agent_meta"]["posture"] = "argue_fp"
    pass2["agent_meta"]["pass_number"] = 2
    _write_pass(out_dir, finding_id, 2, pass2)

    consolidated = _prepare_verdict(consolidate(pass1, pass2), finding_id)
    envelope = {"pass1": pass1, "pass2": pass2, "consolidated": consolidated}
    with session(db_path) as conn:
        nxt = apply_transition("triaging", "verifying")
        cur = conn.execute(
            """
            UPDATE findings
               SET verdict_json = ?, confidence = ?, status = ?
             WHERE id = ? AND status = 'triaging'
            """,
            (
                json.dumps(envelope, ensure_ascii=False),
                consolidated.get("confidence"),
                nxt,
                finding_id,
            ),
        )
        if cur.rowcount == 0:
            raise TransitionConflict(finding_id, "triaging")


def triage_finding(
    finding_id: str,
    db_path: Path | str,
    *,
    worktree: Path | str | None = None,
    spawn: AgentFn | None = None,
    recon: dict | None = None,
    verdicts_dir: Path | str | None = None,
) -> None:
    runner = spawn or _default_spawn
    out_dir = Path(verdicts_dir) if verdicts_dir is not None else REPO_ROOT / "verdicts"

    with session(db_path) as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if row is None:
            raise ValueError(f"finding not found: {finding_id}")
        if row["status"] != "queued":
            raise ValueError(f"finding {finding_id} is {row['status']}, want queued")
        finding = _row_dict(row)
        tree = worktree_for(row, Path(worktree) if worktree is not None else None)
        cas_status(conn, finding_id, row["status"], "triaging")
        conn.execute("UPDATE findings SET attempts = attempts + 1 WHERE id = ?", (finding_id,))

    try:
        _run_passes(
            finding_id,
            db_path,
            finding=finding,
            tree=tree,
            runner=runner,
            recon=recon,
            out_dir=out_dir,
        )
    except Exception:  # noqa: BLE001
        with session(db_path) as conn:
            row = conn.execute(
                "SELECT status FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if row is not None and row["status"] == "triaging":
                cas_status(conn, finding_id, "triaging", "error")
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage.triage_worker")
    parser.add_argument("--db", default=str(CONFIG.db_path))
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--workdir")
    args = parser.parse_args(argv)
    init_schema(args.db)
    try:
        triage_finding(
            args.finding_id,
            args.db,
            worktree=Path(args.workdir) if args.workdir else None,
        )
    except Exception as e:  # noqa: BLE001
        print(e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
