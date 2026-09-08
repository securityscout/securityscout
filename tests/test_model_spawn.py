"""Production model spawn: Anthropic Messages, OpenAI Responses, cursor."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from triage import db
from triage.config import CONFIG, REPO_ROOT
from tests.test_triage_mode import _fp_verdict, _recon_doc, _tp_verdict


def _ctx(prompt: str = '{"ping": true}', model: str = "test-model") -> SimpleNamespace:
    return SimpleNamespace(prompt=prompt, model=model, worktree=REPO_ROOT)


def _prompt_from_kwargs(kwargs: dict) -> str:
    if "messages" in kwargs:
        return str(kwargs["messages"][0]["content"])
    return str(kwargs.get("input", ""))


def _payload_for_prompt(prompt: str) -> dict:
    # Recon prompts include the fixture path (`sqli-app`); rule ids do not.
    if "python.sql.injection" in prompt:
        return _tp_verdict("spawn-test")
    if "python.xss.template" in prompt:
        return _fp_verdict("spawn-test")
    return _recon_doc()


class _TextBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _AnthropicMessage:
    def __init__(self, text: str) -> None:
        self.content = [_TextBlock(text)]


class _AnthropicMessages:
    def __init__(self, calls: list[dict]) -> None:
        self.calls = calls

    def create(self, **kwargs):
        body = json.dumps(_payload_for_prompt(_prompt_from_kwargs(kwargs)))
        self.calls.append(kwargs)
        return _AnthropicMessage(body)


class _AnthropicClient:
    def __init__(self, calls: list[dict]) -> None:
        self.messages = _AnthropicMessages(calls)


class _OpenAIResponse:
    def __init__(self, text: str) -> None:
        self.output_text = text


class _OpenAIResponses:
    def __init__(self, calls: list[dict]) -> None:
        self.calls = calls

    def create(self, **kwargs):
        body = json.dumps(_payload_for_prompt(_prompt_from_kwargs(kwargs)))
        self.calls.append(kwargs)
        return _OpenAIResponse(body)


class _OpenAIClient:
    def __init__(self, calls: list[dict]) -> None:
        self.responses = _OpenAIResponses(calls)


def _run_seeded_path(tmp_path: Path) -> dict[str, object]:
    from triage import recon, seeds, triage_worker, verifier

    known = seeds.load_known()
    db_path = tmp_path / "triage.db"
    db.init_schema(db_path)
    inserted: dict[str, str] = {}
    with db.session(db_path) as conn:
        for seed in known:
            inserted[seed.expected] = seeds.insert_seed(conn, seed)

    for seed in known:
        worktree = REPO_ROOT / seed.worktree
        recon.ensure_recon(
            seed.repo_url,
            seed.sha,
            worktree,
            db_path=db_path,
            cache_dir=tmp_path / "cache",
        )
        fid = inserted[seed.expected]
        triage_worker.triage_finding(
            fid,
            db_path,
            worktree=worktree,
            verdicts_dir=tmp_path / "verdicts",
        )
        verifier.verify_finding(fid, db_path, worktree=worktree)

    with db.session(db_path) as conn:
        tp = conn.execute(
            "SELECT status, verdict_json FROM findings WHERE id = ?",
            (inserted["true_positive"],),
        ).fetchone()
        fp = conn.execute(
            "SELECT status, verdict_json FROM findings WHERE id = ?",
            (inserted["false_positive"],),
        ).fetchone()
    return {"tp": tp, "fp": fp}


def test_env_example_does_not_assign_model_slugs() -> None:
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    for key in ("TRIAGE_MODEL_PASS1", "TRIAGE_MODEL_PASS2", "TRIAGE_MODEL_RECON"):
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert not stripped.startswith(f"{key}="), key


def test_equal_pass_slugs_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    from triage.config import TriageConfig

    monkeypatch.setenv("TRIAGE_MODEL_PASS1", "same-slug")
    monkeypatch.setenv("TRIAGE_MODEL_PASS2", "same-slug")
    with pytest.raises(ValueError, match="differ"):
        TriageConfig()


def test_recon_cache_file_rejects_non_object(tmp_path: Path) -> None:
    from triage import recon

    db_path = tmp_path / "triage.db"
    db.init_schema(db_path)
    cache = tmp_path / "cache"
    cache.mkdir()
    url = "https://fixtures.securityscout.test/sqli-app"
    sha = "deadbeef"
    path = cache / f"{recon.repo_slug(url)}-{sha}.json"
    path.write_text("[1, 2]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="object"):
        recon.ensure_recon(url, sha, tmp_path, db_path=db_path, cache_dir=cache)
    assert recon.load_recon(db_path, url, sha) is None


def test_vendor_mock_keys_off_prompt_not_call_index() -> None:
    calls: list[dict] = []
    client = _AnthropicClient(calls)
    xss = "pass 2 python.xss.template tests/fixtures/triage/xss-app"
    first = client.messages.create(model="x", messages=[{"role": "user", "content": xss}])
    assert json.loads(first.content[0].text)["verdict"] == "false_positive"

    sqli = "pass 1 python.sql.injection tests/fixtures/triage/sqli-app"
    second = client.messages.create(model="x", messages=[{"role": "user", "content": sqli}])
    assert json.loads(second.content[0].text)["verdict"] == "true_positive"

    recon_prompt = "map languages and routes for this repo"
    third = client.messages.create(model="x", messages=[{"role": "user", "content": recon_prompt}])
    assert "languages" in json.loads(third.content[0].text)


def test_unset_backend_fails_clearly(monkeypatch: pytest.MonkeyPatch) -> None:
    from triage import model_spawn

    monkeypatch.delenv("TRIAGE_MODEL_BACKEND", raising=False)
    with pytest.raises(RuntimeError, match="TRIAGE_MODEL_BACKEND") as exc:
        model_spawn.spawn(_ctx())
    msg = str(exc.value)
    assert "anthropic" in msg
    assert "openai" in msg
    assert "cursor" in msg


def test_unknown_backend_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    from triage import model_spawn

    monkeypatch.setenv("TRIAGE_MODEL_BACKEND", "bedrock")
    with pytest.raises(RuntimeError, match="TRIAGE_MODEL_BACKEND"):
        model_spawn.spawn(_ctx())


def test_anthropic_missing_key_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    from triage import model_spawn

    monkeypatch.setenv("TRIAGE_MODEL_BACKEND", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        model_spawn.spawn(_ctx())


def test_openai_missing_key_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    from triage import model_spawn

    monkeypatch.setenv("TRIAGE_MODEL_BACKEND", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        model_spawn.spawn(_ctx())


def test_recon_and_worker_succeed_with_mocked_anthropic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from triage import model_spawn

    calls: list[dict] = []
    monkeypatch.setenv("TRIAGE_MODEL_BACKEND", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-real-key")
    monkeypatch.setattr(model_spawn, "_anthropic_client", lambda: _AnthropicClient(calls))

    rows = _run_seeded_path(tmp_path)
    tp_cons = json.loads(rows["tp"]["verdict_json"])["consolidated"]
    fp_cons = json.loads(rows["fp"]["verdict_json"])["consolidated"]
    assert tp_cons["verdict"] == "true_positive"
    assert tp_cons["proof"]["replay"]["passed"] is True
    assert rows["tp"]["status"] == "needs_review"
    assert fp_cons["verdict"] == "false_positive"
    assert fp_cons["proof"]["replay"]["passed"] is True
    assert rows["fp"]["status"] == "done"

    models = [c["model"] for c in calls]
    assert CONFIG.model_pass1 in models
    assert CONFIG.model_pass2 in models
    assert CONFIG.model_pass1 != CONFIG.model_pass2
    for call in calls:
        assert "tools" not in call
        assert call["model"]
        assert call["max_tokens"] == 8192


def test_recon_and_worker_succeed_with_mocked_openai(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from triage import model_spawn

    calls: list[dict] = []
    monkeypatch.setenv("TRIAGE_MODEL_BACKEND", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-real-key")
    monkeypatch.setattr(model_spawn, "_openai_client", lambda: _OpenAIClient(calls))

    rows = _run_seeded_path(tmp_path)
    tp_cons = json.loads(rows["tp"]["verdict_json"])["consolidated"]
    fp_cons = json.loads(rows["fp"]["verdict_json"])["consolidated"]
    assert tp_cons["verdict"] == "true_positive"
    assert tp_cons["proof"]["replay"]["passed"] is True
    assert rows["tp"]["status"] == "needs_review"
    assert fp_cons["verdict"] == "false_positive"
    assert fp_cons["proof"]["replay"]["passed"] is True
    assert rows["fp"]["status"] == "done"

    models = [c["model"] for c in calls]
    assert CONFIG.model_pass1 in models
    assert CONFIG.model_pass2 in models
    assert CONFIG.model_pass1 != CONFIG.model_pass2
    for call in calls:
        assert "tools" not in call
        assert call["text"] == {"format": {"type": "json_object"}}
        assert call["store"] is False
        assert "JSON" in call["instructions"]


def test_cursor_backend_still_selectable(monkeypatch: pytest.MonkeyPatch) -> None:
    from triage import model_spawn

    seen: list[dict] = []

    def fake_cursor(**kwargs):
        seen.append(kwargs)
        return {"ok": True, "backend": "cursor"}

    monkeypatch.setenv("TRIAGE_MODEL_BACKEND", "cursor")
    monkeypatch.setattr(model_spawn, "spawn_cursor_agent", fake_cursor)
    monkeypatch.setattr(
        model_spawn, "_anthropic_client", lambda: (_ for _ in ()).throw(AssertionError("anthropic"))
    )
    monkeypatch.setattr(
        model_spawn, "_openai_client", lambda: (_ for _ in ()).throw(AssertionError("openai"))
    )

    out = model_spawn.complete("ping", "composer-2.5-fast", cwd=REPO_ROOT, mode="plan")
    assert out == {"ok": True, "backend": "cursor"}
    assert seen[0]["prompt"] == "ping"
    assert seen[0]["model"] == "composer-2.5-fast"
    assert seen[0]["cwd"] == REPO_ROOT
    assert seen[0]["mode"] == "plan"
