"""Tests for triage/deploy.py.

Every test injects `docker` — no test spawns a real container. The one
live test is gated on TRIAGE_LIVE_DOCKER=1 and never runs in CI. The
health check inside `deploy.up` is a real loopback HTTP call, so
`test_run_job_ups_hunts_and_downs` and `test_down_runs_when_hunt_raises`
spin a real stdlib HTTP server and point the injected `docker` at its
actual port.
"""

from __future__ import annotations

import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from triage import deploy

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "deploy" / "echo-app"


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


class _FakeServer:
    """A real loopback HTTP server standing in for a container's health port."""

    def __enter__(self) -> "_FakeServer":
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _HealthHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.thread.join()


def _make_docker(port: int):
    calls: list[list[str]] = []

    def docker(argv: list[str]) -> tuple[int, str, str]:
        calls.append(argv)
        if argv[:2] == ["docker", "build"]:
            return 0, "sha256:deadbeef\n", ""
        if argv[:2] == ["docker", "run"]:
            return 0, "containeridfake123\n", ""
        if argv[:2] == ["docker", "port"]:
            return 0, f"127.0.0.1:{port}\n", ""
        if argv[:2] == ["docker", "rm"]:
            return 0, "containeridfake123\n", ""
        return 1, "", f"unexpected argv {argv}"

    docker.calls = calls  # type: ignore[attr-defined]
    return docker


def _failing_docker():
    def docker(argv: list[str]) -> tuple[int, str, str]:
        raise AssertionError(f"docker should not be called, got {argv}")

    return docker


def _failing_hunt():
    def hunt(*, db_path, url=None):
        raise AssertionError("hunt should not be called")

    return hunt


class TestDetect:
    def test_detect_dockerfile(self, tmp_path: Path) -> None:
        assert deploy.detect(FIXTURE_ROOT) == "dockerfile"
        assert deploy.detect(tmp_path) is None

    def test_detect_compose_wins(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM scratch\n")
        (tmp_path / "compose.yaml").write_text("services: {}\n")
        assert deploy.detect(tmp_path) == "compose"


class TestRunJob:
    def test_run_job_ups_hunts_and_downs(self, tmp_path: Path) -> None:
        db_path = tmp_path / "deploy.db"
        hunt_calls: list[tuple[object, str | None]] = []

        def hunt(*, db_path, url=None):
            hunt_calls.append((db_path, url))
            return {"finding_ids": []}

        with _FakeServer() as server:
            docker = _make_docker(server.port)
            result = deploy.run_job(FIXTURE_ROOT, db_path=db_path, docker=docker, hunt=hunt)

        assert result["status"] == "ok"
        assert "run_id" in result
        assert result["url"] == f"http://127.0.0.1:{server.port}"
        assert hunt_calls == [(db_path, result["url"])]

        kinds = [tuple(argv[:2]) for argv in docker.calls]
        assert ("docker", "run") in kinds
        assert ("docker", "rm") in kinds

    def test_detect_none_is_bring_your_own_url(self, tmp_path: Path) -> None:
        result = deploy.run_job(
            tmp_path, db_path=tmp_path / "deploy.db",
            docker=_failing_docker(), hunt=_failing_hunt(),
        )
        assert result["status"] == "needs_review"
        assert "bring your own URL" in result["reason"]

    def test_down_runs_when_hunt_raises(self, tmp_path: Path) -> None:
        db_path = tmp_path / "deploy.db"

        def hunt(*, db_path, url=None):
            raise RuntimeError("boom")

        with _FakeServer() as server:
            docker = _make_docker(server.port)
            with pytest.raises(RuntimeError, match="boom"):
                deploy.run_job(FIXTURE_ROOT, db_path=db_path, docker=docker, hunt=hunt)

        kinds = [tuple(argv[:2]) for argv in docker.calls]
        assert ("docker", "rm") in kinds

    @pytest.mark.skipif(
        os.environ.get("TRIAGE_LIVE_DOCKER") != "1",
        reason="live docker up/down; set TRIAGE_LIVE_DOCKER=1 to run",
    )
    def test_live_echo_app(self, tmp_path: Path) -> None:
        import subprocess
        import urllib.request

        run_id = "live-test"
        running = deploy.up(FIXTURE_ROOT, run_id=run_id)
        try:
            with urllib.request.urlopen(f"{running.url}/health", timeout=5) as resp:
                assert resp.status == 200
        finally:
            deploy.down(running)

        ps = subprocess.run(
            ["docker", "ps", "-q"], capture_output=True, encoding="latin-1",
        ).stdout
        for container_id in running.ids:
            assert container_id not in ps


class TestUpFailureCleanup:
    def test_up_removes_container_when_port_lookup_fails(self, tmp_path: Path) -> None:
        calls: list[list[str]] = []

        def docker(argv: list[str]) -> tuple[int, str, str]:
            calls.append(argv)
            if argv[:2] == ["docker", "build"]:
                return 0, "sha256:deadbeef\n", ""
            if argv[:2] == ["docker", "run"]:
                return 0, "containeridfake123\n", ""
            if argv[:2] == ["docker", "port"]:
                return 1, "", "Error: No such container:port"
            if argv[:2] == ["docker", "rm"]:
                return 0, "containeridfake123\n", ""
            return 1, "", f"unexpected argv {argv}"

        with pytest.raises(RuntimeError, match="docker port failed"):
            deploy.up(FIXTURE_ROOT, run_id="leak-test-1", docker=docker)

        rm_calls = [argv for argv in calls if argv[:2] == ["docker", "rm"]]
        assert rm_calls == [["docker", "rm", "-f", "containeridfake123"]]

    def test_up_removes_container_when_health_check_times_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(deploy, "_HEALTH_TIMEOUT_S", 0.3)
        monkeypatch.setattr(deploy, "_HEALTH_POLL_INTERVAL_S", 0.05)

        # A bound-then-closed socket's port has nothing listening, so the
        # health GET fails fast with connection-refused instead of hanging.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()

        calls: list[list[str]] = []

        def docker(argv: list[str]) -> tuple[int, str, str]:
            calls.append(argv)
            if argv[:2] == ["docker", "build"]:
                return 0, "sha256:deadbeef\n", ""
            if argv[:2] == ["docker", "run"]:
                return 0, "containeridfake456\n", ""
            if argv[:2] == ["docker", "port"]:
                return 0, f"127.0.0.1:{dead_port}\n", ""
            if argv[:2] == ["docker", "rm"]:
                return 0, "containeridfake456\n", ""
            return 1, "", f"unexpected argv {argv}"

        with pytest.raises(RuntimeError, match="did not return 200"):
            deploy.up(FIXTURE_ROOT, run_id="leak-test-2", docker=docker)

        rm_calls = [argv for argv in calls if argv[:2] == ["docker", "rm"]]
        assert rm_calls == [["docker", "rm", "-f", "containeridfake456"]]
