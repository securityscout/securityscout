"""Deploy harness: bring a fixture app up, hand its URL to hunt, tear it down.

`run_fixture` has no `url` kwarg (it drives an in-tree fixture end to
end on its own), so the default `hunt` here is a wrapper that ignores
`url` and calls `run_fixture(db_path=db_path)`. The wrapper exists so a
real specialist that does take a target URL can be swapped in later
without touching `run_job`.

Both `docker` calls and the fixture's own `/health` endpoint go through
real loopback I/O even under the default (non-live) test run — the
`docker` runner is injectable, but the health check is a genuine HTTP
GET at whatever URL `up` derives, so tests point it at a real local
HTTP server rather than mocking the network.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

DockerRunner = Callable[[list[str]], tuple[int, str, str]]
HuntFn = Callable[..., dict[str, Any]]

_CONTAINER_PORT = 8000
_HEALTH_TIMEOUT_S = 30.0
_HEALTH_POLL_INTERVAL_S = 0.5


def _docker_run(argv: list[str], *, timeout: float = 60.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv, capture_output=True, encoding="latin-1",
            stdin=subprocess.DEVNULL, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise RuntimeError(f"{argv}: {type(exc).__name__}: {exc}") from exc
    return proc.returncode, proc.stdout, proc.stderr


def detect(root: Path | str) -> str | None:
    root = Path(root)
    if (root / "compose.yaml").exists() or (root / "compose.yml").exists():
        return "compose"
    if (root / "Dockerfile").exists():
        return "dockerfile"
    return None


@dataclass
class Running:
    url: str
    ids: list[str]


def _parse_port(port_output: str) -> str:
    line = port_output.strip().splitlines()[-1]
    return line.rsplit(":", 1)[-1]


def _wait_healthy(url: str) -> None:
    deadline = time.monotonic() + _HEALTH_TIMEOUT_S
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=5) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
        time.sleep(_HEALTH_POLL_INTERVAL_S)
    raise RuntimeError(f"{url}/health did not return 200 in time: {last_error}")


def _docker_port(container_id: str, *, docker: DockerRunner) -> str:
    rc, out, err = docker(["docker", "port", container_id, f"{_CONTAINER_PORT}/tcp"])
    if rc != 0:
        raise RuntimeError(f"docker port failed (rc={rc}): {err or out}")
    return _parse_port(out)


def _rm(ids: list[str], *, docker: DockerRunner) -> None:
    for container_id in ids:
        docker(["docker", "rm", "-f", container_id])


def _up_dockerfile(root: Path, *, run_id: str, docker: DockerRunner) -> tuple[list[str], str]:
    tag = f"securityscout-deploy-{run_id}"
    rc, out, err = docker(["docker", "build", "-q", "-t", tag, str(root)])
    if rc != 0:
        raise RuntimeError(f"docker build failed (rc={rc}): {err or out}")

    rc, out, err = docker(["docker", "run", "-d", "-p", f"127.0.0.1::{_CONTAINER_PORT}", tag])
    if rc != 0:
        raise RuntimeError(f"docker run failed (rc={rc}): {err or out}")
    container_id = out.strip().splitlines()[-1]

    try:
        port = _docker_port(container_id, docker=docker)
    except Exception:
        _rm([container_id], docker=docker)
        raise
    return [container_id], port


def _up_compose(root: Path, *, docker: DockerRunner) -> tuple[list[str], str]:
    # `docker compose down` would also drop the project network, but `down()`
    # only ever receives `Running.ids` (the pinned public contract) — no
    # compose file / project name survives past `up()` to make that call.
    compose_file = root / "compose.yaml"
    if not compose_file.exists():
        compose_file = root / "compose.yml"

    rc, out, err = docker(["docker", "compose", "-f", str(compose_file), "up", "-d", "--build"])
    if rc != 0:
        raise RuntimeError(f"docker compose up failed (rc={rc}): {err or out}")

    rc, out, err = docker(["docker", "compose", "-f", str(compose_file), "ps", "-q"])
    if rc != 0:
        raise RuntimeError(f"docker compose ps failed (rc={rc}): {err or out}")
    ids = [line for line in out.strip().splitlines() if line.strip()]
    if not ids:
        raise RuntimeError("docker compose up produced no containers")

    try:
        port = _docker_port(ids[0], docker=docker)
    except Exception:
        _rm(ids, docker=docker)
        raise
    return ids, port


def up(root: Path | str, *, run_id: str, docker: DockerRunner | None = None) -> Running:
    root = Path(root)
    docker = docker or _docker_run
    kind = detect(root)
    if kind is None:
        raise ValueError(f"no Dockerfile or compose file at {root}")

    if kind == "dockerfile":
        ids, port = _up_dockerfile(root, run_id=run_id, docker=docker)
    else:
        ids, port = _up_compose(root, docker=docker)

    url = f"http://127.0.0.1:{port}"
    try:
        _wait_healthy(url)
    except Exception:
        _rm(ids, docker=docker)
        raise
    return Running(url=url, ids=ids)


def down(running: Running, *, docker: DockerRunner | None = None) -> None:
    docker = docker or _docker_run
    _rm(running.ids, docker=docker)


def _default_hunt(*, db_path: Path | str, url: str | None = None) -> dict[str, Any]:
    from triage.hunt import run_fixture

    return run_fixture(db_path=db_path)


def run_job(
    root: Path | str, *,
    db_path: Path | str,
    docker: DockerRunner | None = None,
    hunt: HuntFn | None = None,
) -> dict[str, Any]:
    root = Path(root)
    docker = docker or _docker_run
    hunt = hunt or _default_hunt

    if detect(root) is None:
        return {"status": "needs_review", "reason": "bring your own URL"}

    run_id = uuid.uuid4().hex
    running = up(root, run_id=run_id, docker=docker)
    try:
        hunt_result = hunt(db_path=db_path, url=running.url)
    finally:
        down(running, docker=docker)

    return {"status": "ok", "url": running.url, "run_id": run_id, "hunt": hunt_result}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--db", required=True)
    args = parser.parse_args(argv)

    try:
        result = run_job(Path(args.root), db_path=args.db)
    except RuntimeError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
