"""Listen entrypoint: `python -m api`. The only supported serve path.

Off-loopback exposure is gated here, before the socket exists, because
`require_auth` cannot see the listen address and an ASGI lifespan hook
cannot see uvicorn's `--host` either.
"""

from __future__ import annotations

import os

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = "8000"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def check_bind(host: str, token: str | None) -> None:
    """Refuse a non-loopback listen address while the API token is unset.

    A blank `TRIAGE_API_TOKEN` counts as unset — an empty assignment in
    `.env` is an operator forgetting the value, not a credential.
    """
    if token or host in LOOPBACK_HOSTS:
        return
    raise RuntimeError(
        f"TRIAGE_API_TOKEN is unset; refusing to listen on {host!r}. "
        f"Set TRIAGE_API_TOKEN, or bind {DEFAULT_HOST}."
    )


def main() -> None:
    """Resolve the listen address, guard it, then hand off to uvicorn.

    `api.app` is imported first so `triage.config` loads `.env` before the
    guard reads the environment; otherwise a token set only in `.env` would
    be invisible here yet honored by `require_auth`.
    """
    from api.app import app

    host = os.environ.get("TRIAGE_API_HOST") or DEFAULT_HOST
    port = int(os.environ.get("TRIAGE_API_PORT") or DEFAULT_PORT)
    check_bind(host, os.environ.get("TRIAGE_API_TOKEN"))

    import uvicorn

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
