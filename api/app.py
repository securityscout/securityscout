"""Control-plane HTTP app. No exploit tools live here."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from triage.config import CONFIG


class ApiError(Exception):
    def __init__(self, status: int, error: str, detail: str) -> None:
        self.status = status
        self.error = error
        self.detail = detail


def error_response(
    status: int,
    error: str,
    detail: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": error, "detail": detail},
        headers=headers,
    )


def _validation_detail(exc: RequestValidationError) -> str:
    """Render pydantic errors without echoing the request or the traceback.

    Stringifying the exception carries the server's absolute source path, the
    OS username and the submitted input, and this handler answers
    unauthenticated calls. Only `loc` and `msg` cross the wire.
    """
    clauses = [
        "{}: {}".format(".".join(str(part) for part in err["loc"]), err["msg"])
        for err in exc.errors()
    ]
    return "; ".join(clauses)


def require_auth(request: Request) -> None:
    token = os.environ.get("TRIAGE_API_TOKEN")
    if not token:
        return
    header = request.headers.get("authorization", "")
    if header != f"Bearer {token}":
        raise ApiError(401, "unauthorized", "invalid or missing token")


def _default_policies() -> dict:
    return {
        "scope": {"repos": [], "hosts": []},
        "blast_radius": "safe",
        "budget": {
            "monthly_usd": CONFIG.budget_usd_monthly,
            "per_finding_usd": CONFIG.per_finding_usd_ceiling,
        },
        "models": {},
        "auto_publish": False,
    }


def create_app(db_path: Path | str | None = None) -> FastAPI:
    from api import (
        routes_engagements,
        routes_findings,
        routes_graph,
        routes_policies,
        routes_runs,
    )

    app = FastAPI()
    app.state.db_path = Path(db_path) if db_path is not None else Path(CONFIG.db_path)
    app.state.policies = _default_policies()

    @app.exception_handler(ApiError)
    async def _api_error(_request: Request, exc: ApiError) -> JSONResponse:
        return error_response(exc.status, exc.error, exc.detail)

    @app.exception_handler(RequestValidationError)
    async def _validation(_request: Request, exc: RequestValidationError) -> JSONResponse:
        return error_response(400, "invalid_request", _validation_detail(exc))

    @app.get("/health")
    def health() -> dict:
        return {"ok": True}

    deps = [Depends(require_auth)]
    app.include_router(routes_engagements.router, dependencies=deps)
    app.include_router(routes_runs.router, dependencies=deps)
    app.include_router(routes_findings.router, dependencies=deps)
    app.include_router(routes_graph.router, dependencies=deps)
    app.include_router(routes_policies.router, dependencies=deps)
    return app


app = create_app()
