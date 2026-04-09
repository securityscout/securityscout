from __future__ import annotations

import uuid

from exceptions import SecurityScoutError

__all__ = ["SlackAPIError"]


class SlackAPIError(SecurityScoutError):
    def __init__(
        self,
        message: str | None = None,
        *,
        is_transient: bool,
        http_status: int | None = None,
        slack_error_code: str | None = None,
        finding_id: str | None = None,
        workflow_run_id: uuid.UUID | str | None = None,
    ) -> None:
        super().__init__(
            message,
            finding_id=finding_id,
            workflow_run_id=workflow_run_id,
            is_transient=is_transient,
            is_resource_error=False,
        )
        self.http_status = http_status
        self.slack_error_code = slack_error_code

    @classmethod
    def from_status(cls, status: int, message: str) -> SlackAPIError:
        transient = status in (408, 425, 429, 500, 502, 503, 504)
        return cls(message, is_transient=transient, http_status=status)
