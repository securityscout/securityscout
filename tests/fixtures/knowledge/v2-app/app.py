"""Fixture target app: the v2 orders API.

The knowledge PDF describes an IDOR on the previous major version of
this endpoint. None of that version is routed here, so a hypothesis
carried over from the PDF is only ever a hypothesis until someone
proves it against this handler.

Stdlib only; nothing in the suite serves this app.
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

ORDERS = {
    "1": {"id": 1, "owner": "u2", "total": "42.00"},
    "2": {"id": 2, "owner": "u7", "total": "8.50"},
}

_ORDER_PATH = re.compile(r"^/v2/orders/([0-9]+)$")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        match = _ORDER_PATH.match(self.path)
        if match is None:
            self._send(404, {"error": "not_found"})
            return
        order = ORDERS.get(match.group(1))
        if order is None:
            self._send(404, {"error": "not_found"})
            return
        self._send(200, order)

    def log_message(self, *_args) -> None:
        return

    def _send(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()


if __name__ == "__main__":
    main()
