"""Tiny stdlib HTTP app for the deploy-harness fixture.

`GET /health` answers 200 so `deploy.up` can confirm the container is
reachable; every other path echoes it back so a hunt run has something
to look at.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f"echo {self.path}".encode())

    def log_message(self, format: str, *args: object) -> None:
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
