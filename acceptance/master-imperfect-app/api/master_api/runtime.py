"""Dependency-free runtime used only by the isolated master acceptance journey."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FixtureHandler(BaseHTTPRequestHandler):
    accounts: set[str] = set()
    uploads: list[int] = []

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, status: int, payload: object) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/admin/users":
            # Deliberate authorization defect: no role check.
            self._send(200, [{"id": item} for item in sorted(self.accounts)])
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.path == "/auth/login":
            account = "acceptance-user"
            self.accounts.add(account)
            self._send(200, {"token": "acceptance-token", "account": account})
            return
        if self.path == "/upload":
            self.uploads.append(len(body))
            self._send(200, {"bytes": len(body)})
            return
        if self.path == "/mcp":
            self._send(200, {"jsonrpc": "2.0", "result": {"accepted": True}})
            return
        self._send(404, {"error": "not_found"})


def create_server() -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
