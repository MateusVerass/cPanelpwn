#!/usr/bin/env python3
"""Servidor mock WHM/cPanel para testes E2E de cPanelpwn.

Simula a cadeia completa de exploit CVE-2026-41940:
  /openid_connect/cpanelid      → 307 → host canónico
  /login/?login_only=1 (POST)   → 401 + cookie whostmgrsession
  / (com Authorization)         → 307 → /cpsess1234567890/
  /scripts2/listaccts           → 401 Token denied
  /cpsess1234567890/json-api/version → 200 {"version":"11.130.0.6"}
"""
import http.server
import json
import socketserver
import sys

VERSION = "11.130.0.6"


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/openid_connect/cpanelid":
            self._send(307, b"", {"Location": "https://mock-canonical.local:2087/login"})
        elif path == "/":
            self._send(307, b"", {"Location": "https://mock-canonical.local:2087/cpsess1234567890/index.html"})
        elif path == "/scripts2/listaccts":
            self._send(401, b"Token denied - WHM Login required", {"Content-Type": "text/plain"})
        elif path.startswith("/cpsess1234567890/json-api/version"):
            self._send(200, json.dumps({"version": VERSION, "result": 1}).encode(),
                       {"Content-Type": "application/json"})
        elif path == "/login":
            self._send(200, b"<html>WHM Login</html>", {"Content-Type": "text/html"})
        else:
            self._send(404, b"not found")

    def do_POST(self):
        self._send(401, b"login failed",
                   {"Set-Cookie": "whostmgrsession=%3aMOCK_SESSION,OBHASH; path=/"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    with socketserver.TCPServer(("127.0.0.1", port), Handler) as srv:
        print(srv.server_address[1], flush=True)
        srv.serve_forever()