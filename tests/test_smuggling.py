"""Testes para cpanelpwn.smuggling — detecção CL.TE/TE.CL (CVE-2026-58047).

Sobe servidores HTTP reais de stdlib: um que responde rápido (sem smuggling)
e outro que "pendura" no POST (simula desincronização).
"""
import http.server
import threading
import time
import unittest

from cpanelpwn import smuggling


class _Base(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Normal(_Base):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        body = b"posted"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Hanging(_Base):
    def do_POST(self):
        time.sleep(3)


def _serve(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


class TestRawHttp(unittest.TestCase):
    def test_raw_request_connects(self):
        srv, port = _serve(_Normal)
        try:
            data, elapsed, ok = smuggling._raw_http(
                "http", "127.0.0.1", port,
                b"GET /login HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                timeout=3)
            self.assertTrue(ok)
            self.assertIn(b"200", data)
            self.assertGreaterEqual(elapsed, 0.0)
        finally:
            srv.shutdown()


class TestDetect(unittest.TestCase):
    def test_no_smuggling_on_normal_server(self):
        srv, port = _serve(_Normal)
        try:
            res = smuggling.detect("http", "127.0.0.1", port, timeout=2)
            self.assertFalse(res["vulnerable"])
            self.assertEqual(res["cve"], "CVE-2026-58047")
        finally:
            srv.shutdown()

    def test_detects_hanging_backend(self):
        srv, port = _serve(_Hanging)
        try:
            res = smuggling.detect("http", "127.0.0.1", port, timeout=0.6)
            self.assertTrue(res["vulnerable"])
            self.assertIn(res["technique"], ("CL.TE", "TE.CL"))
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
