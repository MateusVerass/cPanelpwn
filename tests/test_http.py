"""Testes para cpanelpwn.http — servidor HTTP local, retries, cookies.

Levanta um http.server real de stdlib em 127.0.0.1 para exercitar _do()
sem tocar a rede.
"""
import http.server
import threading
import unittest

from cpanelpwn import config as cfg
from cpanelpwn.http import _do


class _Handler(http.server.BaseHTTPRequestHandler):
    status = 200
    body = b"hello"
    headers = {}
    set_cookie = ""
    requests = []

    def do_GET(self):
        self.__class__.requests.append(self.path)
        if self.path == "/fail500":
            self.__class__.status, self.__class__.body = 500, b"boom"
        elif self.path == "/cookie":
            self.__class__.set_cookie = "whostmgrsession=%3aABC,OBHASH; path=/"
        else:
            self.__class__.status, self.__class__.body = 200, b"hello"
        self.send_response(self.__class__.status)
        for k, v in self.__class__.headers.items():
            self.send_header(k, v)
        if self.__class__.set_cookie:
            self.send_header("Set-Cookie", self.__class__.set_cookie)
        self.send_header("Content-Length", str(len(self.__class__.body)))
        self.end_headers()
        self.wfile.write(self.__class__.body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.__class__.received = self.rfile.read(length)
        self.send_response(401)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class HttpTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        _Handler.requests = []
        _Handler.set_cookie = ""
        _Handler.status, _Handler.body = 200, b"hello"
        cfg._RETRIES = 2
        cfg._DELAY = 0
        cfg._JITTER = 0
        cfg._PROXY = None
        cfg._UA = None

    def test_get(self):
        r = _do(f"http://127.0.0.1:{self.port}/", timeout=5)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, "hello")

    def test_post_form(self):
        r = _do(f"http://127.0.0.1:{self.port}/login",
                method="POST", data={"user": "root", "pass": "x"}, timeout=5)
        self.assertEqual(r.status, 401)
        self.assertIn(b"user=root", _Handler.received)

    def test_retry_on_500(self):
        cfg._RETRIES = 1
        r = _do(f"http://127.0.0.1:{self.port}/fail500", timeout=5)
        self.assertEqual(r.status, 500)
        self.assertGreaterEqual(len(_Handler.requests), 2)

    def test_cookie_capture(self):
        r = _do(f"http://127.0.0.1:{self.port}/cookie", timeout=5)
        self.assertIn("whostmgrsession", r.raw_cookies)
        self.assertEqual(r.raw_cookie("whostmgrsession"), "%3aABC,OBHASH")

    def test_connection_refused(self):
        r = _do("http://127.0.0.1:1/", timeout=2)
        self.assertEqual(r.status, 0)

    def test_custom_ua(self):
        cfg._UA = "curl/8.0"
        r = _do(f"http://127.0.0.1:{self.port}/", timeout=5)
        self.assertEqual(r.status, 200)


if __name__ == "__main__":
    unittest.main()