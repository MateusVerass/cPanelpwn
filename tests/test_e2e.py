"""Teste E2E da cadeia de exploit contra o servidor mock WHM (tests/mock_whm.py).

Exercita os 4 estágios de ponta a ponta sem tocar a rede externa. Foi esse
tipo de teste que faltava na v2.4 — a cadeia só era validada manualmente.
"""
import argparse
import socketserver
import threading
import unittest

from cpanelpwn import config as cfg
from cpanelpwn import scanner
from tests import mock_whm


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class TestExploitE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = _Server(("127.0.0.1", 0), mock_whm.Handler)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _args(self):
        return argparse.Namespace(
            timeout=5, session=None, token_reuse=None, hostname=None,
            action=None)

    def test_full_chain_confirms(self):
        cfg._CHECKPOINT = None
        cfg._JSON_LINES = False
        cfg._RETRIES = 0
        target = f"http://127.0.0.1:{self.port}"
        result = scanner.scan(target, self._args())
        self.assertTrue(result.get("vuln"))
        finding = result["finding"]
        self.assertEqual(finding["cve"], "CVE-2026-41940")
        self.assertEqual(finding["token"], "/cpsess1234567890")
        self.assertEqual(finding["version"], "11.130.0.6")

    def test_check_target_reads_version(self):
        cfg._TIMEOUT_PROBE = 5
        result = scanner.check_target(f"http://127.0.0.1:{self.port}")
        self.assertEqual(result.get("version"), "11.130.0.6")


if __name__ == "__main__":
    unittest.main()
