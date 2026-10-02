"""Testes para cpanelpwn.discovery — parsing de CT logs e detecção de WHM.

Cobrem o bug histórico do `import json` ausente, que fazia o discovery por
Certificate Transparency devolver sempre 0 hostnames.
"""
import json
import unittest

from cpanelpwn import discovery
from cpanelpwn.http import R

CT_BODY = json.dumps([
    {"name_value": "*.alvo.com\nmail.alvo.com", "common_name": "alvo.com"},
    {"name_value": "whm.alvo.com", "common_name": "outro.exemplo.com"},
])


class TestParseCtEntries(unittest.TestCase):
    def test_extracts_subdomains(self):
        got = discovery._parse_ct_entries(CT_BODY, "alvo.com")
        self.assertIn("mail.alvo.com", got)
        self.assertIn("whm.alvo.com", got)
        self.assertIn("alvo.com", got)
        # host de outro domínio não deve entrar
        self.assertNotIn("outro.exemplo.com", got)

    def test_bad_json_returns_empty(self):
        self.assertEqual(discovery._parse_ct_entries("<html>", "alvo.com"), set())


class TestIsWhmResponse(unittest.TestCase):
    def test_detects_whm_login(self):
        self.assertTrue(discovery._is_whm_response(
            R(200, "<title>WHM Login</title>", {}, "http://x/")))

    def test_ignores_other(self):
        self.assertFalse(discovery._is_whm_response(
            R(200, "hello world", {}, "http://x/")))

    def test_status_zero(self):
        self.assertFalse(discovery._is_whm_response(R(0, "", {}, "http://x/")))


class TestCrtShFallback(unittest.TestCase):
    def test_crtsh_used_when_ok(self):
        calls = []

        def fake_do(url, **kw):
            calls.append(url)
            return R(200, CT_BODY, {}, url)

        old = discovery._do
        discovery._do = fake_do
        try:
            got = discovery.crtsh_subdomains("alvo.com", timeout=1)
        finally:
            discovery._do = old
        self.assertIn("whm.alvo.com", got)
        self.assertTrue(any("crt.sh" in c for c in calls))

    def test_fallback_to_certspotter(self):
        calls = []

        def fake_do(url, **kw):
            calls.append(url)
            if "crt.sh" in url:
                return R(500, "", {}, url)
            return R(200, json.dumps([{"dns_names": ["cpanel.alvo.com"]}]), {}, url)

        old = discovery._do
        discovery._do = fake_do
        try:
            got = discovery.crtsh_subdomains("alvo.com", timeout=1)
        finally:
            discovery._do = old
        self.assertIn("cpanel.alvo.com", got)
        self.assertTrue(any("certspotter" in c for c in calls))


if __name__ == "__main__":
    unittest.main()
