"""Testes unitários para cpanelpwn.waf — detecção + perfiles de bypass."""
import unittest

from cpanelpwn.http import R
from cpanelpwn.waf import (
    WAF_BYPASS, WAF_SIGNATURES, get_bypass_delay,
    get_bypass_headers, _mk_profile,
)


class TestMkProfile(unittest.TestCase):
    def test_default_spoof(self):
        p = _mk_profile(0.5)
        self.assertEqual(p["delay"], 0.5)
        self.assertEqual(p["headers"]["X-Forwarded-For"], "127.0.0.1")
        self.assertEqual(p["headers"]["X-Real-IP"], "127.0.0.1")

    def test_extras_merged(self):
        p = _mk_profile(0.1, {"X-Originating-IP": "127.0.0.1"})
        self.assertEqual(p["headers"]["X-Originating-IP"], "127.0.0.1")
        self.assertIn("X-Forwarded-For", p["headers"])


class TestBypassProfile(unittest.TestCase):
    def test_cloudflare_profile(self):
        hdrs = get_bypass_headers("Cloudflare")
        self.assertEqual(hdrs["X-Forwarded-For"], "127.0.0.1")
        self.assertIn("CF-Connecting-IP", hdrs)
        self.assertGreaterEqual(get_bypass_delay("Cloudflare"), 0)

    def test_unknown_waf_returns_empty(self):
        self.assertEqual(get_bypass_headers("NoSuchWAF"), {})
        self.assertEqual(get_bypass_delay("NoSuchWAF"), 0)

    def test_all_profiles_have_required_keys(self):
        for name, prof in WAF_BYPASS.items():
            self.assertIn("headers", prof, name)
            self.assertIn("delay", prof, name)
            self.assertIsInstance(prof["headers"], dict, name)
            self.assertIn("X-Forwarded-For", prof["headers"], name)

    def test_all_detection_signatures_callable(self):
        r = R(200, "", {"server": "nginx"}, "http://x/")
        for name, fn in WAF_SIGNATURES.items():
            try:
                fn(r)
            except Exception as e:
                self.fail(f"signature {name} raised: {e}")


class TestDetectWaf(unittest.TestCase):
    def test_cloudflare_detected(self):
        r = R(200, "", {"cf-ray": "abc123"}, "http://x/")
        self.assertTrue(any(fn(r) for name, fn in WAF_SIGNATURES.items()
                            if name == "Cloudflare"))

    def test_unknown_headers(self):
        r = R(200, "", {"server": "nginx"}, "http://x/")
        for name, fn in WAF_SIGNATURES.items():
            self.assertFalse(fn(r), name)


if __name__ == "__main__":
    unittest.main()