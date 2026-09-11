"""Testes unitários para cpanelpwn.core — parse de alvos, build de URLs, verificação de versão."""
import base64
import unittest

from cpanelpwn.core import (
    PAYLOAD_B64, PAYLOAD_B64_CR, PAYLOAD_B64_LF,
    ScanCtx, build_url, is_version_patched, parse_target, _has_explicit_port,
)


class TestParseTarget(unittest.TestCase):
    def test_full_url(self):
        self.assertEqual(
            parse_target("https://host.example:2087"),
            ("https", "host.example", 2087))

    def test_default_port_2087(self):
        self.assertEqual(parse_target("https://host.example"),
                         ("https", "host.example", 2087))

    def test_no_scheme(self):
        self.assertEqual(parse_target("host.example:2083"),
                         ("https", "host.example", 2083))

    def test_http_scheme(self):
        self.assertEqual(parse_target("http://10.0.0.1:2086"),
                         ("http", "10.0.0.1", 2086))

    def test_trailing_slash_stripped(self):
        self.assertEqual(parse_target("https://h:2087/")[2], 2087)

    def test_ipv6(self):
        scheme, host, port = parse_target("https://[::1]:2087")
        self.assertEqual(host, "::1")
        self.assertEqual(port, 2087)


class TestHasExplicitPort(unittest.TestCase):
    def test_with_port(self):
        self.assertTrue(_has_explicit_port("https://h:2087"))

    def test_without_port(self):
        self.assertFalse(_has_explicit_port("https://h"))

    def test_plain_host_port(self):
        self.assertTrue(_has_explicit_port("h:2087"))

    def test_ipv6_bracket(self):
        self.assertTrue(_has_explicit_port("https://[::1]:2087"))
        self.assertFalse(_has_explicit_port("https://[::1]"))


class TestBuildUrl(unittest.TestCase):
    def test_default_https_port_omitted(self):
        self.assertEqual(build_url("https", "h", 443, "/x"),
                         "https://h/x")

    def test_default_http_port_omitted(self):
        self.assertEqual(build_url("http", "h", 80, "/x"), "http://h/x")

    def test_nondefault_port_included(self):
        self.assertEqual(build_url("https", "h", 2087, "/x"),
                         "https://h:2087/x")

    def test_path_preserved(self):
        self.assertEqual(build_url("https", "h", 2087, "/a/b?c=d"),
                         "https://h:2087/a/b?c=d")


class TestIsVersionPatched(unittest.TestCase):
    def test_patched_136(self):
        self.assertTrue(is_version_patched("11.136.0.5"))

    def test_vulnerable_136(self):
        self.assertFalse(is_version_patched("11.136.0.4"))

    def test_patched_110(self):
        self.assertTrue(is_version_patched("11.110.0.97"))

    def test_vulnerable_110(self):
        self.assertFalse(is_version_patched("11.110.0.96"))

    def test_unknown_branch(self):
        self.assertIsNone(is_version_patched("11.999.0.1"))

    def test_malformed(self):
        self.assertIsNone(is_version_patched("garbage"))


class TestPayloads(unittest.TestCase):
    def test_payload_decodes_to_session_fields(self):
        raw = base64.b64decode(PAYLOAD_B64).decode()
        for field in ("root:x", "successful_internal_auth_with_timestamp",
                      "user=root", "tfa_verified=1", "hasroot=1"):
            self.assertIn(field, raw)

    def test_variants_decode(self):
        for b64 in (PAYLOAD_B64_CR, PAYLOAD_B64_LF):
            raw = base64.b64decode(b64).decode()
            self.assertIn("user=root", raw)


class TestScanCtx(unittest.TestCase):
    def test_defaults(self):
        ctx = ScanCtx("https", "h", 2087, "h", "sess", "tok", 10)
        self.assertEqual(ctx.waf, "")
        self.assertEqual(ctx.bypass_hdrs, {})


if __name__ == "__main__":
    unittest.main()