"""Testes unitários para cpanelpwn.cve_feed — parse NVD/CIRCL, cache, versões."""
import json
import os
import tempfile
import unittest

from cpanelpwn.cve_feed import (
    _cve_score, _parse_circl_cves, _parse_nvd_cves, _read_json_cache,
    _ver_tuple, _write_json_cache, cve_feed_sources,
)
NVD_BODY = json.dumps({
    "resultsPerPage": 2,
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2026-67401",
            "published": "2026-09-09T12:00:00.000",
            "descriptions": [{"lang": "en", "value": "RCE in cPanel mail"},
                             {"lang": "es", "value": "otro"}],
            "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseScore": 9.9}}]},
        }},
        {"cve": {
            "id": "CVE-2026-00001",
            "published": "2026-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "WHMCS billing bug"}],
            "metrics": {"cvssMetricV30": [
                {"cvssData": {"baseScore": 5.0}}]},
        }},
    ],
})


class TestParseNvd(unittest.TestCase):
    def test_parses(self):
        cves = _parse_nvd_cves(NVD_BODY)
        by_id = {c["id"]: c for c in cves}
        self.assertEqual(by_id["CVE-2026-67401"]["score"], 9.9)
        self.assertEqual(by_id["CVE-2026-67401"]["summary"],
                         "RCE in cPanel mail")
        self.assertIn("nvd.nist.gov", by_id["CVE-2026-67401"]["url"])

    def test_bad_json_returns_empty(self):
        self.assertEqual(_parse_nvd_cves("not json"), [])


class TestParseCircl(unittest.TestCase):
    def test_parses_list(self):
        body = json.dumps([{"id": "CVE-2026-1", "summary": "x",
                            "cvss": {"score": 7.5}}])
        cves = _parse_circl_cves(body)
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]["score"], 7.5)

    def test_parses_results_object(self):
        body = json.dumps({"results": [{"cve_id": "CVE-2026-2",
                                        "description": "y"}]})
        cves = _parse_circl_cves(body)
        self.assertEqual(cves[0]["id"], "CVE-2026-2")

    def test_whmcs_filter(self):
        body = json.dumps([{"id": "CVE-2026-3", "summary": "WHMCS vuln",
                            "cvss": {"score": 9.0}}])
        cves = _parse_circl_cves(body)
        # fetch_cve_feed faz o drop WHMCS; o parser puro mantém a entrada
        self.assertEqual(cves[0]["id"], "CVE-2026-3")


class TestScore(unittest.TestCase):
    def test_dict_score(self):
        self.assertEqual(_cve_score({"cvss": {"score": "8.1"}}), 8.1)

    def test_flat_score(self):
        self.assertEqual(_cve_score({"cvss": 6.5}), 6.5)

    def test_missing(self):
        self.assertEqual(_cve_score({}), 0.0)


class TestVersion(unittest.TestCase):
    def test_ver_tuple(self):
        self.assertEqual(_ver_tuple("v2.4.1"), (2, 4, 1))
        self.assertEqual(_ver_tuple("2.4"), (2, 4))
        self.assertEqual(_ver_tuple("abc"), (0,))


class TestCache(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "cve_feed.json")
            _write_json_cache(p, {"ts": 1, "cves": [{"id": "X"}]})
            data = _read_json_cache(p)
            self.assertEqual(data["ts"], 1)
            self.assertEqual(data["cves"][0]["id"], "X")

    def test_missing_returns_none(self):
        self.assertIsNone(_read_json_cache("/nonexistent/x.json"))


class TestSources(unittest.TestCase):
    def test_contains_nvd_and_circl(self):
        srcs = cve_feed_sources(30)
        kinds = [k for k, _ in srcs]
        self.assertIn("nvd", kinds)
        self.assertIn("circl", kinds)
        self.assertTrue(any("pubStartDate" in u for k, u in srcs
                            if k == "nvd"))

    def test_window_chunked_over_120_days(self):
        from cpanelpwn.cve_feed import _date_windows
        wins = _date_windows(200)
        self.assertGreaterEqual(len(wins), 2)
        for start, end in wins:
            self.assertLessEqual((end - start).days, 120)
        # cada fatia gera 2 fontes NVD (cpanel + whm)
        nvd = [k for k, _ in cve_feed_sources(200) if k == "nvd"]
        self.assertEqual(len(nvd), 2 * len(wins))


if __name__ == "__main__":
    unittest.main()