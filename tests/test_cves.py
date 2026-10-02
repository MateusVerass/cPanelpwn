"""Testes para cpanelpwn.cves — catálogo, atribuição de versão e exploits."""
import unittest

from cpanelpwn import cves


class TestCatalog(unittest.TestCase):
    def test_id_unique(self):
        ids = [c.id for c in cves.CVES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_get_case_insensitive(self):
        self.assertIsNotNone(cves.get("cve-2026-41940"))
        self.assertIsNotNone(cves.get("CVE-2026-41940"))
        self.assertIsNone(cves.get("CVE-0000-00000"))

    def test_default_is_exploitable(self):
        self.assertIn(cves.DEFAULT_CVE, cves.EXPLOITABLE)
        self.assertTrue(cves.get(cves.DEFAULT_CVE).exploitable)

    def test_list_sorted_by_score(self):
        scores = [(c.cvss or 0.0) for c in cves.list_cves()]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_cvss_of(self):
        self.assertEqual(cves.cvss_of("CVE-2026-41940"), 9.8)
        self.assertEqual(cves.cvss_of("CVE-2026-58047", 1.0), 1.0)


class TestAffecting(unittest.TestCase):
    def test_41940_vulnerable_branch(self):
        ids = [c.id for c in cves.cves_affecting("11.136.0.4")]
        self.assertIn("CVE-2026-41940", ids)

    def test_41940_patched_branch(self):
        ids = [c.id for c in cves.cves_affecting("11.136.0.5")]
        self.assertNotIn("CVE-2026-41940", ids)

    def test_138_branch_patched_for_41940(self):
        ids = [c.id for c in cves.cves_affecting("11.138.0.0")]
        self.assertNotIn("CVE-2026-41940", ids)

    def test_max_affected_cve(self):
        # CVE-2026-65643 afeta <= 11.138.0.0
        self.assertIn("CVE-2026-65643",
                      [c.id for c in cves.cves_affecting("11.136.0.99")])
        self.assertNotIn("CVE-2026-65643",
                         [c.id for c in cves.cves_affecting("11.140.0.1")])

    def test_unknown_version_empty(self):
        self.assertEqual(cves.cves_affecting("garbage"), [])


if __name__ == "__main__":
    unittest.main()
