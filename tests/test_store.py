"""Testes unitários para cpanelpwn.store — Checkpoint + Progress."""
import os
import tempfile
import unittest

from cpanelpwn.store import Checkpoint, Progress, STORE


class TestCheckpoint(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "resume.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip(self):
        cp = Checkpoint(self.path)
        cp.set_targets(["https://a:2087", "https://b:2087"])
        cp.mark_done("https://a:2087", {"vuln": True})
        cp.save()

        cp2 = Checkpoint(self.path)
        self.assertEqual(cp2.targets(), ["https://a:2087", "https://b:2087"])
        self.assertIn("https://a:2087", cp2.done())
        self.assertTrue(cp2.results()["https://a:2087"]["vuln"])

    def test_disabled_writes_nothing(self):
        cp = Checkpoint(self.path, enabled=False)
        cp.set_targets(["https://a:2087"])
        cp.save()
        self.assertFalse(os.path.exists(self.path))

    def test_clear(self):
        cp = Checkpoint(self.path)
        cp.set_targets(["https://a:2087"])
        cp.mark_done("https://a:2087", {"vuln": False})
        cp.clear()
        self.assertEqual(cp.done(), set())

    def test_version_mismatch_ignored(self):
        cp = Checkpoint(self.path)
        cp.set_targets(["https://a:2087"])
        cp.save()
        with open(self.path, "w") as f:
            f.write('{"version": "0.1", "targets": []}')
        cp2 = Checkpoint(self.path)
        self.assertEqual(cp2.targets(), [])

    def test_corrupt_file_ignored(self):
        with open(self.path, "w") as f:
            f.write("{not json")
        cp = Checkpoint(self.path)
        self.assertEqual(cp.done(), set())


class TestProgress(unittest.TestCase):
    def test_tick_counts(self):
        p = Progress(10)
        p.tick(True)
        p.tick(False)
        self.assertEqual(p._done, 2)
        self.assertEqual(p._vulns, 1)


class TestStore(unittest.TestCase):
    def test_add_dedup(self):
        STORE._f = []
        STORE._seen = set()
        STORE.add({"target": "https://a", "severity": "HIGH"})
        STORE.add({"target": "https://a", "severity": "HIGH"})
        self.assertEqual(len(STORE.all()), 1)

    def test_severity_sort(self):
        STORE._f = []
        STORE._seen = set()
        STORE.add({"target": "https://low", "severity": "INFO"})
        STORE.add({"target": "https://crit", "severity": "CRIT"})
        self.assertEqual(STORE.all()[0]["target"], "https://crit")


if __name__ == "__main__":
    unittest.main()