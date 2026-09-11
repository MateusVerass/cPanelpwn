"""Testes unitários para cpanelpwn.parsers — formatos de entrada + listas de exclusão."""
import os
import tempfile
import unittest

from cpanelpwn.parsers import (
    is_excluded, load_exclude, load_list_file,
    parse_masscan_json, parse_nmap_xml, parse_shodan_json,
)

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="2087">
      <state state="open" reason="syn-ack"/>
    </port></ports>
  </host>
  <host><address addr="10.0.0.2" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22">
      <state state="closed" reason="reset"/>
    </port></ports>
  </host>
  <host><address addr="2001:db8::1" addrtype="ipv6"/>
    <ports><port protocol="tcp" portid="2083">
      <state state="open" reason="syn-ack"/>
    </port></ports>
  </host>
</nmaprun>
"""

MASSCAN_JSON = """[
  {"ip": "10.0.0.1", "ports": [{"port": 2087, "proto": "tcp"}]},
  {"ip": "10.0.0.2", "ports": [{"port": 80, "proto": "tcp"}]}
]
"""

SHODAN_NDJSON = (
    '{"ip_str": "10.0.0.1", "port": 2087, "product": "cPanel"}\n'
    '{"ip_str": "10.0.0.2", "port": 2083, "product": "cPanel"}\n'
)


class TestNmapXml(unittest.TestCase):
    def test_parses_open_ports(self):
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(NMAP_XML)
            path = f.name
        try:
            targets = parse_nmap_xml(path)
        finally:
            os.unlink(path)
        self.assertIn("https://10.0.0.1:2087", targets)
        self.assertNotIn("https://10.0.0.2:22", targets)
        self.assertTrue(any(t.startswith("https://[") for t in targets))


class TestMasscanJson(unittest.TestCase):
    def test_parses_array(self):
        t = parse_masscan_json(MASSCAN_JSON)
        self.assertIn("https://10.0.0.1:2087", t)
        self.assertIn("http://10.0.0.2:80", t)

    def test_parses_ndjson_lines(self):
        t = parse_masscan_json('{"ip": "10.0.0.9", "ports": [{"port": 2087}]}\n'
                               '{"ip": "10.0.0.8", "ports": [{"port": 2086}]}\n')
        self.assertIn("https://10.0.0.9:2087", t)
        self.assertIn("http://10.0.0.8:2086", t)


class TestShodanNdjson(unittest.TestCase):
    def test_parses(self):
        t = parse_shodan_json(SHODAN_NDJSON)
        self.assertIn("https://10.0.0.1:2087", t)
        self.assertIn("https://10.0.0.2:2083", t)


class TestLoadListFile(unittest.TestCase):
    def _tmp(self, content, suffix=".txt"):
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as f:
            f.write(content)
            return f.name

    def test_plain_text(self):
        path = self._tmp("# comment\nhttps://a:2087\n\nb.example\n")
        try:
            self.assertEqual(load_list_file(path),
                             ["https://a:2087", "b.example"])
        finally:
            os.unlink(path)

    def test_auto_detect_xml(self):
        path = self._tmp(NMAP_XML, ".xml")
        try:
            self.assertIn("https://10.0.0.1:2087", load_list_file(path))
        finally:
            os.unlink(path)

    def test_auto_detect_masscan(self):
        path = self._tmp(MASSCAN_JSON, ".json")
        try:
            self.assertIn("https://10.0.0.1:2087", load_list_file(path))
        finally:
            os.unlink(path)

    def test_auto_detect_shodan(self):
        path = self._tmp(SHODAN_NDJSON, ".json")
        try:
            self.assertIn("https://10.0.0.1:2087", load_list_file(path))
        finally:
            os.unlink(path)

    def test_missing_file(self):
        self.assertEqual(load_list_file("/nonexistent/xyz.txt"), [])


class TestExclude(unittest.TestCase):
    def test_load_and_match(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("# comment\n10.0.0.1:2087\n")
            path = f.name
        try:
            excluded = load_exclude(path)
            self.assertTrue(is_excluded("https://10.0.0.1:2087", excluded))
            self.assertFalse(is_excluded("https://10.0.0.2:2087", excluded))
        finally:
            os.unlink(path)

    def test_empty(self):
        self.assertFalse(is_excluded("https://a:2087", set()))


if __name__ == "__main__":
    unittest.main()