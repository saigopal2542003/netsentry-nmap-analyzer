
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from netsentry.parser import parse_nmap_xml

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "sample_scan.xml"


class TestNmapParser(unittest.TestCase):

    def test_parses_hosts_and_ports(self):
        hosts = parse_nmap_xml(SAMPLE)
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]["ip"], "192.0.2.10")
        self.assertEqual(hosts[0]["hostname"], "lab-web")
        self.assertEqual(len(hosts[0]["ports"]), 3)

    def test_extracts_ssh_details(self):
        hosts = parse_nmap_xml(SAMPLE)
        ssh = next(p for p in hosts[0]["ports"] if p["port"] == 22)
        self.assertEqual(ssh["state"], "open")
        self.assertEqual(ssh["service"], "ssh")
        self.assertEqual(ssh["product"], "OpenSSH")
        self.assertEqual(ssh["version"], "9.6")

    def test_closed_port_remains_closed(self):
        hosts = parse_nmap_xml(SAMPLE)
        https = next(p for p in hosts[0]["ports"] if p["port"] == 443)
        self.assertEqual(https["state"], "closed")

    def test_missing_version_is_not_invented(self):
        hosts = parse_nmap_xml(SAMPLE)
        telnet = next(p for p in hosts[1]["ports"] if p["port"] == 23)
        self.assertEqual(telnet["service"], "telnet")
        self.assertEqual(telnet["version"], "")

    def test_malformed_xml(self):
        with TemporaryDirectory() as folder:
            bad_file = Path(folder) / "bad.xml"
            bad_file.write_text("<nmaprun><host>", encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_nmap_xml(bad_file)

    def test_wrong_xml_root(self):
        with TemporaryDirectory() as folder:
            bad_file = Path(folder) / "wrong.xml"
            bad_file.write_text("<root/>", encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_nmap_xml(bad_file)

    def test_missing_file(self):
        missing = ROOT / "samples" / "missing.xml"
        with self.assertRaises(FileNotFoundError):
            parse_nmap_xml(missing)


if __name__ == "__main__":
    unittest.main()
