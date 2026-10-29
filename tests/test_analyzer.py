
import unittest
from pathlib import Path

from netsentry.parser import parse_nmap_xml
from netsentry.analyzer import analyze_hosts


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "sample_scan.xml"


class TestSecurityAnalyzer(unittest.TestCase):

    def setUp(self):
        self.hosts = parse_nmap_xml(SAMPLE)
        self.findings = analyze_hosts(self.hosts)

    def test_open_services_are_reported(self):
        # Three open ports: 22, 80 and 23.
        self.assertEqual(len(self.findings), 3)

    def test_telnet_gets_high_review_priority(self):
        telnet = next(
            f for f in self.findings if f["port"] == 23
        )
        self.assertEqual(telnet["priority"], "HIGH REVIEW")
        self.assertIn("encryption", telnet["reason"].lower())

    def test_ssh_is_not_called_a_confirmed_vulnerability(self):
        ssh = next(
            f for f in self.findings if f["port"] == 22
        )
        self.assertEqual(ssh["priority"], "REVIEW")
        self.assertIn("not a vulnerability", ssh["reason"].lower())

    def test_closed_https_port_is_not_reported(self):
        ports = [finding["port"] for finding in self.findings]
        self.assertNotIn(443, ports)

    def test_findings_include_recommendations(self):
        for finding in self.findings:
            self.assertTrue(finding["reason"])
            self.assertTrue(finding["recommendation"])

    def test_empty_input_returns_no_findings(self):
        self.assertEqual(analyze_hosts([]), [])


if __name__ == "__main__":
    unittest.main()
