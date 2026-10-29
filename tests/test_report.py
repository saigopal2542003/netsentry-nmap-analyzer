
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from netsentry.parser import parse_nmap_xml
from netsentry.analyzer import analyze_hosts
from netsentry.report import generate_report, save_report


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "sample_scan.xml"


class TestReport(unittest.TestCase):

    def setUp(self):
        self.hosts = parse_nmap_xml(SAMPLE)
        self.findings = analyze_hosts(self.hosts)
        self.report = generate_report(
            self.hosts,
            self.findings,
            SAMPLE,
        )

    def test_report_contains_summary(self):
        self.assertIn("# NetSentry Security Review Report", self.report)
        self.assertIn("Hosts analyzed: 2", self.report)
        self.assertIn("Open ports identified: 3", self.report)

    def test_report_contains_findings_and_limitations(self):
        self.assertIn("Telnet service exposed", self.report)
        self.assertIn(
            "does not by itself prove a vulnerability",
            self.report,
        )

    def test_closed_port_is_in_inventory(self):
        self.assertIn("443/tcp | closed", self.report)

    def test_report_can_be_saved(self):
        with TemporaryDirectory() as folder:
            output = Path(folder) / "nested" / "report.md"
            saved_path = save_report(self.report, output)

            self.assertTrue(saved_path.exists())
            self.assertEqual(
                saved_path.read_text(encoding="utf-8"),
                self.report + "\n",
            )

    def test_empty_results_are_reported(self):
        report = generate_report([], [], "empty.xml")
        self.assertIn("Hosts analyzed: 0", report)
        self.assertIn("No open-service review findings", report)


if __name__ == "__main__":
    unittest.main()
