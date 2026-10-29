"""Command-line interface for NetSentry."""

import argparse
import sys

from netsentry.parser import parse_nmap_xml
from netsentry.analyzer import analyze_hosts
from netsentry.report import generate_report, save_report


def main():
    parser = argparse.ArgumentParser(
        description="Analyze an existing Nmap XML scan and generate a report."
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to the input Nmap XML file",
    )
    parser.add_argument(
        "--output",
        default="reports/netsentry_report.md",
        help="Path for the Markdown report",
    )

    args = parser.parse_args()

    try:
        hosts = parse_nmap_xml(args.input)
        findings = analyze_hosts(hosts)

        report_text = generate_report(hosts, findings, args.input)
        output_path = save_report(report_text, args.output)

    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    open_ports = sum(
        1
        for host in hosts
        for port in host.get("ports", [])
        if port.get("state") == "open"
    )

    print("NetSentry analysis completed.")
    print(f"Hosts analyzed: {len(hosts)}")
    print(f"Open ports identified: {open_ports}")
    print(f"Findings requiring review: {len(findings)}")
    print(f"Report saved to: {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

