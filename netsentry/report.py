
"""Generate a Markdown report from NetSentry analysis results."""

from datetime import datetime, timezone
from pathlib import Path


def generate_report(hosts, findings, input_file):
    """Return a Markdown report as a string."""

    host_count = len(hosts)
    open_port_count = sum(
        1
        for host in hosts
        for port in host.get("ports", [])
        if port.get("state") == "open"
    )

    high_review_count = sum(
        1 for finding in findings
        if finding["priority"] == "HIGH REVIEW"
    )

    lines = [
        "# NetSentry Security Review Report",
        "",
        f"- Generated (UTC): {datetime.now(timezone.utc).isoformat()}",
        f"- Input file: `{Path(input_file).name}`",
        "",
        "## Summary",
        "",
        f"- Hosts analyzed: {host_count}",
        f"- Open ports identified: {open_port_count}",
        f"- Findings requiring review: {len(findings)}",
        f"- High review priority: {high_review_count}",
        "",
        "## Host Inventory",
        "",
    ]

    for host in hosts:
        hostname = host.get("hostname") or "Not provided"
        lines.extend([
            f"### {host.get('ip', 'unknown')} ({hostname})",
            "",
            f"- Host status: {host.get('status', 'unknown')}",
            "",
            "| Port | State | Service | Version |",
            "|---|---|---|---|",
        ])

        for port in host.get("ports", []):
            version = port.get("version") or "Not provided"
            service = port.get("service") or "unknown"

            lines.append(
                f"| {port.get('port', 'unknown')}/"
                f"{port.get('protocol', 'unknown')} | "
                f"{port.get('state', 'unknown')} | "
                f"{service} | {version} |"
            )

        lines.append("")

    lines.extend(["## Findings", ""])

    if not findings:
        lines.append("No open-service review findings were identified.")
        lines.append("")
    else:
        for index, finding in enumerate(findings, start=1):
            lines.extend([
                f"### {index}. {finding['title']}",
                "",
                f"- Priority: **{finding['priority']}**",
                f"- Host: {finding['host']}",
                f"- Port: {finding['port']}/{finding['protocol']}",
                f"- Service: {finding['service']}",
                f"- Version: {finding.get('version') or 'Not provided'}",
                f"- Reason: {finding['reason']}",
                f"- Recommended verification: {finding['recommendation']}",
                "",
            ])

    lines.extend([
        "## Limitations",
        "",
        "- An open port does not by itself prove a vulnerability.",
        "- Review priorities are rule-based triage labels, not CVSS scores.",
        "- Service versions may be missing or inaccurate in scan data.",
        "- Findings require manual verification and context.",
        "- This report does not establish exploitability.",
        "",
    ])

    return "\n".join(lines)


def save_report(report_text, output_file):
    """Save the report as UTF-8 Markdown."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_text + "\n", encoding="utf-8")
    return output_path
