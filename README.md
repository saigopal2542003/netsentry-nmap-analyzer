# NetSentry — Nmap XML Security Analyzer

NetSentry is a Python-based cybersecurity tool that parses existing Nmap XML scan results, identifies open services that may require security review, and generates a Markdown report with findings and recommendations.

## Features

- Parses Nmap XML scan files.
- Extracts host addresses, hostnames, port states, services, and available version information.
- Identifies open services using transparent, rule-based checks.
- Highlights Telnet as a high-priority review item.
- Generates a Markdown report with a host inventory, findings, recommendations, and limitations.
- Handles missing files and invalid XML with readable errors.
- Includes automated unit tests.

## Technology Stack

- Python
- Nmap XML
- XML parsing with Python's standard library
- `unittest` for automated testing
- Git for version control

## Project Structure

```text
netsentry/
├── main.py
├── netsentry/
│   ├── parser.py
│   ├── analyzer.py
│   └── report.py
├── tests/
│   ├── test_parser.py
│   ├── test_analyzer.py
│   └── test_report.py
├── samples/
│   └── sample_scan.xml
├── reports/
├── README.md
├── AI_USAGE.md
└── .gitignore
```

## Requirements

- Python 3.10 or newer
- An Nmap XML scan file
- No third-party Python packages are currently required.

## Usage

Run NetSentry against an existing Nmap XML file:

```powershell
python main.py --input samples/sample_scan.xml --output reports/report.md
```

To display available command-line options:

```powershell
python main.py --help
```

The generated Markdown report is saved to the output path supplied with `--output`.

## How It Works

1. **Parsing:** Reads the Nmap XML file and extracts hosts, ports, states, and service information.
2. **Analysis:** Applies transparent rules to open services.
3. **Reporting:** Generates a Markdown report containing an inventory, findings, recommendations, and limitations.
4. **Testing:** Uses Python's `unittest` framework to verify parsing, analysis, and report generation.

## Example Results

Using the included synthetic sample scan, NetSentry analyzes two hosts and identifies three open ports:

- TCP/22 — SSH
- TCP/80 — HTTP
- TCP/23 — Telnet

The tool produces three review findings. Telnet receives a high-priority review label because it commonly lacks transport encryption.

## Testing

Run all unit tests with:

```powershell
python -m unittest discover -s tests -v
```

The current test suite contains 18 tests covering XML parsing, service analysis, report generation, invalid input, and report limitations.

## Limitations

- An open port does not automatically indicate a vulnerability.
- Findings are rule-based review recommendations, not confirmed vulnerabilities.
- Review priorities are not CVSS scores.
- Service version information may be absent or inaccurate.
- Results require manual verification and environmental context.
- NetSentry analyzes existing scan files; it does not perform network scans itself.

## Authorized Use

Use Nmap and NetSentry only on systems you own or are explicitly authorized to assess.

## Future Improvements

- Add configurable analysis rules.
- Add JSON report output.
- Improve service identification and severity explanations.
- Add command-line options for filtering hosts and services.
