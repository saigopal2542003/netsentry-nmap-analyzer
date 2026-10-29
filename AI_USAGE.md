# AI Usage Disclosure — NetSentry

## Purpose

AI assistance was used as a learning and development aid while building NetSentry, a Python-based analyzer for existing Nmap XML scan results.

## Areas Where AI Assisted

- Suggested the project structure and implementation sequence.
- Helped develop and explain XML parsing logic.
- Assisted with rule-based security review logic for open services.
- Helped design Markdown report generation.
- Suggested unit tests for parsing, analysis, report generation, and error handling.
- Helped troubleshoot development workflow and Git setup.
- Assisted with drafting project documentation.

## Developer Responsibilities

I created and tested the project in my local development environment. I reviewed the generated code, ran the application against the included sample XML, and executed the unit test suite. I am responsible for understanding, validating, and explaining the submitted implementation.

## Validation

- Executed NetSentry using the included synthetic Nmap XML sample.
- Verified that the tool generated a Markdown report.
- Ran the automated unit tests; 18 tests passed at the time of validation.
- Reviewed the report's limitations and ensured that open ports are described as review items rather than confirmed vulnerabilities.

## Limitations

AI assistance does not guarantee that code is correct or secure. The tool uses transparent, rule-based checks and does not independently confirm exploitability. Findings require manual verification and appropriate authorization.
