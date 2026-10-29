
"""Apply transparent security review rules to parsed Nmap data."""

def analyze_hosts(hosts):
    """Return review findings for open services only.

    These rules identify items to review, not confirmed vulnerabilities.
    """
    findings = []

    for host in hosts:
        for port in host.get("ports", []):
            # Closed or filtered ports are not treated as open services.
            if port.get("state") != "open":
                continue

            service = (port.get("service") or "unknown").lower()
            port_number = port.get("port")
            protocol = port.get("protocol", "unknown")

            finding = None

            if service == "telnet" or port_number == 23:
                finding = {
                    "priority": "HIGH REVIEW",
                    "title": "Telnet service exposed",
                    "reason": (
                        "Telnet commonly transmits session data without "
                        "transport encryption. The scan alone does not "
                        "prove how this service is configured."
                    ),
                    "recommendation": (
                        "Confirm whether remote access is required. "
                        "Check the service configuration and prefer "
                        "SSH or another appropriately secured alternative."
                    ),
                }

            elif service == "ssh" or port_number == 22:
                finding = {
                    "priority": "REVIEW",
                    "title": "SSH service exposed",
                    "reason": (
                        "SSH is commonly used for secure remote access. "
                        "An open SSH port alone is not a vulnerability."
                    ),
                    "recommendation": (
                        "Confirm that remote access is intended and review "
                        "exposure, authentication policy and access controls."
                    ),
                }

            elif service in {"http", "https"} or port_number in {80, 443}:
                finding = {
                    "priority": "REVIEW",
                    "title": "Web service exposed",
                    "reason": (
                        "An open web service may be expected. The scan "
                        "does not establish whether its configuration "
                        "or transport security is adequate."
                    ),
                    "recommendation": (
                        "Confirm that the service should be reachable. "
                        "Review HTTPS configuration, redirects and "
                        "application security where applicable."
                    ),
                }

            else:
                finding = {
                    "priority": "REVIEW",
                    "title": "Open service requires review",
                    "reason": (
                        "An open service was detected, but the supplied "
                        "scan data is insufficient to determine whether "
                        "it represents a security weakness."
                    ),
                    "recommendation": (
                        "Confirm the service identity, business need, "
                        "network exposure and security configuration."
                    ),
                }

            findings.append({
                "host": host.get("ip", "unknown"),
                "hostname": host.get("hostname", ""),
                "port": port_number,
                "protocol": protocol,
                "service": service,
                "version": port.get("version", ""),
                **finding,
            })

    return findings
