
"""Parse host and port information from an Nmap XML file."""

import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap_xml(file_path):
    """Parse Nmap XML and return host and port details."""
    path = Path(file_path)

    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML in '{path}': {exc}") from exc

    root = tree.getroot()

    if root.tag != "nmaprun":
        raise ValueError("Input XML is not an Nmap XML document.")

    hosts = []

    for host_element in root.findall("host"):
        address_element = host_element.find(
            "address[@addrtype='ipv4']"
        )

        if address_element is None:
            address_element = host_element.find("address")

        ip_address = (
            address_element.get("addr", "unknown")
            if address_element is not None
            else "unknown"
        )

        hostname_element = host_element.find("hostnames/hostname")
        hostname = (
            hostname_element.get("name", "")
            if hostname_element is not None
            else ""
        )

        status_element = host_element.find("status")
        host_status = (
            status_element.get("state", "unknown")
            if status_element is not None
            else "unknown"
        )

        ports = []

        for port_element in host_element.findall("ports/port"):
            state_element = port_element.find("state")
            service_element = port_element.find("service")

            service = (
                service_element.attrib
                if service_element is not None
                else {}
            )

            ports.append({
                "protocol": port_element.get("protocol", "unknown"),
                "port": int(port_element.get("portid")),
                "state": (
                    state_element.get("state", "unknown")
                    if state_element is not None
                    else "unknown"
                ),
                "service": service.get("name", "unknown"),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
            })

        hosts.append({
            "ip": ip_address,
            "hostname": hostname,
            "status": host_status,
            "ports": ports,
        })

    return hosts
