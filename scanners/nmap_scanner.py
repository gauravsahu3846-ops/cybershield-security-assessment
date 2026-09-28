from urllib.parse import urlparse
import subprocess
import xml.etree.ElementTree as ET


def normalize_target(target):
    if "://" not in target:
        return target, None

    parsed = urlparse(target)

    if not parsed.hostname:
        raise ValueError("Invalid target URL")

    return parsed.hostname, parsed.port


def parse_nmap_xml(xml_output):
    root = ET.fromstring(xml_output)

    results = []

    for host in root.findall("host"):
        address_element = host.find("address")

        if address_element is None:
            continue

        host_address = address_element.get("addr")

        ports_element = host.find("ports")

        if ports_element is None:
            continue

        for port in ports_element.findall("port"):
            state = port.find("state")
            service = port.find("service")

            results.append(
                {
                    "host": host_address,
                    "protocol": port.get("protocol"),
                    "port": int(port.get("portid")),
                    "state": state.get("state") if state is not None else None,
                    "service": (
                        service.get("name")
                        if service is not None
                        else None
                    ),
                    "confidence": (
                        int(service.get("conf"))
                        if service is not None and service.get("conf")
                        else None
                    ),
                }
            )

    return results


def run_nmap(target):
    host, port = normalize_target(target)

    command = [
        "nmap",
        "-sV",
        "-Pn",
        "-oX",
        "-",
    ]

    if port:
        command.extend(["-p", str(port)])

    command.append(host)

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=120
    )

    parsed_results = []

    if result.returncode == 0 and result.stdout:
        parsed_results = parse_nmap_xml(result.stdout)

    return {
        "target": target,
        "host": host,
        "port": port,
        "return_code": result.returncode,
        "results": parsed_results,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
