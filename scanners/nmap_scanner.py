from urllib.parse import urlparse
import subprocess


def normalize_target(target):
    if "://" not in target:
        return target, None

    parsed = urlparse(target)

    if not parsed.hostname:
        raise ValueError("Invalid target URL")

    return parsed.hostname, parsed.port


def run_nmap(target):
    host, port = normalize_target(target)

    command = [
        "nmap",
        "-sV",
        "-Pn",
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

    return {
        "target": target,
        "host": host,
        "port": port,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
