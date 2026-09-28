from urllib.parse import urlparse
import subprocess


def normalize_target(target):
    if "://" not in target:
        return target

    parsed = urlparse(target)

    if not parsed.hostname:
        raise ValueError("Invalid target URL")

    return parsed.hostname


def run_nmap(target):
    host = normalize_target(target)

    command = [
        "nmap",
        "-sV",
        "-Pn",
        host
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=120
    )

    return {
        "target": target,
        "host": host,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
