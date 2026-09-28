import hashlib

from backend.extensions import db
from backend.models import Finding, Scan, ScanResult
from backend.services.http_detector import detect_http_service


def generate_fingerprint(
    target_id,
    host,
    port,
    title,
    cwe_id=None,
    extra=None
):
    """
    Generate a stable fingerprint for a security finding.

    scan_id is intentionally excluded so the same issue
    across multiple scans uses the same finding.
    """

    parts = [
        str(target_id),
        str(host),
        str(port),
        title.strip().lower(),
        str(cwe_id or ""),
        str(extra or "").strip().lower(),
    ]

    raw_value = "|".join(parts)

    return hashlib.sha256(
        raw_value.encode("utf-8")
    ).hexdigest()


def create_or_update_finding(
    scan_id,
    target_id,
    host,
    port,
    title,
    severity,
    description,
    evidence,
    remediation,
    cwe_id=None,
    cvss_score=None,
    fingerprint_extra=None,
):
    """
    Create a new finding or update an existing finding.
    """

    fingerprint = generate_fingerprint(
        target_id=target_id,
        host=host,
        port=port,
        title=title,
        cwe_id=cwe_id,
        extra=fingerprint_extra,
    )

    finding = Finding.query.filter_by(
        fingerprint=fingerprint
    ).first()

    if finding:
        finding.scan_id = scan_id
        finding.severity = severity
        finding.description = description
        finding.evidence = evidence
        finding.remediation = remediation
        finding.cwe_id = cwe_id
        finding.cvss_score = cvss_score
        finding.status = "open"

        return finding, False

    finding = Finding(
        scan_id=scan_id,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe_id=cwe_id,
        cvss_score=cvss_score,
        status="open",
        fingerprint=fingerprint,
    )

    db.session.add(finding)

    return finding, True


def analyze_scan_results(scan_id):
    """
    Analyze scan results and create, update, or resolve findings.

    Findings are resolved only within the target being scanned.

    Intended for authorized security assessments and local labs.
    """

    scan = db.session.get(Scan, scan_id)

    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    target_id = scan.target_id

    results = ScanResult.query.filter_by(
        scan_id=scan_id
    ).all()

    findings_created = []
    detected_fingerprints = set()

    for result in results:

        if result.state != "open":
            continue

        service = (result.service or "").lower()

        # ---------------------------------------------------------
        # HTTP SERVICE DETECTION
        # ---------------------------------------------------------

        http_result = detect_http_service(
            result.host,
            result.port
        )

        if http_result["is_http"]:

            headers = http_result["headers"]

            security_headers = {
                "x-content-type-options": "X-Content-Type-Options",
                "x-frame-options": "X-Frame-Options",
                "content-security-policy": "Content-Security-Policy",
                "strict-transport-security": "Strict-Transport-Security",
            }

            missing_headers = []

            for header_key, header_name in security_headers.items():
                if header_key not in headers:
                    missing_headers.append(header_name)

            if missing_headers:

                title = "Missing HTTP Security Headers"

                fingerprint_extra = ",".join(
                    sorted(missing_headers)
                )

                fingerprint = generate_fingerprint(
                    target_id=target_id,
                    host=result.host,
                    port=result.port,
                    title=title,
                    cwe_id="CWE-693",
                    extra=fingerprint_extra,
                )

                detected_fingerprints.add(fingerprint)

                finding, created = create_or_update_finding(
                    scan_id=scan_id,
                    target_id=target_id,
                    host=result.host,
                    port=result.port,
                    title=title,
                    severity="medium",
                    description=(
                        "One or more recommended HTTP security headers "
                        "are missing from the web application response."
                    ),
                    evidence=(
                        f"URL: {http_result['url']}\n"
                        f"Status Code: {http_result['status_code']}\n"
                        f"Missing Headers: "
                        f"{', '.join(missing_headers)}"
                    ),
                    remediation=(
                        "Configure the web server or application to send "
                        "appropriate security headers. Review each missing "
                        "header based on the application's requirements."
                    ),
                    cwe_id="CWE-693",
                    fingerprint_extra=fingerprint_extra,
                )

                if created:
                    findings_created.append(finding)

        # ---------------------------------------------------------
        # DATABASE SERVICE DETECTION
        # ---------------------------------------------------------

        database_services = {
            "mysql",
            "microsoft-sql-s",
            "postgresql",
            "mongodb",
            "redis",
        }

        if service in database_services:

            title = (
                f"Exposed Database Service on Port "
                f"{result.port}"
            )

            fingerprint = generate_fingerprint(
                target_id=target_id,
                host=result.host,
                port=result.port,
                title=title,
                cwe_id="CWE-284",
            )

            detected_fingerprints.add(fingerprint)

            finding, created = create_or_update_finding(
                scan_id=scan_id,
                target_id=target_id,
                host=result.host,
                port=result.port,
                title=title,
                severity="high",
                description=(
                    f"A database service ({result.service}) was detected "
                    f"on {result.host}:{result.port}. Exposed database "
                    "services can increase the attack surface if they are "
                    "not properly restricted."
                ),
                evidence=(
                    f"Host: {result.host}\n"
                    f"Protocol: {result.protocol}\n"
                    f"Port: {result.port}\n"
                    f"Service: {result.service}\n"
                    f"State: {result.state}"
                ),
                remediation=(
                    "Restrict database services to trusted networks, "
                    "use firewall rules, disable unnecessary exposure, "
                    "and require strong authentication."
                ),
                cwe_id="CWE-284",
            )

            if created:
                findings_created.append(finding)

        # ---------------------------------------------------------
        # INSECURE REMOTE SERVICE DETECTION
        # ---------------------------------------------------------

        remote_services = {
            "telnet",
            "ftp",
            "rsh",
            "rlogin",
        }

        if service in remote_services:

            title = (
                f"Potentially Insecure Remote Service "
                f"on Port {result.port}"
            )

            fingerprint = generate_fingerprint(
                target_id=target_id,
                host=result.host,
                port=result.port,
                title=title,
                cwe_id="CWE-319",
            )

            detected_fingerprints.add(fingerprint)

            finding, created = create_or_update_finding(
                scan_id=scan_id,
                target_id=target_id,
                host=result.host,
                port=result.port,
                title=title,
                severity="medium",
                description=(
                    f"The service {result.service} was detected on "
                    f"{result.host}:{result.port}. Legacy or insecure "
                    "remote services may expose credentials or increase "
                    "the attack surface."
                ),
                evidence=(
                    f"Host: {result.host}\n"
                    f"Protocol: {result.protocol}\n"
                    f"Port: {result.port}\n"
                    f"Service: {result.service}\n"
                    f"State: {result.state}"
                ),
                remediation=(
                    "Disable the service if it is not required. "
                    "If remote administration is necessary, use a "
                    "secure alternative such as SSH and restrict access."
                ),
                cwe_id="CWE-319",
            )

            if created:
                findings_created.append(finding)

    # -------------------------------------------------------------
    # RESOLVE FINDINGS NOT DETECTED IN THIS SCAN
    # ONLY FOR THE CURRENT TARGET
    # -------------------------------------------------------------

    existing_findings = (
        Finding.query
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Finding.status == "open",
            Scan.target_id == target_id
        )
        .all()
    )

    for finding in existing_findings:

        if finding.fingerprint is None:
            continue

        if finding.fingerprint not in detected_fingerprints:
            finding.status = "resolved"
            finding.scan_id = scan_id

    db.session.commit()

    return findings_created