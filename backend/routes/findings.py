from flask import Blueprint, jsonify
from backend.extensions import db
from backend.models import Finding

findings_bp = Blueprint(
    "findings",
    __name__,
    url_prefix="/api/findings"
)


def finding_to_dict(finding):
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "title": finding.title,
        "severity": finding.severity,
        "description": finding.description,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "cwe_id": finding.cwe_id,
        "cvss_score": finding.cvss_score,
        "status": finding.status,
        "fingerprint": finding.fingerprint,
        "created_at": finding.created_at,
        "updated_at": finding.updated_at,
    }


@findings_bp.get("/")
def get_findings():
    findings = Finding.query.order_by(
        Finding.id.desc()
    ).all()

    return jsonify({
        "status": "success",
        "count": len(findings),
        "findings": [
            finding_to_dict(finding)
            for finding in findings
        ]
    })


@findings_bp.get("/<int:finding_id>")
def get_finding(finding_id):
    finding = db.session.get(
        Finding,
        finding_id
    )

    if not finding:
        return jsonify({
            "status": "error",
            "message": "Finding not found"
        }), 404

    return jsonify({
        "status": "success",
        "finding": finding_to_dict(finding)
    })