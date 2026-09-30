from flask import Blueprint, jsonify, request

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
    status = request.args.get("status")
    severity = request.args.get("severity")

    query = Finding.query

    if status:
        query = query.filter(
            Finding.status == status
        )

    if severity:
        query = query.filter(
            Finding.severity == severity
        )

    findings = query.order_by(
        Finding.id.desc()
    ).all()

    return jsonify({
        "status": "success",
        "count": len(findings),
        "filters": {
            "status": status,
            "severity": severity
        },
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


@findings_bp.patch("/<int:finding_id>/status")
def update_finding_status(finding_id):
    finding = db.session.get(
        Finding,
        finding_id
    )

    if not finding:
        return jsonify({
            "status": "error",
            "message": "Finding not found"
        }), 404

    data = request.get_json()

    if not data:
        return jsonify({
            "status": "error",
            "message": "Request body is required"
        }), 400

    new_status = data.get("status")

    allowed_statuses = {
        "open",
        "resolved",
        "false_positive",
        "accepted_risk"
    }

    if new_status not in allowed_statuses:
        return jsonify({
            "status": "error",
            "message": "Invalid finding status",
            "allowed_statuses": sorted(allowed_statuses)
        }), 400

    finding.status = new_status

    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Finding status updated",
        "finding": finding_to_dict(finding)
    })
