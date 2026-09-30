from flask import Blueprint, jsonify

from backend.models import Finding, Scan


dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    url_prefix="/api/dashboard"
)


@dashboard_bp.get("/summary")
def dashboard_summary():
    total_findings = Finding.query.count()

    open_findings = Finding.query.filter_by(
        status="open"
    ).count()

    resolved_findings = Finding.query.filter_by(
        status="resolved"
    ).count()

    false_positive_findings = Finding.query.filter_by(
        status="false_positive"
    ).count()

    accepted_risk_findings = Finding.query.filter_by(
        status="accepted_risk"
    ).count()

    critical_findings = Finding.query.filter_by(
        severity="critical"
    ).count()

    high_findings = Finding.query.filter_by(
        severity="high"
    ).count()

    medium_findings = Finding.query.filter_by(
        severity="medium"
    ).count()

    low_findings = Finding.query.filter_by(
        severity="low"
    ).count()

    info_findings = Finding.query.filter_by(
        severity="info"
    ).count()

    total_scans = Scan.query.count()

    completed_scans = Scan.query.filter_by(
        status="completed"
    ).count()

    failed_scans = Scan.query.filter_by(
        status="failed"
    ).count()

    return jsonify({
        "status": "success",
        "summary": {
            "findings": {
                "total": total_findings,
                "open": open_findings,
                "resolved": resolved_findings,
                "false_positive": false_positive_findings,
                "accepted_risk": accepted_risk_findings
            },
            "severity": {
                "critical": critical_findings,
                "high": high_findings,
                "medium": medium_findings,
                "low": low_findings,
                "info": info_findings
            },
            "scans": {
                "total": total_scans,
                "completed": completed_scans,
                "failed": failed_scans
            }
        }
    })
