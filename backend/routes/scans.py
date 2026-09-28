from datetime import datetime

from flask import Blueprint, jsonify, request

from backend.extensions import db
from backend.models import Scan, ScanResult, Target
from scanners.nmap_scanner import run_nmap


scans_bp = Blueprint("scans", __name__, url_prefix="/api/scans")


@scans_bp.post("/")
def create_scan():
    data = request.get_json()

    if not data:
        return jsonify(
            {
                "status": "error",
                "message": "JSON body is required"
            }
        ), 400

    target_id = data.get("target_id")

    if not target_id:
        return jsonify(
            {
                "status": "error",
                "message": "target_id is required"
            }
        ), 400

    target = db.session.get(Target, target_id)

    if not target:
        return jsonify(
            {
                "status": "error",
                "message": "Target not found"
            }
        ), 404

    scan = Scan(
        target_id=target.id,
        scan_type=data.get("scan_type", "full"),
        status="pending"
    )

    db.session.add(scan)
    db.session.commit()

    try:
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.session.commit()

        result = run_nmap(target.value)

        if result["return_code"] != 0:
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            db.session.commit()

            return jsonify(
                {
                    "status": "error",
                    "message": "Nmap scan failed",
                    "scan_id": scan.id,
                    "error": result["stderr"]
                }
            ), 500

        for item in result["results"]:
            scan_result = ScanResult(
                scan_id=scan.id,
                host=item["host"],
                protocol=item["protocol"],
                port=item["port"],
                state=item["state"],
                service=item["service"],
                confidence=item["confidence"]
            )

            db.session.add(scan_result)

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()

        db.session.commit()

    except Exception as exc:
        db.session.rollback()

        scan.status = "failed"
        scan.completed_at = datetime.utcnow()

        db.session.commit()

        return jsonify(
            {
                "status": "error",
                "message": "Scan execution failed",
                "scan_id": scan.id,
                "error": str(exc)
            }
        ), 500

    return jsonify(
        {
            "status": "success",
            "message": "Scan completed successfully",
            "scan": {
                "id": scan.id,
                "target_id": scan.target_id,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "results_count": len(result["results"])
            }
        }
    ), 201


@scans_bp.get("/")
def get_scans():
    scans = Scan.query.order_by(Scan.id.desc()).all()

    return jsonify(
        {
            "status": "success",
            "count": len(scans),
            "scans": [
                {
                    "id": scan.id,
                    "target_id": scan.target_id,
                    "target_name": scan.target.name,
                    "target_value": scan.target.value,
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "started_at": scan.started_at,
                    "completed_at": scan.completed_at,
                    "created_at": scan.created_at,
                }
                for scan in scans
            ],
        }
    )


@scans_bp.patch("/<int:scan_id>/status")
def update_scan_status(scan_id):
    scan = db.session.get(Scan, scan_id)

    if not scan:
        return jsonify(
            {
                "status": "error",
                "message": "Scan not found"
            }
        ), 404

    data = request.get_json()

    if not data:
        return jsonify(
            {
                "status": "error",
                "message": "JSON body is required"
            }
        ), 400

    new_status = data.get("status")

    allowed_statuses = [
        "pending",
        "running",
        "completed",
        "failed"
    ]

    if new_status not in allowed_statuses:
        return jsonify(
            {
                "status": "error",
                "message": "Invalid scan status"
            }
        ), 400

    scan.status = new_status

    if new_status == "running" and scan.started_at is None:
        scan.started_at = datetime.utcnow()

    if new_status in ["completed", "failed"]:
        scan.completed_at = datetime.utcnow()

    db.session.commit()

    return jsonify(
        {
            "status": "success",
            "message": "Scan status updated successfully",
            "scan": {
                "id": scan.id,
                "target_id": scan.target_id,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at
            }
        }
    )
