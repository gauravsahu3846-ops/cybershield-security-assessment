from flask import Blueprint, jsonify, request

from backend.extensions import db
from backend.models import Target

targets_bp = Blueprint("targets", __name__, url_prefix="/api/targets")


@targets_bp.get("/")
def get_targets():
    targets = Target.query.order_by(Target.id.desc()).all()

    return jsonify(
        {
            "status": "success",
            "count": len(targets),
            "targets": [
                {
                    "id": target.id,
                    "name": target.name,
                    "target_type": target.target_type,
                    "value": target.value,
                    "description": target.description,
                    "is_active": target.is_active,
                }
                for target in targets
            ],
        }
    )


@targets_bp.post("/")
def create_target():
    data = request.get_json()

    if not data:
        return jsonify(
            {
                "status": "error",
                "message": "JSON body is required"
            }
        ), 400

    required_fields = ["name", "target_type", "value"]

    for field in required_fields:
        if not data.get(field):
            return jsonify(
                {
                    "status": "error",
                    "message": f"{field} is required"
                }
            ), 400

    target = Target(
        name=data["name"],
        target_type=data["target_type"],
        value=data["value"],
        description=data.get("description"),
        is_active=data.get("is_active", True),
    )

    db.session.add(target)
    db.session.commit()

    return jsonify(
        {
            "status": "success",
            "message": "Target created successfully",
            "target": {
                "id": target.id,
                "name": target.name,
                "target_type": target.target_type,
                "value": target.value,
                "description": target.description,
                "is_active": target.is_active,
            },
        }
    ), 201
@targets_bp.delete("/<int:target_id>")
def delete_target(target_id):
    target = db.session.get(Target, target_id)

    if not target:
        return jsonify(
            {
                "status": "error",
                "message": "Target not found"
            }
        ), 404

    db.session.delete(target)
    db.session.commit()

    return jsonify(
        {
            "status": "success",
            "message": "Target deleted successfully",
            "id": target_id
        }
    )
@targets_bp.patch("/<int:target_id>")
def update_target(target_id):
    target = db.session.get(Target, target_id)

    if not target:
        return jsonify(
            {
                "status": "error",
                "message": "Target not found"
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

    if "name" in data:
        target.name = data["name"]

    if "target_type" in data:
        target.target_type = data["target_type"]

    if "value" in data:
        target.value = data["value"]

    if "description" in data:
        target.description = data["description"]

    if "is_active" in data:
        target.is_active = data["is_active"]

    db.session.commit()

    return jsonify(
        {
            "status": "success",
            "message": "Target updated successfully",
            "target": {
                "id": target.id,
                "name": target.name,
                "target_type": target.target_type,
                "value": target.value,
                "description": target.description,
                "is_active": target.is_active,
            },
        }
    )
