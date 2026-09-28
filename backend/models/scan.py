from datetime import datetime

from backend.extensions import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)

    target_id = db.Column(
        db.Integer,
        db.ForeignKey("targets.id"),
        nullable=False
    )

    scan_type = db.Column(
        db.String(50),
        nullable=False,
        default="full"
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="pending"
    )

    started_at = db.Column(
        db.DateTime,
        nullable=True
    )

    completed_at = db.Column(
        db.DateTime,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    target = db.relationship(
        "Target",
        backref=db.backref("scans", lazy=True)
    )

    def __repr__(self):
        return f"<Scan {self.id} - {self.status}>"
