from datetime import datetime

from backend.extensions import db


class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=False
    )

    host = db.Column(
        db.String(255),
        nullable=False
    )

    protocol = db.Column(
        db.String(20),
        nullable=False
    )

    port = db.Column(
        db.Integer,
        nullable=False
    )

    state = db.Column(
        db.String(30),
        nullable=False
    )

    service = db.Column(
        db.String(100),
        nullable=True
    )

    confidence = db.Column(
        db.Integer,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    scan = db.relationship(
        "Scan",
        backref=db.backref("results", lazy=True)
    )

    def __repr__(self):
        return f"<ScanResult {self.host}:{self.port}>"
