from datetime import datetime

from backend.extensions import db


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=False
    )

    title = db.Column(
        db.String(255),
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="info"
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    evidence = db.Column(
        db.Text,
        nullable=True
    )

    remediation = db.Column(
        db.Text,
        nullable=True
    )

    cwe_id = db.Column(
        db.String(30),
        nullable=True
    )

    cvss_score = db.Column(
        db.Float,
        nullable=True
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="open"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    scan = db.relationship(
        "Scan",
        backref=db.backref("findings", lazy=True)
    )

    def __repr__(self):
        return f"<Finding {self.id} - {self.title}>"
