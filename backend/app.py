import os

from flask import Flask, jsonify
from dotenv import load_dotenv

from backend.extensions import db
from backend.routes.targets import targets_bp
from backend.routes.scans import scans_bp


load_dotenv()


def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.getenv(
        "SECRET_KEY",
        "development-secret"
    )

    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL",
        "sqlite:///cybershield.db"
    )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    app.register_blueprint(targets_bp)
    app.register_blueprint(scans_bp)

    @app.get("/health")
    def health():
        return jsonify(
            {
                "status": "healthy",
                "service": "CyberShield API"
            }
        )

    return app


app = create_app()


