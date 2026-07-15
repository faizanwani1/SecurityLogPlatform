from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    full_name = db.Column(db.String(150))

    email = db.Column(db.String(150))

    role = db.Column(
        db.String(50),
        default="analyst"
    )

    status = db.Column(
        db.String(20),
        default="Active"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class LogEntry(db.Model):
    __tablename__ = "logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    timestamp = db.Column(
        db.String(100)
    )

    source_ip = db.Column(
        db.String(100)
    )

    event_type = db.Column(
        db.String(100)
    )

    severity = db.Column(
        db.String(20)
    )

    message = db.Column(
        db.Text
    )

    filename = db.Column(
        db.String(255)
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    timestamp = db.Column(
        db.String(100)
    )

    ip_address = db.Column(
        db.String(100)
    )

    event_type = db.Column(
        db.String(100)
    )

    severity = db.Column(
        db.String(20)
    )

    status = db.Column(
        db.String(20),
        default="Open"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class Incident(db.Model):
    __tablename__ = "incidents"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(255)
    )

    description = db.Column(
        db.Text
    )

    severity = db.Column(
        db.String(20)
    )

    status = db.Column(
        db.String(50),
        default="Open"
    )

    assigned_to = db.Column(
        db.String(100)
    )

    source_ip = db.Column(
        db.String(100)
    )

    event_type = db.Column(
        db.String(100)
    )

    investigation_notes = db.Column(
        db.Text
    )

    containment = db.Column(
        db.Text
    )

    remediation = db.Column(
        db.Text
    )

    recovery = db.Column(
        db.Text
    )

    resolution_notes = db.Column(
        db.Text
    )

    lessons_learned = db.Column(
        db.Text
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )
class UploadedFile(db.Model):
    __tablename__ = "uploaded_files"

    id = db.Column(db.Integer, primary_key=True)

    filename = db.Column(db.String(255))

    log_type = db.Column(db.String(50))

    upload_date = db.Column(db.DateTime)