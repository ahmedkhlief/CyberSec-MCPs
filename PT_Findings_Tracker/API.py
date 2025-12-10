#!/usr/bin/env python3
"""
app.py — Pentest API (single-file PoC)
- Auth (JWT) with simple SHA256 hashing (replace with bcrypt in prod)
- Entities: Projects, Users, Targets, Commands, Findings, Notes, Evidence
- Recon: Services (per port), Vulnerabilities, ExploitAttempts, ServiceNotes
- Idempotency via external_id / dedupe_key
- Bulk upsert for services & vulnerabilities
- Simple search endpoints
"""

import os
from uuid import uuid4
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory, g, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
# Authentication removed: no JWT imports
from marshmallow import Schema, fields, validate, ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func
from werkzeug.exceptions import HTTPException
import logging
import time

# -------------------------
# Config & setup
# -------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'LLM-allattack-test1_fresh.db')}")
# Authentication removed: no JWT configuration

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_DIR"] = UPLOAD_DIR

db = SQLAlchemy(app)
migrate = Migrate(app, db)
# Authentication removed: no JWT manager

# -------------------------
# Logging setup
# -------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
app.logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))


@app.before_request
def _start_timer():
    g._start_time = time.time()
    try:
        g._req_id = uuid4().hex
    except Exception:
        g._req_id = None


@app.after_request
def _log_response(response):
    try:
        start = getattr(g, "_start_time", None)
        duration_ms = int((time.time() - start) * 1000) if start else None
        method = request.method
        path = request.full_path if request.query_string else request.path
        status = response.status_code
        remote_addr = request.headers.get("X-Forwarded-For", request.remote_addr)
        content_type = response.headers.get("Content-Type", "")
        length = response.calculate_content_length() or 0

        # Optionally include a tiny snippet of the body for JSON/text responses
        body_snippet = None
        if (content_type.startswith("application/json") or content_type.startswith("text/")) and length <= 2048:
            try:
                body_text = response.get_data(as_text=True)
                if body_text and len(body_text) > 512:
                    body_snippet = body_text[:512] + "…"
                else:
                    body_snippet = body_text
            except Exception:
                body_snippet = None

        log_line = {
            "request_id": getattr(g, "_req_id", None),
            "method": method,
            "path": path,
            "status": status,
            "duration_ms": duration_ms,
            "length": length,
            "content_type": content_type,
            "remote_addr": remote_addr,
        }
        if body_snippet is not None:
            log_line["body_snippet"] = body_snippet

        app.logger.info(f"response: {log_line}")

        # Propagate helpful headers
        if getattr(g, "_req_id", None):
            response.headers["X-Request-Id"] = g._req_id
        if duration_ms is not None:
            response.headers["X-Response-Time"] = str(duration_ms)
    except Exception as e:
        app.logger.warning(f"logging-failed: {e}")
    return response

# -------------------------
# Models (host-centric)
# -------------------------
class Command(db.Model):
    __tablename__ = "commands"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host = db.Column(db.String(255), nullable=False, index=True)  # ip/fqdn
    user_id = db.Column(db.Integer, nullable=True)
    session_id = db.Column(db.String(128), index=True)
    phase = db.Column(db.String(80), nullable=False, index=True)  # reconnaissance, exploitation...
    command = db.Column(db.Text, nullable=False)
    tool = db.Column(db.String(120))
    exit_code = db.Column(db.Integer)
    output = db.Column(db.Text)
    summary = db.Column(db.Text)
    external_id = db.Column(db.String(255), index=True)  # client-provided id for idempotency (per-host)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Finding(db.Model):
    __tablename__ = "findings"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host = db.Column(db.String(255), nullable=False, index=True)
    created_by = db.Column(db.Integer, nullable=True)
    title = db.Column(db.String(400), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(30), index=True)  # low/medium/high/critical
    status = db.Column(db.String(50), default="open", index=True)
    commands = db.Column(db.JSON)  # list of command refs
    evidence = db.Column(db.JSON)  # list of evidence metadata
    dedupe_key = db.Column(db.String(255), index=True)
    external_id = db.Column(db.String(255), index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host = db.Column(db.String(255), nullable=False, index=True)
    author_id = db.Column(db.Integer, nullable=True)
    content = db.Column(db.Text, nullable=False)
    context_type = db.Column(db.String(50))  # 'command', 'finding', 'general'
    context_id = db.Column(db.BigInteger)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Evidence(db.Model):
    __tablename__ = "evidence"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host = db.Column(db.String(255), nullable=False, index=True)
    filename = db.Column(db.String(500), nullable=False)
    stored_path = db.Column(db.String(1000), nullable=False)
    uploader_id = db.Column(db.Integer, nullable=True)
    linked = db.Column(db.JSON)  # {"type":"finding","id":123} or {"type":"command","id":456}
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---- Recon models ----
class Service(db.Model):
    __tablename__ = "services"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host = db.Column(db.String(255), nullable=False, index=True)

    port = db.Column(db.Integer, nullable=False, index=True)
    protocol = db.Column(db.String(10), nullable=False, index=True)  # tcp/udp
    state = db.Column(db.String(30), default="open", index=True)     # open/filtered/closed
    name = db.Column(db.String(120))           # e.g., http, ssh
    product = db.Column(db.String(200))        # e.g., OpenSSH
    version = db.Column(db.String(200))        # e.g., 8.2p1
    cpe = db.Column(db.String(300))            # standard CPE
    scripts = db.Column(db.JSON)               # nmap script results
    banner = db.Column(db.Text)                # raw banner
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    external_id = db.Column(db.String(255), index=True)

    __table_args__ = (
        db.UniqueConstraint("host", "port", "protocol", name="uq_service_host_port_proto"),
    )


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host = db.Column(db.String(255), nullable=False, index=True)
    port = db.Column(db.Integer, nullable=True, index=True)
    protocol = db.Column(db.String(10), nullable=True, index=True)

    title = db.Column(db.String(400), nullable=False)
    cve = db.Column(db.String(64), index=True)
    severity = db.Column(db.String(30), index=True)            # info/low/medium/high/critical
    cvss = db.Column(db.Float)
    description = db.Column(db.Text)
    evidence = db.Column(db.JSON)
    source = db.Column(db.String(100))                         # nessus/nmap/burp/manual/etc.
    status = db.Column(db.String(40), default="open", index=True) # open/confirmed/exploited/closed
    dedupe_key = db.Column(db.String(255), index=True)         # e.g., host:port:cve
    external_id = db.Column(db.String(255), index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ExploitAttempt(db.Model):
    __tablename__ = "exploit_attempts"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host = db.Column(db.String(255), nullable=False, index=True)
    port = db.Column(db.Integer, nullable=True, index=True)
    protocol = db.Column(db.String(10), nullable=True, index=True)
    vulnerability_id = db.Column(db.Integer, nullable=True, index=True)

    tool = db.Column(db.String(120))            # metasploit, nmap, custom-poc
    module = db.Column(db.String(200))          # module name / EDB-ID
    command = db.Column(db.Text)                # exact command or params
    result_summary = db.Column(db.Text)         # concise outcome summary
    succeeded = db.Column(db.Boolean, default=False, index=True)
    external_id = db.Column(db.String(255), index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class ServiceNote(db.Model):
    __tablename__ = "service_notes"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host = db.Column(db.String(255), nullable=False, index=True)
    port = db.Column(db.Integer, nullable=False, index=True)
    protocol = db.Column(db.String(10), nullable=False, index=True)
    author_id = db.Column(db.Integer, nullable=True)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# -------------------------
# Schemas
# -------------------------
class CommandInputSchema(Schema):
    host = fields.Str(required=True)
    user_id = fields.Int(required=False, allow_none=True)
    session_id = fields.Str(required=False, allow_none=True)
    phase = fields.Str(required=True, validate=validate.Length(min=1))
    command = fields.Str(required=True)
    tool = fields.Str(required=False, allow_none=True)
    exit_code = fields.Int(required=False, allow_none=True)
    output = fields.Str(required=False, allow_none=True)
    summary = fields.Str(required=False, allow_none=True)
    external_id = fields.Str(required=False, allow_none=True)


class FindingInputSchema(Schema):
    host = fields.Str(required=True)
    created_by = fields.Int(required=False, allow_none=True)
    title = fields.Str(required=True)
    description = fields.Str(required=False, allow_none=True)
    severity = fields.Str(required=False, validate=validate.OneOf(["low","medium","high","critical"]), allow_none=True)
    status = fields.Str(required=False, allow_none=True)
    commands = fields.List(fields.Dict(), required=False, allow_none=True)
    evidence = fields.List(fields.Dict(), required=False, allow_none=True)
    dedupe_key = fields.Str(required=False, allow_none=True)
    external_id = fields.Str(required=False, allow_none=True)


class NoteInputSchema(Schema):
    host = fields.Str(required=True)
    author_id = fields.Int(required=False, allow_none=True)
    content = fields.Str(required=True)
    context_type = fields.Str(required=False, allow_none=True)
    context_id = fields.Int(required=False, allow_none=True)


class ServiceInputSchema(Schema):
    host = fields.Str(required=True)
    port = fields.Int(required=True)
    protocol = fields.Str(required=True, validate=validate.OneOf(["tcp","udp"]))
    state = fields.Str(required=False, allow_none=True)
    name = fields.Str(required=False, allow_none=True)
    product = fields.Str(required=False, allow_none=True)
    version = fields.Str(required=False, allow_none=True)
    cpe = fields.Str(required=False, allow_none=True)
    scripts = fields.Dict(required=False, allow_none=True)
    banner = fields.Str(required=False, allow_none=True)
    last_seen = fields.DateTime(required=False, allow_none=True)
    external_id = fields.Str(required=False, allow_none=True)


class VulnerabilityInputSchema(Schema):
    host = fields.Str(required=True)
    port = fields.Int(required=False, allow_none=True)
    protocol = fields.Str(required=False, allow_none=True, validate=validate.OneOf(["tcp","udp"]))
    title = fields.Str(required=True)
    cve = fields.Str(required=False, allow_none=True)
    severity = fields.Str(required=False, validate=validate.OneOf(["info","low","medium","high","critical"]), allow_none=True)
    cvss = fields.Float(required=False, allow_none=True)
    description = fields.Str(required=False, allow_none=True)
    evidence = fields.Dict(required=False, allow_none=True)
    source = fields.Str(required=False, allow_none=True)
    status = fields.Str(required=False, allow_none=True)
    dedupe_key = fields.Str(required=False, allow_none=True)
    external_id = fields.Str(required=False, allow_none=True)


class ExploitAttemptInputSchema(Schema):
    host = fields.Str(required=True)
    port = fields.Int(required=False, allow_none=True)
    protocol = fields.Str(required=False, allow_none=True, validate=validate.OneOf(["tcp","udp"]))
    vulnerability_id = fields.Int(required=False, allow_none=True)
    tool = fields.Str(required=False, allow_none=True)
    module = fields.Str(required=False, allow_none=True)
    command = fields.Str(required=False, allow_none=True)
    result_summary = fields.Str(required=False, allow_none=True)
    succeeded = fields.Boolean(required=False, allow_none=True)
    external_id = fields.Str(required=False, allow_none=True)


class ServiceNoteInputSchema(Schema):
    host = fields.Str(required=True)
    port = fields.Int(required=True)
    protocol = fields.Str(required=True, validate=validate.OneOf(["tcp","udp"]))
    author_id = fields.Int(required=False, allow_none=True)
    note = fields.Str(required=True)

# Authentication endpoints removed

# -------------------------
# Error handling helpers
# -------------------------
def error_response(message: str, status: int = 400, *, code: str | None = None, field: str | None = None, details=None):
    payload = {"error": {"message": message}}
    if code:
        payload["error"]["code"] = code
    if field:
        payload["error"]["field"] = field
    if details is not None:
        payload["error"]["details"] = details
    return jsonify(payload), status


@app.errorhandler(IntegrityError)
def handle_integrity_error(e: IntegrityError):
    # Ensure the session is clean for the next request
    try:
        db.session.rollback()
    except Exception:
        pass
    # Provide a friendlier message for common cases
    orig = str(getattr(e, "orig", e))
    if "UNIQUE constraint failed: projects.name" in orig:
        return error_response("Project name already exists", 409, code="unique_violation", field="name")
    return error_response("Database integrity error", 400, code="integrity_error", details=orig)


@app.errorhandler(ValidationError)
def handle_validation_error(e: ValidationError):
    return error_response("Validation error", 400, code="validation_error", details=e.messages)


@app.errorhandler(Exception)
def handle_uncaught_exception(e: Exception):
    # Let Flask/werkzeug handle standard HTTP exceptions (404, 405, etc.)
    if isinstance(e, HTTPException):
        return e
    try:
        db.session.rollback()
    except Exception:
        pass
    # Return a summarized error without stack trace
    return error_response("An unexpected error occurred", 500, code=e.__class__.__name__)

# -------------------------
# Core CRUD / Queries
# -------------------------
# Project endpoints removed in host-centric refactor


# -------------------------
# Dev utilities (optional)
# -------------------------
@app.route("/__dev/schema_info", methods=["GET"])
def dev_schema_info():
    if os.getenv("DEV_ENABLE_SCHEMA_INFO") != "1":
        return error_response("Schema info disabled", 403, code="forbidden")
    out = {}
    try:
        inspector = db.inspect(db.engine)
        for table_name in inspector.get_table_names():
            cols = []
            for col in inspector.get_columns(table_name):
                cols.append({
                    "name": col.get("name"),
                    "type": str(col.get("type")),
                    "primary_key": bool(col.get("primary_key")),
                    "nullable": bool(col.get("nullable")),
                    "default": str(col.get("default")) if col.get("default") is not None else None,
                })
            out[table_name] = cols
    except Exception as e:
        return error_response("Failed to inspect schema", 500, code="schema_inspect_error", details=str(e))
    return jsonify({"tables": out})


@app.route("/__dev/reset_db", methods=["POST"])
def dev_reset_db():
    if os.getenv("DEV_ENABLE_RESET") != "1":
        return error_response("Reset disabled", 403, code="forbidden")
    try:
        db.drop_all()
        db.create_all()
        return jsonify({"status": "reset"})
    except Exception as e:
        return error_response("Failed to reset DB", 500, code="reset_failed", details=str(e))


@app.route("/api/hosts", methods=["GET"])
def list_hosts():
    """Return a list of distinct hosts observed across services, commands, and findings."""
    hosts = set()
    for row in db.session.query(Service.host).distinct().all():
        hosts.add(row[0])
    for row in db.session.query(Command.host).distinct().all():
        hosts.add(row[0])
    for row in db.session.query(Finding.host).distinct().all():
        hosts.add(row[0])
    return jsonify({"items": sorted([h for h in hosts if h])})


@app.route("/api/commands", methods=["POST"])
def create_command():
    json_payload = request.json or {}
    try:
        data = CommandInputSchema().load(json_payload)
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400
    print(json_payload)
    ext = data.get("external_id")
    if ext:
        existing = Command.query.filter_by(host=data["host"], external_id=ext).first()
        if existing:
            return jsonify({"id": existing.id, "action": "exists"}), 200

    cmd = Command(
        host=data["host"],
        user_id=data.get("user_id"),
        session_id=data.get("session_id"),
        phase=data["phase"],
        command=data["command"],
        tool=data.get("tool"),
        exit_code=data.get("exit_code"),
        output=data.get("output"),
        summary=data.get("summary"),
        external_id=ext
    )
    db.session.add(cmd)
    db.session.commit()
    return jsonify({"id": cmd.id}), 201


@app.route("/api/commands/<int:command_id>", methods=["GET"])
def get_command(command_id):
    c = Command.query.get_or_404(command_id)
    return {
        "id": c.id,
        "host": c.host,
        "user_id": c.user_id,
        "phase": c.phase,
        "command": c.command,
        "tool": c.tool,
        "exit_code": c.exit_code,
        "output": c.output,
        "summary": c.summary,
        "created_at": c.created_at.isoformat()
    }

# Findings
@app.route("/api/findings", methods=["POST"])
def create_finding():
    json_payload = request.json or {}
    try:
        data = FindingInputSchema().load(json_payload)
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400
    print(json_payload)
    if data.get("external_id"):
        existing = Finding.query.filter_by(host=data["host"], external_id=data["external_id"]).first()
        if existing:
            return jsonify({"id": existing.id, "action": "exists"}), 200
    if data.get("dedupe_key"):
        existing = Finding.query.filter_by(host=data["host"], dedupe_key=data["dedupe_key"]).first()
        if existing:
            return jsonify({"id": existing.id, "action": "exists"}), 200

    f = Finding(
        host=data["host"],
        created_by=data.get("created_by"),
        title=data["title"],
        description=data.get("description"),
        severity=data.get("severity", "medium"),
        status=data.get("status", "open"),
        commands=data.get("commands"),
        evidence=data.get("evidence"),
        dedupe_key=data.get("dedupe_key"),
        external_id=data.get("external_id")
    )
    db.session.add(f)
    db.session.commit()
    return jsonify({"id": f.id}), 201


@app.route("/api/findings", methods=["GET"])
def list_findings():
    host = request.args.get("host")
    q = Finding.query
    if host:
        q = q.filter(Finding.host.ilike(f"%{host}%"))
    severity = request.args.get("severity")
    if severity:
        q = q.filter_by(severity=severity)
    status = request.args.get("status")
    if status:
        q = q.filter_by(status=status)
    page = request.args.get("page", 1, type=int)
    per = request.args.get("per", 50, type=int)
    items = q.order_by(Finding.created_at.asc()).offset((page-1)*per).limit(per).all()
    out = []
    for f in items:
        out.append({
            "id": f.id,
            "host": f.host,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "created_at": f.created_at.isoformat()
        })
    return jsonify({"items": out})

# Notes
@app.route("/api/notes", methods=["POST"])
def create_note():
    json_payload = request.json or {}
    try:
        data = NoteInputSchema().load(json_payload)
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400
    n = Note(
        host=data["host"],
        author_id=data.get("author_id"),
        content=data["content"],
        context_type=data.get("context_type"),
        context_id=data.get("context_id")
    )
    db.session.add(n)
    db.session.commit()
    return jsonify({"id": n.id}), 201

# Evidence upload/download
@app.route("/api/evidence", methods=["POST"])
@app.route("/api/projects/<int:project_id>/evidence", methods=["POST"])  # backward-compatible
def upload_evidence(project_id=None):
    if "file" not in request.files:
        return jsonify({"msg": "file missing"}), 400
    f = request.files["file"]
    uploader_id = request.form.get("uploader_id", type=int)
    linked_type = request.form.get("linked_type")
    linked_id = request.form.get("linked_id", type=int)
    host = request.form.get("host")
    if not host:
        return jsonify({"msg": "host missing"}), 400
    filename = f.filename or f"{uuid4().hex}"
    safe_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
    dest = os.path.join(app.config["UPLOAD_DIR"], safe_name)
    f.save(dest)
    ev = Evidence(host=host, filename=filename, stored_path=dest,
                  uploader_id=uploader_id, linked={"type": linked_type, "id": linked_id})
    db.session.add(ev)
    db.session.commit()
    return jsonify({"id": ev.id, "filename": filename}), 201


@app.route("/api/evidence/<int:evidence_id>/download", methods=["GET"])
def download_evidence(evidence_id):
    e = Evidence.query.get_or_404(evidence_id)
    folder, fname = os.path.split(e.stored_path)
    return send_from_directory(folder, fname, as_attachment=True)

# -------------------------
# Recon Endpoints
# -------------------------
@app.route("/api/services/bulk_upsert", methods=["POST"])
def bulk_upsert_services():
    """
    Upsert services by (target_id, port, protocol) OR external_id if provided.
    Body: {"items":[{ServiceInput}, ...]}
    """
    payload = request.json or {}
    items = payload.get("items", [])
    sch = ServiceInputSchema()
    out = []
    for raw in items:
        try:
            data = sch.load(raw)
        except ValidationError as err:
            return jsonify({"errors": err.messages, "item": raw}), 400

        service = None
        if data.get("external_id"):
            service = Service.query.filter_by(host=data["host"], external_id=data["external_id"]).first()
        if not service:
            service = Service.query.filter_by(
                host=data["host"],
                port=data["port"],
                protocol=data["protocol"]
            ).first()

        if service:
            for k in ("state","name","product","version","cpe","scripts","banner","last_seen","external_id"):
                v = data.get(k)
                if v is not None:
                    setattr(service, k, v)
        else:
            service = Service(**data)
            db.session.add(service)
        db.session.flush()
        out.append({"id": service.id, "host": service.host, "port": service.port, "protocol": service.protocol})
    db.session.commit()
    return jsonify({"items": out}), 200


@app.route("/api/services/notes", methods=["POST"])
def add_service_note():
    payload = request.json or {}
    try:
        data = ServiceNoteInputSchema().load(payload)
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400
    sn = ServiceNote(**data)
    db.session.add(sn)
    db.session.commit()
    return jsonify({"id": sn.id}), 201


@app.route("/api/services/search", methods=["GET"])
def search_services():
    host = request.args.get("host")
    name = request.args.get("name")
    port = request.args.get("port", type=int)

    q = db.session.query(Service)
    if host: q = q.filter(Service.host.ilike(f"%{host}%"))
    if name: q = q.filter(Service.name.ilike(f"%{name}%"))
    if port: q = q.filter(Service.port == port)

    rows = q.order_by(Service.last_seen.desc()).limit(200).all()
    return jsonify({"items": [{
        "id": s.id, "host": s.host,
        "port": s.port, "protocol": s.protocol, "state": s.state,
        "name": s.name, "product": s.product, "version": s.version,
        "cpe": s.cpe, "last_seen": s.last_seen.isoformat()
    } for s in rows]})


@app.route("/api/vulns/bulk_upsert", methods=["POST"])
def bulk_upsert_vulns():
    """
    Upsert vulnerabilities by (project_id + external_id) or dedupe_key, else create.
    Body: {"items":[{VulnerabilityInput}, ...]}
    """
    payload = request.json or {}
    items = payload.get("items", [])
    sch = VulnerabilityInputSchema()
    out = []
    for raw in items:
        try:
            data = sch.load(raw)
        except ValidationError as err:
            return jsonify({"errors": err.messages, "item": raw}), 400

        v = None
        if data.get("external_id"):
            v = Vulnerability.query.filter_by(host=data["host"], external_id=data["external_id"]).first()
        if not v and data.get("dedupe_key"):
            v = Vulnerability.query.filter_by(host=data["host"], dedupe_key=data["dedupe_key"]).first()

        if v:
            for k in ("title","cve","severity","cvss","description","evidence","source","status"):
                if k in data and data[k] is not None:
                    setattr(v, k, data[k])
        else:
            v = Vulnerability(**data)
            db.session.add(v)
        db.session.flush()
        out.append({"id": v.id, "title": v.title})
    db.session.commit()
    return jsonify({"items": out}), 200


@app.route("/api/exploits", methods=["POST"])
def create_exploit_attempt():
    payload = request.json or {}
    try:
        data = ExploitAttemptInputSchema().load(payload)
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400

    if data.get("external_id"):
        ex = ExploitAttempt.query.filter_by(host=data["host"], external_id=data["external_id"]).first()
        if ex:
            for k in ("tool","module","command","result_summary","succeeded"):
                if k in data and data[k] is not None:
                    setattr(ex, k, data[k])
            db.session.commit()
            return jsonify({"id": ex.id, "action": "exists"}), 200

    ex = ExploitAttempt(**data)
    db.session.add(ex)
    db.session.commit()
    return jsonify({"id": ex.id}), 201

# -------------------------
# Search & Health
# -------------------------
@app.route("/api/search/commands", methods=["GET"])
def search_commands():
    qtxt = request.args.get("q")
    host = request.args.get("host")
    q = Command.query
    if host:
        q = q.filter(Command.host.ilike(f"%{host}%"))
    if qtxt:
        q = q.filter((Command.command.ilike(f"%{qtxt}%")) | (Command.summary.ilike(f"%{qtxt}%")))
    items = q.order_by(Command.created_at.desc()).limit(200).all()
    out = []
    for c in items:
        out.append({"id": c.id, "host": c.host, "command": c.command, "summary": c.summary, "phase": c.phase, "created_at": c.created_at.isoformat()})
    return jsonify({"items": out})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})


# -------------------------
# Simple root summary
# -------------------------
@app.route("/")
def root_summary():
    """Redirect to the hosts overview page."""
    return redirect("/hosts")


# -------------------------
# Simple Web UI pages
# -------------------------
@app.route("/commands", methods=["GET"])
def ui_commands():
    host = request.args.get("host")
    qtxt = request.args.get("q")
    page = request.args.get("page", 1, type=int)
    per = request.args.get("per", 50, type=int)

    q = Command.query
    if host:
        q = q.filter(Command.host.ilike(f"%{host}%"))
    if qtxt:
        q = q.filter((Command.command.ilike(f"%{qtxt}%")) | (Command.summary.ilike(f"%{qtxt}%")))

    total = q.count()
    items = q.order_by(Command.created_at.asc()).offset((page - 1) * per).limit(per).all()
    has_prev = page > 1
    has_next = (page * per) < total

    return render_template(
        "commands.html",
        commands=items,
        host=host or "",
        q=qtxt or "",
        page=page,
        per=per,
        total=total,
        has_prev=has_prev,
        has_next=has_next,
    )


@app.route("/findings", methods=["GET"])
def ui_findings():
    host = request.args.get("host")
    severity = request.args.get("severity")
    status = request.args.get("status")
    page = request.args.get("page", 1, type=int)
    per = request.args.get("per", 50, type=int)

    q = Finding.query
    if host:
        q = q.filter(Finding.host.ilike(f"%{host}%"))
    if severity:
        q = q.filter_by(severity=severity)
    if status:
        q = q.filter_by(status=status)

    total = q.count()
    items = q.order_by(Finding.created_at.asc()).offset((page - 1) * per).limit(per).all()
    has_prev = page > 1
    has_next = (page * per) < total

    return render_template(
        "findings.html",
        findings=items,
        host=host or "",
        severity=severity or "",
        status=status or "",
        page=page,
        per=per,
        total=total,
        has_prev=has_prev,
        has_next=has_next,
    )


@app.route("/hosts", methods=["GET"])
def ui_hosts():
    """Host overview page with summary counts and navigation links."""
    q_host = request.args.get("host")

    # Aggregate counts per host
    cmd_rows = db.session.query(Command.host, func.count(Command.id), func.max(Command.created_at)).group_by(Command.host).all()
    fnd_rows = db.session.query(Finding.host, func.count(Finding.id), func.max(Finding.created_at)).group_by(Finding.host).all()
    svc_rows = db.session.query(Service.host, func.count(Service.id), func.max(Service.last_seen)).group_by(Service.host).all()
    vul_rows = db.session.query(Vulnerability.host, func.count(Vulnerability.id), func.max(Vulnerability.created_at)).group_by(Vulnerability.host).all()

    def rows_to_map(rows):
        out = {}
        for host, cnt, last in rows:
            if not host:
                continue
            out[host] = {"count": int(cnt or 0), "last": last}
        return out

    cmd_map = rows_to_map(cmd_rows)
    fnd_map = rows_to_map(fnd_rows)
    svc_map = rows_to_map(svc_rows)
    vul_map = rows_to_map(vul_rows)

    hosts = set(cmd_map.keys()) | set(fnd_map.keys()) | set(svc_map.keys()) | set(vul_map.keys())
    if q_host:
        hosts = {h for h in hosts if q_host.lower() in h.lower()}

    summaries = []
    for h in sorted(hosts):
        last_candidates = [
            cmd_map.get(h, {}).get("last"),
            fnd_map.get(h, {}).get("last"),
            svc_map.get(h, {}).get("last"),
            vul_map.get(h, {}).get("last"),
        ]
        last_activity = max([d for d in last_candidates if d is not None], default=None)
        summaries.append({
            "host": h,
            "commands": cmd_map.get(h, {}).get("count", 0),
            "findings": fnd_map.get(h, {}).get("count", 0),
            "services": svc_map.get(h, {}).get("count", 0),
            "vulns": vul_map.get(h, {}).get("count", 0),
            "last_activity": last_activity,
        })

    return render_template("hosts.html", items=summaries, host=q_host or "")


@app.route("/services", methods=["GET"])
def ui_services():
    host = request.args.get("host")
    name = request.args.get("name")
    port = request.args.get("port", type=int)
    protocol = request.args.get("protocol")
    state = request.args.get("state")
    page = request.args.get("page", 1, type=int)
    per = request.args.get("per", 50, type=int)

    q = Service.query
    if host:
        q = q.filter(Service.host.ilike(f"%{host}%"))
    if name:
        q = q.filter(Service.name.ilike(f"%{name}%"))
    if port is not None:
        q = q.filter(Service.port == port)
    if protocol:
        q = q.filter(Service.protocol == protocol)
    if state:
        q = q.filter(Service.state == state)

    total = q.count()
    items = q.order_by(Service.last_seen.desc()).offset((page - 1) * per).limit(per).all()
    has_prev = page > 1
    has_next = (page * per) < total

    return render_template(
        "services.html",
        services=items,
        host=host or "",
        name=name or "",
        port=port or "",
        protocol=protocol or "",
        state=state or "",
        page=page,
        per=per,
        total=total,
        has_prev=has_prev,
        has_next=has_next,
    )


@app.route("/vulns", methods=["GET"])
def ui_vulns():
    host = request.args.get("host")
    severity = request.args.get("severity")
    status = request.args.get("status")
    cve = request.args.get("cve")
    title_q = request.args.get("title")
    port = request.args.get("port", type=int)
    protocol = request.args.get("protocol")
    page = request.args.get("page", 1, type=int)
    per = request.args.get("per", 50, type=int)

    q = Vulnerability.query
    if host:
        q = q.filter(Vulnerability.host.ilike(f"%{host}%"))
    if severity:
        q = q.filter_by(severity=severity)
    if status:
        q = q.filter_by(status=status)
    if cve:
        q = q.filter(Vulnerability.cve.ilike(f"%{cve}%"))
    if title_q:
        q = q.filter(Vulnerability.title.ilike(f"%{title_q}%"))
    if port is not None:
        q = q.filter(Vulnerability.port == port)
    if protocol:
        q = q.filter(Vulnerability.protocol == protocol)

    total = q.count()
    items = q.order_by(Vulnerability.created_at.asc()).offset((page - 1) * per).limit(per).all()
    has_prev = page > 1
    has_next = (page * per) < total

    return render_template(
        "vulns.html",
        vulns=items,
        host=host or "",
        severity=severity or "",
        status=status or "",
        cve=cve or "",
        title=title_q or "",
        port=port or "",
        protocol=protocol or "",
        page=page,
        per=per,
        total=total,
        has_prev=has_prev,
        has_next=has_next,
    )

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    # PoC convenience: auto-create tables if not existing.
    with app.app_context():
        if os.getenv("RESET_DB") == "1":
            app.logger.warning("RESET_DB=1 detected: dropping and recreating all tables (dev only)")
            db.drop_all()
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5555)), debug=True)
