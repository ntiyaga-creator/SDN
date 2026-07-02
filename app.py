import os
import uuid
import json
import csv
import io
import logging
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from functools import wraps
from collections import defaultdict

from flask import Flask, Response, jsonify, request, send_file, session
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

from models import Alert, Policy, PolicyAction, Severity, TrafficStats
from sdn_client import RyuClient
from traffic_monitor import TrafficMonitor
from database import db, init_db, UserModel, RoleModel, AlertModel, PolicyModel, LogModel, SettingModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder=".", static_url_path="")
app.config["SECRET_KEY"] = os.urandom(24).hex()
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 28800
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

init_db(app)

ryu_client = RyuClient()
stats = TrafficStats()
monitor = TrafficMonitor(alert_callback=lambda data: _handle_monitor_update(data))

login_attempts = defaultdict(list)
LOGIN_RATE_LIMIT = 5
LOGIN_WINDOW = 300


def _is_rate_limited(ip):
    now = datetime.now(timezone.utc)
    attempts = login_attempts[ip]
    attempts[:] = [t for t in attempts if now - t < timedelta(seconds=LOGIN_WINDOW)]
    return len(attempts) >= LOGIN_RATE_LIMIT


def _load_counts():
    with app.app_context():
        alerts = AlertModel.query.count()
        active = PolicyModel.query.filter_by(enabled=1).count()
        stats.total_alerts = alerts
        stats.active_rules = active


def _get_user(username):
    return UserModel.query.filter_by(username=username).first()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def role_required(*permissions):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("logged_in"):
                return jsonify({"error": "Authentication required"}), 401
            user_perms = session.get("permissions", [])
            if permissions and not any(p in user_perms for p in permissions):
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def add_log(level, message):
    timestamp = datetime.now(timezone.utc).isoformat()
    entry = f"[{timestamp}] [{level}] {message}"
    logger.info(entry)
    try:
        with app.app_context():
            db.session.add(LogModel(timestamp=timestamp, level=level, message=message))
            db.session.commit()
    except Exception:
        pass


def _handle_monitor_update(data):
    if "alert" in data:
        alert_dict = data["alert"]
        with app.app_context():
            if not AlertModel.query.get(alert_dict["id"]):
                alert = AlertModel(
                    id=alert_dict["id"],
                    timestamp=alert_dict["timestamp"],
                    message=alert_dict["message"],
                    severity=alert_dict["severity"],
                    source_ip=alert_dict["sourceIp"],
                    destination_ip=alert_dict["destinationIp"],
                    mitigated=int(alert_dict.get("mitigated", False)),
                )
                db.session.add(alert)
                db.session.commit()
            else:
                alert = AlertModel.query.get(alert_dict["id"])
        stats.total_alerts += 1
        add_log("ALERT", f"{alert_dict['severity']}: {alert_dict['message']}")
        socketio.emit("new_alert", alert_dict)
        socketio.emit("stats_update", stats.to_dict())
    elif "totalPackets" in data:
        stats.total_packets = data["totalPackets"]
        stats.active_flows = data["activeFlows"]
        socketio.emit("stats_update", stats.to_dict())
        socketio.emit("traffic_update", {
            "timestamps": data["trafficData"]["timestamps"],
            "rates": data["trafficData"]["rates"],
        })


def _ryu_poller():
    while True:
        try:
            if ryu_client.connected:
                ryu_stats = ryu_client.get_stats()
                if ryu_stats:
                    stats.total_packets = ryu_stats.get("totalPackets", stats.total_packets)
                    stats.total_alerts = ryu_stats.get("totalAlerts", stats.total_alerts)
                    stats.active_rules = ryu_stats.get("activeRules", stats.active_rules)
                    stats.active_flows = ryu_stats.get("activeFlows", stats.active_flows)
                    socketio.emit("stats_update", stats.to_dict())

                ryu_alerts = ryu_client.get_alerts()
                if ryu_alerts is not None:
                    with app.app_context():
                        for a_data in ryu_alerts:
                            if not AlertModel.query.get(a_data["id"]):
                                alert = AlertModel(
                                    id=a_data["id"],
                                    timestamp=a_data["timestamp"],
                                    message=a_data["message"],
                                    severity=a_data["severity"],
                                    source_ip=a_data["sourceIp"],
                                    destination_ip=a_data["destinationIp"],
                                    mitigated=int(a_data["mitigated"]),
                                )
                                db.session.add(alert)
                                db.session.commit()
                                stats.total_alerts += 1
                                add_log("ALERT", f"{a_data['severity']}: {a_data['message']}")
                                socketio.emit("new_alert", alert.to_dict())
        except Exception as e:
            logger.debug("Ryu poll error: %s", e)
        time.sleep(3)


@app.route("/")
def index():
    return app.send_static_file("dashboard.html")


@app.route("/api/login", methods=["POST"])
def login():
    ip = request.remote_addr or "unknown"
    if _is_rate_limited(ip):
        add_log("WARN", f"Rate-limited login from {ip}")
        return jsonify({"error": "Too many login attempts. Try again in 5 minutes."}), 429
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    user = _get_user(username)
    if user and username == user.username and check_password_hash(user.password, password):
        login_attempts.pop(ip, None)
        role = RoleModel.query.get(user.role_id)
        session["logged_in"] = True
        session["username"] = username
        session["user_id"] = user.id
        session["role_id"] = user.role_id
        session["permissions"] = role.get_permissions() if role else []
        session.permanent = True
        role_name = role.name if role else "unknown"
        add_log("INFO", f"Login: {username} ({role_name})")
        return jsonify({"status": "ok", "username": username, "role": role_name})
    login_attempts[ip].append(datetime.now(timezone.utc))
    add_log("WARN", f"Failed login attempt: {username}")
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    username = session.get("username", "unknown")
    session.clear()
    add_log("INFO", f"Admin logout: {username}")
    return jsonify({"status": "ok"})


@app.route("/api/check-auth")
def check_auth():
    if session.get("logged_in"):
        return jsonify({"authenticated": True, "username": session.get("username")})
    return jsonify({"authenticated": False}), 401


@app.route("/api/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json()
    old = data.get("oldPassword", "")
    new = data.get("newPassword", "")
    username = session.get("username", "")
    user = _get_user(username)
    if not user or not check_password_hash(user.password, old):
        return jsonify({"error": "Current password is incorrect"}), 400
    if len(new) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400
    user.password = generate_password_hash(new)
    db.session.commit()
    add_log("INFO", f"Password changed for {username}")
    return jsonify({"status": "ok"})


@app.route("/api/stats")
@login_required
def get_stats():
    if ryu_client.connected and ryu_client.check_connection():
        ryu_stats = ryu_client.get_stats()
        if ryu_stats:
            stats.total_packets = ryu_stats.get("totalPackets", stats.total_packets)
            stats.active_rules = ryu_stats.get("activeRules", stats.active_rules)
            stats.active_flows = ryu_stats.get("activeFlows", stats.active_flows)
    return jsonify(stats.to_dict())


@app.route("/api/alerts")
@login_required
def get_alerts():
    severity = request.args.get("severity", "all")
    status = request.args.get("status", "all")
    search = request.args.get("search", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    with app.app_context():
        query = AlertModel.query
        if severity != "all":
            query = query.filter_by(severity=severity.upper())
        if status == "active":
            query = query.filter_by(mitigated=0)
        elif status == "mitigated":
            query = query.filter_by(mitigated=1)
        if search:
            query = query.filter(
                AlertModel.message.contains(search) |
                AlertModel.source_ip.contains(search) |
                AlertModel.destination_ip.contains(search)
            )
        if date_from:
            try:
                dt_from = datetime.fromisoformat(date_from)
                query = query.filter(AlertModel.timestamp >= dt_from.isoformat())
            except ValueError:
                pass
        if date_to:
            try:
                dt_to = datetime.fromisoformat(date_to)
                query = query.filter(AlertModel.timestamp <= dt_to.isoformat())
            except ValueError:
                pass
        total = query.count()
        alerts = query.order_by(AlertModel.timestamp.desc()).limit(200).all()
        return jsonify({"alerts": [a.to_dict() for a in alerts], "total": total})


@app.route("/api/alerts/export")
@login_required
@role_required("alerts.export")
def export_alerts_csv():
    severity = request.args.get("severity", "all")
    with app.app_context():
        query = AlertModel.query
        if severity != "all":
            query = query.filter_by(severity=severity.upper())
        alerts = query.order_by(AlertModel.timestamp.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Severity", "Message", "Source IP", "Destination IP", "Status"])
    for a in alerts:
        writer.writerow([a.id, a.timestamp, a.severity, a.message, a.source_ip, a.destination_ip, "Mitigated" if a.mitigated else "Active"])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=sea_alerts_export.csv"},
    )


@app.route("/api/alerts/clear", methods=["POST"])
@login_required
@role_required("alerts.clear")
def clear_alerts():
    with app.app_context():
        AlertModel.query.delete()
        db.session.commit()
    if ryu_client.connected:
        ryu_client.clear_alerts()
    add_log("INFO", "All alerts cleared")
    return jsonify({"status": "ok"})


@app.route("/api/policies", methods=["GET"])
@login_required
def get_policies():
    if ryu_client.connected:
        ryu_policies = ryu_client.get_policies()
        if ryu_policies is not None:
            return jsonify(ryu_policies)
    with app.app_context():
        return jsonify([p.to_dict() for p in PolicyModel.query.order_by(PolicyModel.priority.desc()).all()])


@app.route("/api/policies", methods=["POST"])
@login_required
@role_required("policies.create")
def add_policy():
    data = request.get_json()
    action = data.get("action", "LOG_ONLY").upper()
    name = data.get("name", "")
    description = data.get("description", "")
    priority = data.get("priority", 100)
    enabled = data.get("enabled", True)
    if ryu_client.connected:
        result = ryu_client.add_policy(action, priority, enabled)
        if result:
            return jsonify(result), 201
    with app.app_context():
        policy = PolicyModel(
            id=f"policy_{uuid.uuid4().hex[:8]}",
            name=name, description=description,
            action=action, priority=priority,
            enabled=int(enabled), match_json="{}",
        )
        db.session.add(policy)
        db.session.commit()
        add_log("INFO", f"Policy added: {name or policy.id} ({action})")
        return jsonify(policy.to_dict()), 201


@app.route("/api/policies/<policy_id>/toggle", methods=["POST"])
@login_required
@role_required("policies.edit")
def toggle_policy(policy_id):
    if ryu_client.connected:
        result = ryu_client.toggle_policy(policy_id)
        if result:
            return jsonify(result)
    with app.app_context():
        policy = PolicyModel.query.get(policy_id)
        if policy:
            policy.enabled = int(not policy.enabled)
            db.session.commit()
            add_log("INFO", f"Policy {policy_id} toggled")
            return jsonify(policy.to_dict())
    return jsonify({"error": "Policy not found"}), 404


@app.route("/api/policies/<policy_id>", methods=["DELETE"])
@login_required
@role_required("policies.delete")
def delete_policy(policy_id):
    if ryu_client.connected:
        ryu_client.delete_policy(policy_id)
    with app.app_context():
        policy = PolicyModel.query.get(policy_id)
        if policy:
            db.session.delete(policy)
            db.session.commit()
    add_log("INFO", f"Policy deleted: {policy_id}")
    return jsonify({"status": "ok"})


@app.route("/api/policies/import", methods=["POST"])
@login_required
@role_required("policies.import")
def import_policies():
    data = request.get_json()
    if not isinstance(data, list):
        return jsonify({"error": "Expected JSON array of policies"}), 400
    imported = 0
    with app.app_context():
        for item in data:
            name = item.get("name", "")
            description = item.get("description", "")
            action = item.get("action", "LOG_ONLY").upper()
            priority = item.get("priority", 100)
            enabled = item.get("enabled", True)
            match = item.get("match", {})
            if action not in ("BLOCK", "DROP", "RATE_LIMIT", "ISOLATE", "QUARANTINE", "REDIRECT", "LOG_ONLY", "ALERT"):
                action = "LOG_ONLY"
            policy = PolicyModel(
                id=item.get("id") or f"policy_{uuid.uuid4().hex[:8]}",
                name=name, description=description,
                action=action, priority=priority,
                enabled=int(enabled), match_json=json.dumps(match),
            )
            db.session.add(policy)
            imported += 1
        db.session.commit()
    add_log("INFO", f"Imported {imported} policies")
    return jsonify({"status": "ok", "imported": imported})


@app.route("/api/flows")
@login_required
def get_flows():
    if ryu_client.connected and ryu_client.check_connection():
        flows = ryu_client.get_flows()
        if flows is not None:
            return jsonify(flows)
    n = stats.active_flows or 10
    return jsonify([
        {"id": f"flow_{i}", "deviceId": f"dpid_{i % 5 + 1}", "state": "INSTALLED",
         "bytes": i * 1000, "packets": i * 10, "priority": 100 - i, "byteRate": i * 5000 + 1000}
        for i in range(n)
    ])


@app.route("/api/topology")
@login_required
def get_topology():
    if ryu_client.connected and ryu_client.check_connection():
        topo = ryu_client.get_topology()
        if topo:
            return jsonify(topo)
    return jsonify({
        "switches": [
            {"dpid": "1", "ports": [{"port_no": 1, "name": "eth0"}, {"port_no": 2, "name": "eth1"}]},
            {"dpid": "2", "ports": [{"port_no": 1, "name": "eth0"}, {"port_no": 2, "name": "eth1"}]},
            {"dpid": "3", "ports": [{"port_no": 1, "name": "eth0"}, {"port_no": 2, "name": "eth1"}]},
        ],
        "hosts": [
            {"mac": "00:00:00:00:00:01", "ip": ["10.0.0.1"], "port": 1, "dpid": "1"},
            {"mac": "00:00:00:00:00:02", "ip": ["10.0.0.2"], "port": 2, "dpid": "1"},
            {"mac": "00:00:00:00:00:03", "ip": ["10.0.0.3"], "port": 1, "dpid": "2"},
        ],
        "links": [
            {"src": {"dpid": "1", "port": 3}, "dst": {"dpid": "2", "port": 3}},
            {"src": {"dpid": "2", "port": 4}, "dst": {"dpid": "3", "port": 4}},
        ],
    })


@app.route("/api/logs")
@login_required
def get_logs():
    with app.app_context():
        logs = LogModel.query.order_by(LogModel.id.desc()).limit(200).all()
        if not logs:
            return "No logs yet"
        return "\n".join(f"[{l.timestamp}] [{l.level}] {l.message}" for l in reversed(logs))


@app.route("/api/logs/download")
@login_required
def download_logs():
    with app.app_context():
        logs = LogModel.query.order_by(LogModel.id.asc()).all()
        content = "\n".join(f"[{l.timestamp}] [{l.level}] {l.message}" for l in logs)
    log_path = Path("sea_system.log")
    log_path.write_text(content, encoding="utf-8")
    return send_file(
        log_path.resolve(),
        as_attachment=True,
        download_name="sea_system.log",
        mimetype="text/plain",
    )


@app.route("/api/mitigate", methods=["POST"])
@login_required
@role_required("alerts.mitigate")
def mitigate_alert():
    data = request.get_json()
    alert_id = data.get("alertId")
    with app.app_context():
        alert = AlertModel.query.get(alert_id)
        if alert:
            alert.mitigated = 1
            db.session.commit()
            add_log("INFO", f"Mitigation applied to alert {alert_id}: {alert.message}")
            socketio.emit("alert_mitigated", {"id": alert_id})
            if ryu_client.connected:
                ryu_client.mitigate(alert_id)
            return jsonify({"status": "ok", "mitigated": True})
    return jsonify({"error": "Alert not found"}), 404


@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def handle_settings():
    if request.method == "POST":
        if "settings.edit" not in session.get("permissions", []):
            return jsonify({"error": "Insufficient permissions"}), 403
        data = request.get_json()
        if data:
            with app.app_context():
                for key, field in [("packet_rate", "packetThreshold"), ("byte_rate", "byteThreshold"), ("ddos_packets", "ddosThreshold")]:
                    if field in data:
                        s = SettingModel.query.get(key)
                        if s:
                            s.value = str(data[field])
                        else:
                            db.session.add(SettingModel(key=key, value=str(data[field])))
                db.session.commit()
            monitor.detection_thresholds.update({
                "packet_rate": int(data.get("packetThreshold", 1000)),
                "byte_rate": int(data.get("byteThreshold", 1000000)),
                "ddos_packets": int(data.get("ddosThreshold", 10000)),
            })
            if ryu_client.connected:
                ryu_client.update_settings(data)
            add_log("INFO", "Settings updated")
            return jsonify({"status": "ok"})
        return jsonify({"error": "Invalid data"}), 400
    with app.app_context():
        return jsonify({
            "packetThreshold": int((SettingModel.query.get("packet_rate") or SettingModel(key="packet_rate", value="1000")).value),
            "byteThreshold": int((SettingModel.query.get("byte_rate") or SettingModel(key="byte_rate", value="1000000")).value),
            "ddosThreshold": int((SettingModel.query.get("ddos_packets") or SettingModel(key="ddos_packets", value="10000")).value),
        })


@app.route("/api/roles")
@login_required
@role_required("roles.view")
def get_roles():
    with app.app_context():
        return jsonify([r.to_dict() for r in RoleModel.query.all()])


@app.route("/api/roles/import", methods=["POST"])
@login_required
@role_required("roles.import")
def import_roles():
    data = request.get_json()
    if not isinstance(data, list):
        return jsonify({"error": "Expected JSON array of roles"}), 400
    imported = 0
    with app.app_context():
        for item in data:
            rid = item.get("id")
            name = item.get("name", "")
            if not name:
                continue
            existing = RoleModel.query.get(rid) if rid else RoleModel.query.filter_by(name=name).first()
            perms = json.dumps(item.get("permissions", []))
            if existing:
                existing.description = item.get("description", existing.description)
                existing.permissions = perms
            else:
                role = RoleModel(
                    id=rid, name=name,
                    description=item.get("description", ""),
                    permissions=perms, is_builtin=0,
                )
                db.session.add(role)
            imported += 1
        db.session.commit()
    add_log("INFO", f"Imported {imported} roles")
    return jsonify({"status": "ok", "imported": imported})


@app.route("/api/users")
@login_required
@role_required("users.view")
def get_users():
    with app.app_context():
        return jsonify([u.to_dict() for u in UserModel.query.all()])


@app.route("/api/users", methods=["POST"])
@login_required
@role_required("users.create")
def add_user():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role_id = data.get("role_id", 3)
    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    with app.app_context():
        if UserModel.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 400
        user = UserModel(
            username=username, password=generate_password_hash(password),
            role_id=role_id,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        db.session.add(user)
        db.session.flush()
        result = user.to_dict()
        db.session.commit()
    add_log("INFO", f"User created: {username}")
    return jsonify(result), 201


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
@role_required("users.delete")
def delete_user(user_id):
    with app.app_context():
        user = UserModel.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        if user.id == session.get("user_id"):
            return jsonify({"error": "Cannot delete yourself"}), 400
        db.session.delete(user)
        db.session.commit()
    add_log("INFO", f"User deleted: {user.username}")
    return jsonify({"status": "ok"})


@socketio.on("connect")
def handle_connect():
    emit("connected", {"status": "ok"})


@socketio.on("disconnect")
def handle_disconnect():
    logger.info("Client disconnected from WebSocket")


if __name__ == "__main__":
    add_log("INFO", "SEA Application starting with SQLite database...")
    _load_counts()
    monitor.start()

    if ryu_client.check_connection():
        add_log("INFO", "Ryu controller connected")
        t = threading.Thread(target=_ryu_poller, daemon=True)
        t.start()
    else:
        add_log("WARN", "Ryu controller not reachable, running in standalone mode")

    with app.app_context():
        first_user = UserModel.query.first()
        add_log("INFO", f"Loaded {first_user.username if first_user else 'no'} user, {stats.active_rules} active policies")

    try:
        socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        add_log("INFO", "SEA Application shutting down")
