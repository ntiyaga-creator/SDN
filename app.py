import os
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, send_file, session
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from models import Alert, Policy, PolicyAction, Severity, TrafficStats
from sdn_client import RyuClient
from traffic_monitor import TrafficMonitor

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

ryu_client = RyuClient()
stats = TrafficStats()
alerts = []
policies = [
    Policy(PolicyAction.BLOCK, "DDoS Mitigation", "Block traffic from IPs exceeding DDoS threshold", priority=100),
    Policy(PolicyAction.RATE_LIMIT, "ICMP Flood Protection", "Rate-limit ICMP echo requests to prevent ping flood", priority=95, match={"eth_type": 0x0800, "ip_proto": 1}),
    Policy(PolicyAction.ISOLATE, "Host Isolation", "Isolate compromised hosts from network traffic", priority=90, enabled=False),
    Policy(PolicyAction.BLOCK, "Port Scan Prevention", "Block IPs scanning more than 20 ports in 2 seconds", priority=98, match={"eth_type": 0x0800}),
    Policy(PolicyAction.DROP, "SYN Flood Protection", "Drop excessive TCP SYN packets to prevent handshake exhaustion", priority=97, match={"eth_type": 0x0800, "ip_proto": 6, "tcp_flags": 2}),
    Policy(PolicyAction.REDIRECT, "Traffic Mirroring", "Redirect suspicious traffic to monitoring/honeypot port", priority=85, enabled=False),
    Policy(PolicyAction.QUARANTINE, "Malware Containment", "Quarantine hosts exhibiting malware-like behavior", priority=92, enabled=False),
    Policy(PolicyAction.BLOCK, "Known Malicious IPs", "Block traffic from blacklisted IP addresses", priority=99, match={"eth_type": 0x0800}),
    Policy(PolicyAction.RATE_LIMIT, "DNS Amplification Protection", "Rate-limit DNS responses to prevent amplification attacks", priority=93, match={"eth_type": 0x0800, "ip_proto": 17, "udp_dst": 53}),
    Policy(PolicyAction.LOG_ONLY, "Suspicious Traffic Logging", "Log all traffic matching suspicious patterns for analysis", priority=80),
    Policy(PolicyAction.ALERT, "ARP Spoofing Detection", "Generate alert on ARP cache poisoning attempts", priority=88, match={"eth_type": 0x0806}),
    Policy(PolicyAction.DROP, "Invalid TCP Flags", "Drop packets with invalid TCP flag combinations (e.g. SYN+URG)", priority=96, match={"eth_type": 0x0800, "ip_proto": 6}),
    Policy(PolicyAction.RATE_LIMIT, "UDP Flood Protection", "Rate-limit UDP traffic to prevent UDP flood attacks", priority=94, match={"eth_type": 0x0800, "ip_proto": 17}),
    Policy(PolicyAction.BLOCK, "Spoofed IP Protection", "Block traffic from internal IP ranges arriving on external interfaces", priority=99, match={"eth_type": 0x0800}),
    Policy(PolicyAction.ISOLATE, "Rogue DHCP Server", "Isolate unauthorized DHCP servers on the network", priority=91, match={"eth_type": 0x0800, "udp_src": 67}),
]
system_logs = []

ADMIN_USER = {"username": "admin", "password": "ntiyaga@1234"}


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def add_log(level, message):
    timestamp = datetime.now(timezone.utc).isoformat()
    entry = f"[{timestamp}] [{level}] {message}"
    system_logs.append(entry)
    logger.info(entry)


def handle_monitor_update(data):
    if "alert" in data:
        alert_dict = data["alert"]
        alert = Alert(
            message=alert_dict["message"],
            severity=Severity(alert_dict["severity"]),
            source_ip=alert_dict["sourceIp"],
            destination_ip=alert_dict["destinationIp"],
        )
        alert.mitigated = alert_dict.get("mitigated", False)
        alert.id = alert_dict["id"]
        alert.timestamp = alert_dict["timestamp"]
        alerts.insert(0, alert)
        stats.total_alerts += 1
        add_log("ALERT", f"{alert.severity.value}: {alert.message}")
        socketio.emit("new_alert", alert.to_dict())
        socketio.emit("stats_update", stats.to_dict())
    elif "totalPackets" in data:
        stats.total_packets = data["totalPackets"]
        stats.active_flows = data["activeFlows"]
        socketio.emit("stats_update", stats.to_dict())
        socketio.emit("traffic_update", {
            "timestamps": data["trafficData"]["timestamps"],
            "rates": data["trafficData"]["rates"],
        })


monitor = TrafficMonitor(alert_callback=handle_monitor_update)


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
                    global alerts
                    new_alert_ids = {a["id"] for a in ryu_alerts}
                    existing_ids = {a.id for a in alerts}
                    for a_data in ryu_alerts:
                        if a_data["id"] not in existing_ids:
                            alert = Alert(
                                message=a_data["message"],
                                severity=Severity(a_data["severity"]),
                                source_ip=a_data["sourceIp"],
                                destination_ip=a_data["destinationIp"],
                            )
                            alert.id = a_data["id"]
                            alert.timestamp = a_data["timestamp"]
                            alert.mitigated = a_data["mitigated"]
                            alerts.insert(0, alert)
                            stats.total_alerts += 1
                            add_log("ALERT", f"{alert.severity.value}: {alert.message}")
                            socketio.emit("new_alert", alert.to_dict())
        except Exception as e:
            logger.debug("Ryu poll error: %s", e)
        time.sleep(3)


@app.route("/")
def index():
    return app.send_static_file("dashboard.html")


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    if username == ADMIN_USER["username"] and password == ADMIN_USER["password"]:
        session["logged_in"] = True
        session["username"] = username
        session.permanent = True
        add_log("INFO", f"Admin login: {username}")
        return jsonify({"status": "ok", "username": username})
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
    if old != ADMIN_USER["password"]:
        return jsonify({"error": "Current password is incorrect"}), 400
    if len(new) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400
    ADMIN_USER["password"] = new
    add_log("INFO", "Admin password changed")
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
    if severity != "all":
        filtered = [a for a in alerts if a.severity.value == severity.upper()]
        return jsonify([a.to_dict() for a in filtered])
    return jsonify([a.to_dict() for a in alerts])


@app.route("/api/alerts/clear", methods=["POST"])
@login_required
def clear_alerts():
    alerts.clear()
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
    return jsonify([p.to_dict() for p in policies])


@app.route("/api/policies", methods=["POST"])
@login_required
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
    policy = Policy(PolicyAction(action), name, description, priority, enabled)
    policies.append(policy)
    add_log("INFO", f"Policy added: {policy.name or policy.id} ({action})")
    return jsonify(policy.to_dict()), 201


@app.route("/api/policies/<policy_id>/toggle", methods=["POST"])
@login_required
def toggle_policy(policy_id):
    if ryu_client.connected:
        result = ryu_client.toggle_policy(policy_id)
        if result:
            return jsonify(result)
    for policy in policies:
        if policy.id == policy_id:
            policy.enabled = not policy.enabled
            add_log("INFO", f"Policy {policy_id} toggled")
            return jsonify(policy.to_dict())
    return jsonify({"error": "Policy not found"}), 404


@app.route("/api/policies/<policy_id>", methods=["DELETE"])
@login_required
def delete_policy(policy_id):
    if ryu_client.connected:
        ryu_client.delete_policy(policy_id)
    global policies
    policies = [p for p in policies if p.id != policy_id]
    add_log("INFO", f"Policy deleted: {policy_id}")
    return jsonify({"status": "ok"})


@app.route("/api/flows")
@login_required
def get_flows():
    if ryu_client.connected and ryu_client.check_connection():
        flows = ryu_client.get_flows()
        if flows is not None:
            return jsonify(flows)
    flows_data = []
    for i in range(stats.active_flows or 10):
        flows_data.append({
            "id": f"flow_{i}",
            "deviceId": f"dpid_{i % 5 + 1}",
            "state": "INSTALLED",
            "bytes": i * 1000,
            "packets": i * 10,
            "priority": 100 - i,
            "byteRate": i * 5000 + 1000,
        })
    return jsonify(flows_data)


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
    return "\n".join(system_logs[-200:]) if system_logs else "No logs yet"


@app.route("/api/logs/download")
@login_required
def download_logs():
    log_path = Path("sea_system.log")
    log_path.write_text("\n".join(system_logs), encoding="utf-8")
    return send_file(
        log_path.resolve(),
        as_attachment=True,
        download_name="sea_system.log",
        mimetype="text/plain",
    )


@app.route("/api/mitigate", methods=["POST"])
@login_required
def mitigate_alert():
    data = request.get_json()
    alert_id = data.get("alertId")
    for alert in alerts:
        if alert.id == alert_id:
            alert.mitigated = True
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
        data = request.get_json()
        if data:
            monitor.detection_thresholds.update({
                "packet_rate": data.get("packetThreshold", 1000),
                "byte_rate": data.get("byteThreshold", 1000000),
                "ddos_packets": data.get("ddosThreshold", 10000),
            })
            if ryu_client.connected:
                ryu_client.update_settings(data)
            add_log("INFO", "Settings updated")
            return jsonify({"status": "ok"})
        return jsonify({"error": "Invalid data"}), 400
    return jsonify({
        "packetThreshold": monitor.detection_thresholds["packet_rate"],
        "byteThreshold": monitor.detection_thresholds["byte_rate"],
        "ddosThreshold": monitor.detection_thresholds["ddos_packets"],
    })


@socketio.on("connect")
def handle_connect():
    emit("connected", {"status": "ok"})


@socketio.on("disconnect")
def handle_disconnect():
    logger.info("Client disconnected from WebSocket")


if __name__ == "__main__":
    add_log("INFO", "SEA Application starting...")
    monitor.start()

    if ryu_client.check_connection():
        add_log("INFO", "Ryu controller connected")
        t = threading.Thread(target=_ryu_poller, daemon=True)
        t.start()
    else:
        add_log("WARN", "Ryu controller not reachable, running in standalone mode")

    stats.active_rules = len(policies)
    add_log("INFO", f"Loaded {len(policies)} security policies")

    try:
        socketio.run(app, host="0.0.0.0", port=5000, debug=False)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        add_log("INFO", "SEA Application shutting down")
