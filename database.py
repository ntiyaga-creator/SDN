import json
import uuid
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class RoleModel(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200), default="")
    permissions = db.Column(db.Text, default="[]")
    is_builtin = db.Column(db.Integer, default=0)

    def get_permissions(self):
        return json.loads(self.permissions) if self.permissions else []

    def to_dict(self):
        return {
            "id": self.id, "name": self.name,
            "description": self.description,
            "permissions": self.get_permissions(),
            "is_builtin": bool(self.is_builtin),
        }


class UserModel(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), default=1)
    created_at = db.Column(db.String(40), nullable=False)

    def to_dict(self):
        from sqlalchemy import inspect
        inst = inspect(self)
        rid = inst.attrs.role_id.loaded_value if inst.attrs.role_id.loaded_value is not None else 1
        role = RoleModel.query.get(rid)
        return {
            "id": inst.attrs.id.loaded_value if inst.attrs.id.loaded_value else self.id,
            "username": inst.attrs.username.loaded_value if inst.attrs.username.loaded_value else self.username,
            "role_id": rid,
            "role_name": role.name if role else "unknown",
            "created_at": inst.attrs.created_at.loaded_value if inst.attrs.created_at.loaded_value else self.created_at,
        }


class AlertModel(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.String(40), primary_key=True)
    timestamp = db.Column(db.String(40), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    source_ip = db.Column(db.String(50), nullable=False)
    destination_ip = db.Column(db.String(50), nullable=False)
    mitigated = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "message": self.message,
            "severity": self.severity,
            "sourceIp": self.source_ip,
            "destinationIp": self.destination_ip,
            "mitigated": bool(self.mitigated),
        }


class PolicyModel(db.Model):
    __tablename__ = "policies"
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(200), default="")
    description = db.Column(db.String(500), default="")
    action = db.Column(db.String(20), nullable=False)
    priority = db.Column(db.Integer, default=100)
    enabled = db.Column(db.Integer, default=1)
    match_json = db.Column(db.Text, default="{}")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "action": self.action,
            "priority": self.priority,
            "enabled": bool(self.enabled),
            "match": json.loads(self.match_json) if self.match_json else {},
        }


class LogModel(db.Model):
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.String(40), nullable=False)
    level = db.Column(db.String(10), nullable=False)
    message = db.Column(db.String(1000), nullable=False)


class SettingModel(db.Model):
    __tablename__ = "settings"
    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.String(500), nullable=False)


def init_db(app):
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sea.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    with app.app_context():
        db.create_all()
        _migrate_schema()
        _seed_defaults()


def _migrate_schema():
    try:
        db.session.execute(db.text("ALTER TABLE users ADD COLUMN role_id INTEGER DEFAULT 1 REFERENCES roles(id)"))
        db.session.commit()
    except Exception:
        db.session.rollback()


def _seed_defaults():
    if not RoleModel.query.first():
        roles = [
            RoleModel(id=1, name="admin", description="Full system access", permissions=json.dumps([
                "alerts.view", "alerts.mitigate", "alerts.clear", "alerts.export",
                "policies.view", "policies.create", "policies.edit", "policies.delete", "policies.import",
                "stats.view", "topology.view", "logs.view", "logs.download",
                "settings.view", "settings.edit",
                "users.view", "users.create", "users.delete",
                "roles.view", "roles.import",
            ]), is_builtin=1),
            RoleModel(id=2, name="analyst", description="Monitor alerts and apply mitigations", permissions=json.dumps([
                "alerts.view", "alerts.mitigate", "alerts.export",
                "policies.view",
                "stats.view", "topology.view", "logs.view",
                "settings.view",
            ]), is_builtin=1),
            RoleModel(id=3, name="viewer", description="Read-only access to dashboard", permissions=json.dumps([
                "alerts.view", "policies.view", "stats.view", "topology.view", "logs.view",
            ]), is_builtin=1),
        ]
        db.session.add_all(roles)

    if not UserModel.query.first():
        user = UserModel(
            username="admin",
            password="ntiyaga@1234",
            role_id=1,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        db.session.add(user)

    if not PolicyModel.query.first():
        defaults = [
            ("DDoS Mitigation", "Block traffic from IPs exceeding DDoS threshold", "BLOCK", 100, True, {"eth_type": 0x0800}),
            ("ICMP Flood Protection", "Rate-limit ICMP echo requests to prevent ping flood", "RATE_LIMIT", 95, True, {"eth_type": 0x0800, "ip_proto": 1}),
            ("Host Isolation", "Isolate compromised hosts from network traffic", "ISOLATE", 90, False, {}),
            ("Port Scan Prevention", "Block IPs scanning more than 20 ports in 2 seconds", "BLOCK", 98, True, {"eth_type": 0x0800}),
            ("SYN Flood Protection", "Drop excessive TCP SYN packets", "DROP", 97, True, {"eth_type": 0x0800, "ip_proto": 6, "tcp_flags": 2}),
            ("Traffic Mirroring", "Redirect suspicious traffic to monitoring/honeypot port", "REDIRECT", 85, False, {}),
            ("Malware Containment", "Quarantine hosts exhibiting malware-like behavior", "QUARANTINE", 92, False, {}),
            ("Known Malicious IPs", "Block traffic from blacklisted IP addresses", "BLOCK", 99, True, {"eth_type": 0x0800}),
            ("DNS Amplification Protection", "Rate-limit DNS responses to prevent amplification attacks", "RATE_LIMIT", 93, True, {"eth_type": 0x0800, "ip_proto": 17, "udp_dst": 53}),
            ("Suspicious Traffic Logging", "Log all traffic matching suspicious patterns for analysis", "LOG_ONLY", 80, True, {}),
            ("ARP Spoofing Detection", "Generate alert on ARP cache poisoning attempts", "ALERT", 88, True, {"eth_type": 0x0806}),
            ("Invalid TCP Flags", "Drop packets with invalid TCP flag combinations", "DROP", 96, True, {"eth_type": 0x0800, "ip_proto": 6}),
            ("UDP Flood Protection", "Rate-limit UDP traffic to prevent UDP flood attacks", "RATE_LIMIT", 94, True, {"eth_type": 0x0800, "ip_proto": 17}),
            ("Spoofed IP Protection", "Block traffic from internal IP ranges on external interfaces", "BLOCK", 99, True, {"eth_type": 0x0800}),
            ("Rogue DHCP Server", "Isolate unauthorized DHCP servers on the network", "ISOLATE", 91, True, {"eth_type": 0x0800, "udp_src": 67}),
        ]
        for name, desc, action, priority, enabled, match in defaults:
            policy = PolicyModel(
                id=f"policy_{uuid.uuid4().hex[:8]}",
                name=name,
                description=desc,
                action=action,
                priority=priority,
                enabled=int(enabled),
                match_json=json.dumps(match),
            )
            db.session.add(policy)

    if not SettingModel.query.first():
        for key, val in [("packet_rate", "1000"), ("byte_rate", "1000000"), ("ddos_packets", "10000")]:
            db.session.add(SettingModel(key=key, value=val))

    db.session.commit()
