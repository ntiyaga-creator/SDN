import uuid
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class PolicyAction(str, Enum):
    BLOCK = "BLOCK"
    DROP = "DROP"
    RATE_LIMIT = "RATE_LIMIT"
    ISOLATE = "ISOLATE"
    QUARANTINE = "QUARANTINE"
    REDIRECT = "REDIRECT"
    LOG_ONLY = "LOG_ONLY"
    ALERT = "ALERT"


class Alert:
    def __init__(self, message, severity, source_ip, destination_ip, mitigated=False):
        self.id = str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.message = message
        self.severity = severity
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.mitigated = mitigated

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "message": self.message,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "sourceIp": self.source_ip,
            "destinationIp": self.destination_ip,
            "mitigated": self.mitigated,
        }


class Policy:
    def __init__(self, action, name="", description="", priority=100, enabled=True, match=None):
        self.id = f"policy_{uuid.uuid4().hex[:8]}"
        self.action = action
        self.name = name
        self.description = description
        self.priority = priority
        self.enabled = enabled
        self.match = match or {}

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "action": self.action.value if isinstance(self.action, PolicyAction) else self.action,
            "priority": self.priority,
            "enabled": self.enabled,
            "match": self.match,
        }


class TrafficStats:
    def __init__(self):
        self.total_packets = 0
        self.total_alerts = 0
        self.active_rules = 0
        self.active_flows = 0

    def to_dict(self):
        return {
            "totalPackets": self.total_packets,
            "totalAlerts": self.total_alerts,
            "activeRules": self.active_rules,
            "activeFlows": self.active_flows,
        }
