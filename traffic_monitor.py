import random
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

from models import Alert, Severity

logger = logging.getLogger(__name__)


class TrafficMonitor:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self._running = False
        self._thread = None
        self.total_packets = 0
        self.packet_rate = 0
        self.byte_rate = 0
        self.active_flows_count = 0
        self.packet_history = defaultdict(list)
        self.traffic_data = {"timestamps": [], "rates": []}
        self.detection_thresholds = {
            "packet_rate": 1000,
            "byte_rate": 1000000,
            "ddos_packets": 10000,
        }

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("Traffic monitor started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("Traffic monitor stopped")

    def _monitor_loop(self):
        suspicious_ips = defaultdict(int)
        port_scan_tracker = defaultdict(set)

        while self._running:
            simulated_packets = random.randint(50, 500)
            self.total_packets += simulated_packets
            self.packet_rate = simulated_packets
            self.byte_rate = simulated_packets * random.randint(64, 1500)
            self.active_flows_count = random.randint(50, 200)

            now = datetime.now(timezone.utc)
            self.traffic_data["timestamps"].append(now.strftime("%H:%M:%S"))
            rate_mbps = round(self.byte_rate / 125000, 2)
            self.traffic_data["rates"].append(rate_mbps)
            if len(self.traffic_data["timestamps"]) > 20:
                self.traffic_data["timestamps"].pop(0)
                self.traffic_data["rates"].pop(0)

            self._simulate_attacks(suspicious_ips, port_scan_tracker)

            if self.alert_callback:
                self.alert_callback({
                    "totalPackets": self.total_packets,
                    "packetRate": self.packet_rate,
                    "byteRate": self.byte_rate,
                    "activeFlows": self.active_flows_count,
                    "trafficData": self.traffic_data,
                })

            time.sleep(2)

    def _simulate_attacks(self, suspicious_ips, port_scan_tracker):
        if random.random() < 0.05:
            src = f"192.168.1.{random.randint(2, 254)}"
            dst = f"10.0.0.{random.randint(1, 10)}"
            suspicious_ips[src] += random.randint(500, 2000)

            if suspicious_ips[src] > self.detection_thresholds["ddos_packets"]:
                alert = Alert(
                    message=f"DDoS attack detected from {src}",
                    severity=Severity.CRITICAL,
                    source_ip=src,
                    destination_ip=dst,
                )
                if self.alert_callback:
                    self.alert_callback({"alert": alert.to_dict()})
                suspicious_ips[src] = 0

        if random.random() < 0.08:
            src = f"192.168.1.{random.randint(2, 254)}"
            dst = f"10.0.0.{random.randint(1, 10)}"
            port = random.randint(1, 65535)
            port_scan_tracker[src].add(port)

            if len(port_scan_tracker[src]) > 20:
                alert = Alert(
                    message=f"Port scan detected from {src} ({len(port_scan_tracker[src])} ports)",
                    severity=Severity.HIGH,
                    source_ip=src,
                    destination_ip=dst,
                )
                if self.alert_callback:
                    self.alert_callback({"alert": alert.to_dict()})
                port_scan_tracker[src] = set()

        if random.random() < 0.1:
            src = f"10.0.0.{random.randint(1, 10)}"
            dst = f"8.8.8.{random.randint(1, 8)}" if random.random() < 0.5 else f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
            alert = Alert(
                message="Suspicious traffic pattern detected",
                severity=random.choice([Severity.MEDIUM, Severity.LOW]),
                source_ip=src,
                destination_ip=dst,
            )
            if self.alert_callback:
                self.alert_callback({"alert": alert.to_dict()})
