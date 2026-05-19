import json
import time
from collections import defaultdict
from threading import Thread
from http.server import HTTPServer, BaseHTTPRequestHandler

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.topology.api import get_switch, get_link, get_host
from ryu.lib import hub

from models import Alert, Severity, Policy, PolicyAction


class SEARyuController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "sea_controller"

        self.datapaths = {}
        self.flow_stats = {}
        self.port_stats = {}
        self.packet_counts = defaultdict(int)
        self.packet_history = defaultdict(list)
        self.port_scan_tracker = defaultdict(set)

        self.alerts = []
        self.policies = [
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
            Policy(PolicyAction.DROP, "Invalid TCP Flags", "Drop packets with invalid TCP flag combinations", priority=96, match={"eth_type": 0x0800, "ip_proto": 6}),
            Policy(PolicyAction.RATE_LIMIT, "UDP Flood Protection", "Rate-limit UDP traffic to prevent UDP flood attacks", priority=94, match={"eth_type": 0x0800, "ip_proto": 17}),
            Policy(PolicyAction.BLOCK, "Spoofed IP Protection", "Block traffic from internal IP ranges on external interfaces", priority=99, match={"eth_type": 0x0800}),
            Policy(PolicyAction.ISOLATE, "Rogue DHCP Server", "Isolate unauthorized DHCP servers on the network", priority=91, match={"eth_type": 0x0800, "udp_src": 67}),
        ]

        self.detection_thresholds = {
            "packet_rate": 1000,
            "byte_rate": 1000000,
            "ddos_packets": 10000,
        }

        self.monitor_thread = hub.spawn(self._stats_poller)
        self.rest_server = None

    def start(self):
        super().start()
        self._start_rest_server()

    def _start_rest_server(self):
        def run_rest():
            server = HTTPServer(("127.0.0.1", 8081), self._make_rest_handler())
            self.rest_server = server
            server.serve_forever()

        t = Thread(target=run_rest, daemon=True)
        t.start()
        self.logger.info("REST API server started on 127.0.0.1:8081")

    def _make_rest_handler(self):
        controller = self

        class Handler(BaseHTTPRequestHandler):
            def _send_json(self, data, status=200):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.end_headers()

            def do_GET(self):
                if self.path == "/ryu/stats":
                    stats = {
                        "totalPackets": sum(controller.packet_counts.values()),
                        "totalAlerts": len(controller.alerts),
                        "activeRules": len([p for p in controller.policies if p.enabled]),
                        "activeFlows": sum(len(f) for f in controller.flow_stats.values()),
                        "datapathCount": len(controller.datapaths),
                    }
                    self._send_json(stats)
                elif self.path == "/ryu/alerts":
                    self._send_json([a.to_dict() for a in controller.alerts])
                elif self.path == "/ryu/policies":
                    self._send_json([p.to_dict() for p in controller.policies])
                elif self.path == "/ryu/flows":
                    flows = []
                    for dpid, flows_list in controller.flow_stats.items():
                        for f in flows_list:
                            f["dpid"] = dpid
                            flows.append(f)
                    self._send_json(flows)
                elif self.path == "/ryu/topology":
                    switches = get_switch(controller, None)
                    links = get_link(controller, None)
                    hosts = get_host(controller, None)
                    self._send_json({
                        "switches": [{"dpid": str(s.dp.id), "ports": [p.to_dict() for p in s.ports]} for s in switches],
                        "links": [{"src": {"dpid": str(l.src.dpid), "port": l.src.port_no}, "dst": {"dpid": str(l.dst.dpid), "port": l.dst.port_no}} for l in links],
                        "hosts": [{"mac": h.mac, "ip": h.ipv4, "port": h.port.port_no, "dpid": str(h.port.dpid)} for h in hosts] if hosts else [],
                    })
                elif self.path == "/ryu/settings":
                    self._send_json(controller.detection_thresholds)
                else:
                    self._send_json({"error": "not found"}, 404)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode() if length else "{}"
                data = json.loads(body) if body else {}

                if self.path == "/ryu/alerts/clear":
                    controller.alerts.clear()
                    self._send_json({"status": "ok"})
                elif self.path == "/ryu/mitigate":
                    alert_id = data.get("alertId")
                    for alert in controller.alerts:
                        if alert.id == alert_id:
                            alert.mitigated = True
                            controller._install_mitigation_flow(alert)
                            self._send_json({"status": "ok", "mitigated": True})
                            return
                    self._send_json({"error": "not found"}, 404)
                elif self.path == "/ryu/policies":
                    action = PolicyAction(data.get("action", "LOG_ONLY").upper())
                    name = data.get("name", "")
                    description = data.get("description", "")
                    priority = data.get("priority", 100)
                    enabled = data.get("enabled", True)
                    controller.policies.append(Policy(action, name, description, priority, enabled))
                    self._send_json(controller.policies[-1].to_dict(), 201)
                elif self.path.startswith("/ryu/policies/") and self.path.endswith("/toggle"):
                    policy_id = self.path.split("/")[3]
                    for p in controller.policies:
                        if p.id == policy_id:
                            p.enabled = not p.enabled
                            self._send_json(p.to_dict())
                            return
                    self._send_json({"error": "not found"}, 404)
                elif self.path.startswith("/ryu/settings"):
                    controller.detection_thresholds.update({
                        "packet_rate": data.get("packetThreshold", controller.detection_thresholds["packet_rate"]),
                        "byte_rate": data.get("byteThreshold", controller.detection_thresholds["byte_rate"]),
                        "ddos_packets": data.get("ddosThreshold", controller.detection_thresholds["ddos_packets"]),
                    })
                    self._send_json({"status": "ok"})
                else:
                    self._send_json({"error": "not found"}, 404)

            def do_DELETE(self):
                if self.path.startswith("/ryu/policies/"):
                    policy_id = self.path.split("/")[3]
                    controller.policies = [p for p in controller.policies if p.id != policy_id]
                    self._send_json({"status": "ok"})
                else:
                    self._send_json({"error": "not found"}, 404)

            def log_message(self, format, *args):
                pass

        return Handler

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("Switch connected: %s", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)
            self.logger.info("Switch disconnected: %s", dp.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        dp = ev.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        msg = parser.OFPSetConfig(dp, ofproto.OFPC_FRAG_NORMAL, 0)
        dp.send_msg(msg)

        self._install_table_miss(dp)

    def _install_table_miss(self, dp):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=0, match=match,
            instructions=inst, table_id=0,
            command=ofproto.OFPFC_ADD
        )
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        dp = ev.datapath
        pkt = packet.Packet(ev.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        dpid = dp.id
        self.packet_counts[dpid] += 1

        now = time.time()
        self.packet_history[dpid].append(now)

        cutoff = now - 2
        self.packet_history[dpid] = [t for t in self.packet_history[dpid] if t > cutoff]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        rate = len(self.packet_history[dpid])
        if rate > self.detection_thresholds["packet_rate"] * 2:
            alert = Alert(
                message=f"DDoS attack detected from {src_ip} (rate: {rate} pps)",
                severity=Severity.CRITICAL,
                source_ip=src_ip,
                destination_ip=dst_ip,
            )
            self.alerts.insert(0, alert)
            self.logger.warning("DDoS alert: %s", alert.message)
            for policy in self.policies:
                if policy.enabled and policy.action == PolicyAction.BLOCK:
                    self._install_mitigation_flow(alert)
                    alert.mitigated = True
                    break

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            self.port_scan_tracker[src_ip].add(tcp_pkt.dst_port)
            if len(self.port_scan_tracker[src_ip]) > 20:
                alert = Alert(
                    message=f"Port scan detected from {src_ip} ({len(self.port_scan_tracker[src_ip])} ports)",
                    severity=Severity.HIGH,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                )
                self.alerts.insert(0, alert)
                self.logger.warning("Port scan alert: %s", alert.message)
                self.port_scan_tracker[src_ip] = set()

    def _install_mitigation_flow(self, alert):
        if not alert.source_ip:
            return
        for dpid, dp in list(self.datapaths.items()):
            parser = dp.ofproto_parser
            ofproto = dp.ofproto

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=alert.source_ip)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
            mod = parser.OFPFlowMod(
                datapath=dp, priority=200, match=match,
                instructions=inst, table_id=0,
                command=ofproto.OFPFC_ADD,
                hard_timeout=300,
            )
            dp.send_msg(mod)
            self.logger.info("Mitigation flow installed on %s for %s", dpid, alert.source_ip)

    def _stats_poller(self):
        while True:
            for dpid, dp in list(self.datapaths.items()):
                self._request_flow_stats(dp)
                self._request_port_stats(dp)
            hub.sleep(5)

    def _request_flow_stats(self, dp):
        parser = dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(dp, 0, ofproto_v1_3.OFPTT_ALL, ofproto_v1_3.OFPP_ANY, ofproto_v1_3.OFPG_ANY, 0, 0, parser.OFPMatch())
        dp.send_msg(req)

    def _request_port_stats(self, dp):
        parser = dp.ofproto_parser
        req = parser.OFPPortStatsRequest(dp, 0, ofproto_v1_3.OFPP_ANY)
        dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.datapath.id
        self.flow_stats[dpid] = [
            {"priority": s.priority, "packets": s.packet_count, "bytes": s.byte_count,
             "duration": s.duration_sec, "idle": s.idle_timeout, "hard": s.hard_timeout,
             "table": s.table_id}
            for s in ev.msg.body
        ]

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.datapath.id
        self.port_stats[dpid] = [
            {"port": s.port_no, "rx_packets": s.rx_packets, "tx_packets": s.tx_packets,
             "rx_bytes": s.rx_bytes, "tx_bytes": s.tx_bytes,
             "rx_errors": s.rx_errors, "tx_errors": s.tx_errors}
            for s in ev.msg.body
        ]
