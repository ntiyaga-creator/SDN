# SEA - Security Enforcement Application

SDN-based application for detecting and mitigating network attacks in Software-Defined Networking architecture.

---

## Database (SQLite)

The application uses **SQLite** via Flask-SQLAlchemy for persistent storage. The database file `sea.db` is created automatically in the project root on first run.

### Tables

| Table | Records | Purpose |
|-------|---------|---------|
| `users` | 1 | Admin credentials (default: admin / ntiyaga@1234) |
| `alerts` | dynamic | All security alerts with timestamp, severity, IPs, status |
| `policies` | 15 | Security policies with action, priority, enabled state, match criteria |
| `logs` | dynamic | Timestamped system log entries |
| `settings` | 3 | Detection thresholds (packet_rate, byte_rate, ddos_packets) |

### Key Features

- **Data persists across restarts** — alerts, logs, policies, and settings survive server shutdown
- **Auto-seeded on first run** — default admin user, 15 policies, and threshold settings are created automatically if the DB is empty
- **Zero configuration** — no database server needed, SQLite is embedded in Python
- **Safe concurrent access** — each API request uses `with app.app_context():` to ensure thread-safe DB operations
- **File location** — `sea.db` in the project root (can be deleted to reset all data)

## Project Overview

The Security Enforcement Application (SEA) is a full-stack web application that monitors network traffic in real time, detects security threats (DDoS, port scans, suspicious patterns), and enforces mitigation policies through a Software-Defined Networking (SDN) controller. The system can operate in **standalone mode** with built-in traffic simulation or connect to a **Ryu SDN controller** for real OpenFlow switch management.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser (dashboard.html)                  │
│  Bootstrap 5 UI  │  Chart.js  │  Socket.IO Client  │  Canvas    │
└────────────────────────┬────────────────────────────────────────┘
         │ HTTP REST API │         │ WebSocket (real-time)
         ▼               ▼         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Flask Server (app.py)                        │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────┐   │
│  │REST API │  │Auth/Sess │  │WebSocket │  │System Logger    │   │
│  │ Endpts  │  │Management│  │ Events   │  │ (timestamps)    │   │
│  └────┬────┘  └──────────┘  └──────────┘  └────────────────┘   │
│       │                                                         │
│  ┌────▼─────────────────────────────────────────────────────┐   │
│  │              SDN Abstraction Layer                        │   │
│  │  ┌─────────────────┐    ┌─────────────────────────────┐  │   │
│  │  │  RyuClient      │    │  TrafficMonitor (standalone) │  │   │
│  │  │  (sdn_client.py)│    │  (traffic_monitor.py)       │  │   │
│  │  └────────┬────────┘    └─────────────────────────────┘  │   │
│  └───────────┼──────────────────────────────────────────────┘   │
└──────────────┼──────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Ryu SDN Controller (ryu_app.py) - Optional                     │
│  ┌──────────┐  ┌────────────┐  ┌──────────────┐                │
│  │OpenFlow  │  │PacketIn    │  │REST API      │                │
│  │1.3       │  │Handler     │  │(port 8081)   │                │
│  └──────────┘  └────────────┘  └──────────────┘                │
└─────────────────────────────────────────────────────────────────┘
               │
               ▼
        OpenFlow Switches (physical or Mininet)
```

### Component Diagram

| Component | Language | Purpose |
|-----------|----------|---------|
| `app.py` | Python | Flask web server - REST API, WebSocket, authentication, session management |
| `dashboard.html` | HTML/JS/CSS | Frontend UI - Bootstrap 5, Chart.js, Socket.IO client |
| `models.py` | Python | Data models - Alert, Policy, TrafficStats, enums |
| `sdn_client.py` | Python | REST API client for Ryu SDN controller |
| `traffic_monitor.py` | Python | Standalone traffic simulation and attack detection engine |
| `ryu_app.py` | Python | Ryu SDN controller - OpenFlow 1.3, PacketIn handler, mitigation flows |
| `database.py` | Python | SQLite database models, initialization, and seed data |

---

## Files & Modules

### 1. `app.py` (409 lines) - Flask Backend Server

The core server that serves the dashboard, handles authentication, exposes REST API endpoints, manages WebSocket connections, and coordinates between the traffic monitor and SDN controller.

**Key Components:**

#### Authentication System
```python
ADMIN_USER = {"username": "admin", "password": "ntiyaga@1234"}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated
```

- Session-based authentication with Flask sessions
- `login_required` decorator protects all API routes
- Session lifetime: 8 hours (`PERMANENT_SESSION_LIFETIME = 28800`)

#### REST API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/` | No | Serves `dashboard.html` |
| POST | `/api/login` | No | Authenticate admin (username + password) |
| POST | `/api/logout` | No | Clear session |
| GET | `/api/check-auth` | No | Check if session is valid |
| POST | `/api/change-password` | Yes | Change admin password |
| GET | `/api/stats` | Yes | Get traffic statistics |
| GET | `/api/alerts` | Yes | Get security alerts (optional `?severity=` filter) |
| POST | `/api/alerts/clear` | Yes | Clear all alerts |
| GET | `/api/policies` | Yes | List security policies |
| POST | `/api/policies` | Yes | Add new policy |
| POST | `/api/policies/<id>/toggle` | Yes | Enable/disable a policy |
| DELETE | `/api/policies/<id>` | Yes | Delete a policy |
| GET | `/api/flows` | Yes | Get flow table entries |
| GET | `/api/topology` | Yes | Get network topology (switches, hosts, links) |
| GET | `/api/logs` | Yes | Get system logs |
| GET | `/api/logs/download` | Yes | Download logs as file |
| POST | `/api/mitigate` | Yes | Trigger mitigation action on an alert |
| GET/POST | `/api/settings` | Yes | Get/update detection thresholds |

#### WebSocket Events (Socket.IO)

| Event | Direction | Description |
|-------|-----------|-------------|
| `connect` | Client → Server | New WebSocket connection |
| `disconnect` | Client → Server | WebSocket disconnection |
| `connected` | Server → Client | Acknowledgment with status |
| `stats_update` | Server → Client | Real-time stats push (every 2s) |
| `traffic_update` | Server → Client | Traffic rate data for chart |
| `new_alert` | Server → Client | New security alert (immediate) |
| `alert_mitigated` | Server → Client | Alert mitigation confirmation |

#### Startup Sequence
1. `TrafficMonitor` starts background simulation thread
2. Checks if Ryu controller is reachable at `127.0.0.1:8081`
3. If connected, starts polling thread to sync alerts/stats from Ryu
4. If not connected, logs warning and runs in standalone mode
5. Starts Flask-SocketIO server on `0.0.0.0:5000`

---

### 2. `models.py` (81 lines) - Data Models

#### Severity Enum
```python
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
```

#### PolicyAction Enum
```python
class PolicyAction(str, Enum):
    BLOCK = "BLOCK"          # Block traffic from source IP
    DROP = "DROP"            # Silently drop matching packets
    RATE_LIMIT = "RATE_LIMIT"  # Rate-limit matching traffic
    ISOLATE = "ISOLATE"      # Isolate compromised host
    QUARANTINE = "QUARANTINE" # Quarantine for inspection
    REDIRECT = "REDIRECT"    # Mirror traffic to monitoring port
    LOG_ONLY = "LOG_ONLY"    # Log without action
    ALERT = "ALERT"          # Generate alert only
```

#### Alert Class
- UUID-based unique ID, ISO-8601 timestamp
- Fields: message, severity, source_ip, destination_ip, mitigated

#### Policy Class
- UUID-based ID, includes name, description, action, priority, enabled status, match criteria

#### TrafficStats Class
- Tracks: total_packets, total_alerts, active_rules, active_flows

---

### 3. `sdn_client.py` (78 lines) - Ryu REST API Client

HTTP client that communicates with the Ryu SDN controller's built-in REST API on port `8081`. All methods gracefully return `None` on failure, allowing the app to fall back to standalone mode.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `check_connection()` | `GET /ryu/stats` | Check if Ryu is reachable |
| `get_stats()` | `GET /ryu/stats` | Get traffic statistics |
| `get_alerts()` | `GET /ryu/alerts` | Get security alerts |
| `clear_alerts()` | `POST /ryu/alerts/clear` | Clear all alerts |
| `get_policies()` | `GET /ryu/policies` | List policies |
| `add_policy()` | `POST /ryu/policies` | Add new policy |
| `toggle_policy()` | `POST /ryu/policies/<id>/toggle` | Toggle policy |
| `delete_policy()` | `DELETE /ryu/policies/<id>` | Delete policy |
| `get_flows()` | `GET /ryu/flows` | Get flow entries |
| `get_topology()` | `GET /ryu/topology` | Get network topology |
| `mitigate()` | `POST /ryu/mitigate` | Mitigate an alert |
| `update_settings()` | `POST /ryu/settings` | Update detection thresholds |

---

### 4. `traffic_monitor.py` (120 lines) - Traffic Simulation & Attack Detection

Runs in a background thread (2-second interval) when operating in standalone mode (no Ryu controller).

**Simulated Traffic:**
- Random packet counts (50-500 packets per cycle)
- Random byte rates (packets × 64-1500 byte packets)
- Traffic rate history stored as timestamps + Mbps values (last 20 entries)

**Attack Simulation (probabilistic):**

| Attack | Probability | Severity | Detection Logic |
|--------|-------------|----------|-----------------|
| DDoS | 5% per cycle | CRITICAL | Tracks packet count per source IP; if > `ddos_threshold` (10,000), triggers alert |
| Port Scan | 8% per cycle | HIGH | Tracks unique destination ports per source IP; if > 20 unique ports, triggers alert |
| Suspicious Traffic | 10% per cycle | MEDIUM/LOW | Random source/dest IP combos with external destinations |

**Detection Thresholds (configurable via Settings page):**
- `packet_rate`: 1000 pps (general threshold)
- `byte_rate`: 1,000,000 Bps
- `ddos_packets`: 10,000 packets

---

### 5. `ryu_app.py` (326 lines) - Ryu SDN Controller

A Ryu application that manages OpenFlow 1.3 switches. Runs with `ryu-manager` and provides a REST API on port 8081.

**OpenFlow Event Handlers:**

| Event | Handler | Description |
|-------|---------|-------------|
| `EventOFPStateChange` | `_state_change_handler` | Track switch connect/disconnect |
| `EventOFPSwitchFeatures` | `_switch_features_handler` | Configure switch on connect, install table-miss flow |
| `EventOFPPacketIn` | `_packet_in_handler` | Analyze packets, detect DDoS/port scans, install mitigation flows |
| `EventOFPFlowStatsReply` | `_flow_stats_reply_handler` | Collect flow statistics |
| `EventOFPPortStatsReply` | `_port_stats_reply_handler` | Collect port statistics |

**Attack Detection (real traffic):**
- DDoS: Monitors packet-in rate per switch (last 2 seconds)
- Port Scan: Tracks unique TCP destination ports per source IP
- Automatic mitigation: installs drop flow with 300-second hard timeout on source IP

**REST API (port 8081):**
- Same endpoints as `sdn_client.py` expects (`/ryu/stats`, `/ryu/alerts`, etc.)
- Uses Python's built-in `http.server.HTTPServer`

---

### 6. `dashboard.html` (1332 lines) - Frontend UI

Single-page application built with Bootstrap 5, Chart.js, and Socket.IO.

**Pages:**

| Page | Features |
|------|----------|
| **Login** | Centered card with gradient background, username/password fields, error display, "Sign In" button |
| **Dashboard** | 4 stat cards (Total Packets, Alerts, Active Rules, Active Flows), Traffic Rate line chart, Alert Distribution doughnut chart, Recent Security Alerts table |
| **Alerts** | Full alert history table with severity filter dropdown, clear all button, status badges |
| **Policies** | 15 security policies with name/description, action badges (color-coded), priority, active/inactive status, toggle and delete buttons, add policy dialog |
| **Network Topology** | Canvas-drawn topology visualization with switches, hosts, controller, connection lines; device list |
| **Logs** | System log viewer with dark terminal-style display, download button |
| **Settings** | Detection threshold inputs (packet rate, byte rate, DDoS), auto-mitigation toggle, logging toggle, notification preferences, save/reset |

**JavaScript Classes:**

| Class | Purpose |
|-------|---------|
| `AuthManager` | Handles login page, authentication check, session management, logout |
| `SEADashboard` | Main dashboard - socket connection, charts, API calls, page navigation, real-time updates |

**Real-Time Features:**
- WebSocket connection via Socket.IO to `window.location.origin`
- Live stats updates pushed from server every 2 seconds
- Instant alert notifications via `new_alert` events
- Auto-refresh every 10 seconds via REST polling

---

## Security Policies (15 Built-in)

| # | Name | Action | Priority | Description |
|---|------|--------|----------|-------------|
| 1 | DDoS Mitigation | BLOCK | 100 | Block traffic from IPs exceeding DDoS threshold |
| 2 | ICMP Flood Protection | RATE_LIMIT | 95 | Rate-limit ICMP echo requests to prevent ping flood |
| 3 | Host Isolation | ISOLATE | 90 | Isolate compromised hosts from network traffic |
| 4 | Port Scan Prevention | BLOCK | 98 | Block IPs scanning more than 20 ports in 2 seconds |
| 5 | SYN Flood Protection | DROP | 97 | Drop excessive TCP SYN packets |
| 6 | Traffic Mirroring | REDIRECT | 85 | Redirect suspicious traffic to monitoring/honeypot port |
| 7 | Malware Containment | QUARANTINE | 92 | Quarantine hosts with malware-like behavior |
| 8 | Known Malicious IPs | BLOCK | 99 | Block blacklisted IP addresses |
| 9 | DNS Amplification Protection | RATE_LIMIT | 93 | Rate-limit DNS responses |
| 10 | Suspicious Traffic Logging | LOG_ONLY | 80 | Log all suspicious patterns for analysis |
| 11 | ARP Spoofing Detection | ALERT | 88 | Alert on ARP poisoning attempts |
| 12 | Invalid TCP Flags | DROP | 96 | Drop invalid TCP flag combinations |
| 13 | UDP Flood Protection | RATE_LIMIT | 94 | Rate-limit UDP traffic |
| 14 | Spoofed IP Protection | BLOCK | 99 | Block internal IP ranges on external interfaces |
| 15 | Rogue DHCP Server | ISOLATE | 91 | Isolate unauthorized DHCP servers |

---

## Installation & Setup

### Prerequisites
- Python 3.12+ (tested on 3.15 alpha)
- pip (Python package manager)

### Quick Start (Standalone Mode)
```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the application
python app.py

# 3. Open browser
#    http://localhost:5000
#    Login: admin / ntiyaga@1234
```

### With Ryu SDN Controller (Linux/WSL/Docker)
```bash
# 1. Install Ryu
pip install ryu

# 2. Run Ryu controller
ryu-manager ryu_app.py

# 3. In another terminal, run dashboard
python app.py

# 4. Open browser at http://localhost:5000
```

### With Mininet (Linux)
```bash
# Create a test network
sudo mn --controller remote,ip=127.0.0.1 --topo tree,3

# Ryu will detect switches and begin monitoring
```

---

## Dependencies

```
flask==3.1.1              # Web framework
flask-socketio==5.5.1     # WebSocket support
flask-cors==5.0.1         # Cross-origin requests
requests==2.32.3          # HTTP client for Ryu API
python-socketio==5.12.1   # Socket.IO protocol

# Optional: Ryu SDN controller (Linux only)
# pip install ryu==4.34
# ryu-manager ryu_app.py
```

**Frontend dependencies** (loaded from CDN):
- Bootstrap 5.3.0 (CSS + JS)
- Bootstrap Icons 1.11.0
- Chart.js 4.x
- Socket.IO 4.5.0 client

---

## API Testing

The application exposes a comprehensive REST API. All endpoints except `/api/login`, `/api/logout`, `/api/check-auth`, and `/` require session authentication.

```powershell
# Login
Invoke-WebRequest -Uri http://localhost:5000/api/login `
  -Method POST `
  -ContentType 'application/json' `
  -Body '{"username":"admin","password":"ntiyaga@1234"}' `
  -SessionVariable session

# Get stats (authenticated)
Invoke-WebRequest -Uri http://localhost:5000/api/stats `
  -WebSession $session

# List policies
Invoke-WebRequest -Uri http://localhost:5000/api/policies `
  -WebSession $session

# Get alerts
Invoke-WebRequest -Uri http://localhost:5000/api/alerts `
  -WebSession $session

# Get topology
Invoke-WebRequest -Uri http://localhost:5000/api/topology `
  -WebSession $session

# Get logs
Invoke-WebRequest -Uri http://localhost:5000/api/logs `
  -WebSession $session

# Logout
Invoke-WebRequest -Uri http://localhost:5000/api/logout `
  -Method POST `
  -WebSession $session
```

---

## Project File Structure

```
SDN/
├── app.py                 # Flask server (409 lines)
├── models.py              # Data models (81 lines)
├── sdn_client.py          # Ryu REST API client (78 lines)
├── traffic_monitor.py     # Traffic simulation & detection (120 lines)
├── ryu_app.py             # Ryu SDN controller (326 lines)
├── dashboard.html         # Frontend UI (1332 lines)
├── requirements.txt       # Python dependencies (5 packages)
├── README.md              # This documentation
└── dashboard.zip          # Original archive (backup)
```

---

## Key Features Summary

| Feature | Implementation |
|---------|---------------|
| Admin Authentication | Flask sessions with `login_required` decorator |
| Real-time Dashboard | WebSocket (Socket.IO) + REST API polling |
| Traffic Visualization | Chart.js line chart (rate) + doughnut chart (alerts) |
| Attack Detection | DDoS, Port Scan, Suspicious Traffic |
| Mitigation Actions | BLOCK, DROP, RATE_LIMIT, ISOLATE, QUARANTINE, REDIRECT |
| Policy Management | 15 built-in policies, CRUD via API + UI |
| Network Topology | Canvas visualization + device list |
| System Logging | Timestamped log viewer with download |
| SDN Integration | Ryu OpenFlow 1.3 controller (optional) |
| Standalone Mode | Built-in traffic simulation (no switch needed) |
| Configurable Thresholds | Packet rate, byte rate, DDoS detection limits |

---

## License

This project is developed for SDN security research and educational purposes.
