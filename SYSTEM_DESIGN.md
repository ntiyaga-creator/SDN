# SEA — System Design Document

> Security Enforcement Application for Software-Defined Networking

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture](#2-architecture)
3. [Component Design](#3-component-design)
4. [Database Design](#4-database-design)
5. [API Design](#5-api-design)
6. [Security Design](#6-security-design)
7. [Algorithm Design](#7-algorithm-design)
8. [UI/UX Prototype](#8-uiux-prototype)
9. [Deployment Architecture](#9-deployment-architecture)
10. [Testing Strategy](#10-testing-strategy)
11. [Appendices](#11-appendices)

---

## 1. System Overview

### 1.1 Purpose

SEA is a full-stack web application for detecting, visualizing, and mitigating network security threats in Software-Defined Networking (SDN) environments. It provides real-time traffic monitoring, automated attack detection (DDoS, port scans, suspicious patterns), and policy-based mitigation enforcement through SDN controllers.

### 1.2 Scope

| In Scope | Out of Scope |
|----------|-------------|
| Real-time traffic monitoring & visualization | Packet-level deep inspection |
| DDoS / port scan / anomaly detection | IPS/IDS signature matching |
| Policy-based automated mitigation | Firewall rule management |
| User authentication & role-based access | Multi-tenant isolation |
| REST API + WebSocket interface | SNMP / NetFlow integration |
| SQLite (dev) / PostgreSQL (prod) persistence | Distributed database clustering |
| Ryu SDN controller integration | Multi-controller orchestration |

### 1.3 System Goals

1. **Real-time visibility** — sub-second alert delivery via WebSocket
2. **Automated detection** — probability-based attack simulation with configurable thresholds
3. **Policy enforcement** — 8 action types (BLOCK, DROP, RATE_LIMIT, ISOLATE, QUARANTINE, REDIRECT, LOG_ONLY, ALERT)
4. **Role-based access** — 3 built-in roles (admin, analyst, viewer) with granular permissions
5. **Portable deployment** — single-file SQLite for dev, PostgreSQL for production, CDN-loaded frontend

### 1.4 Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Backend Framework | Flask (Python) | 3.1.1 |
| Real-time | Flask-SocketIO | 5.5.1 |
| ORM | Flask-SQLAlchemy | 3.1.1 |
| Database (dev) | SQLite | 3.x |
| Database (prod) | PostgreSQL | 15+ (Render) |
| Frontend | Bootstrap 5 | 5.3.0 |
| Charts | Chart.js | 4.x |
| WebSocket Client | Socket.IO | 4.5.0 |
| SDN Controller | Ryu (optional) | 4.34 |
| Production Server | Gunicorn + Eventlet | 23.0 / 0.38 |
| Hosting | Render (free tier) | — |

---

## 2. Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            CLIENT LAYER                                 │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    Browser (dashboard.html)                      │    │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌─────────────┐   │    │
│  │  │ Bootstrap│  │ Chart.js │  │ Socket.IO  │  │ AuthManager │   │    │
│  │  │  5 UI    │  │  Charts  │  │  WebSocket │  │ (JS Class)  │   │    │
│  │  └──────────┘  └──────────┘  └────────────┘  └─────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                   ┌─────────────┼─────────────┐
                   │  HTTP REST  │  WebSocket   │
                   │  (JSON)     │  (Socket.IO) │
                   ▼             ▼              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          APPLICATION LAYER                              │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                     Flask Server (app.py)                        │    │
│  │                                                                  │    │
│  │  ┌────────────┐  ┌─────────────┐  ┌───────────┐  ┌──────────┐   │    │
│  │  │ REST API   │  │ SocketIO    │  │ Auth &    │  │ Logging  │   │    │
│  │  │ Controllers│  │ Events      │  │ Sessions  │  │ System   │   │    │
│  │  └─────┬──────┘  └─────────────┘  └───────────┘  └──────────┘   │    │
│  │        │                                                        │    │
│  │  ┌─────▼────────────────────────────────────────────────────┐   │    │
│  │  │                   SDN Abstraction Layer                   │   │    │
│  │  │  ┌────────────────────────┐  ┌────────────────────────┐  │   │    │
│  │  │  │  RyuClient             │  │  TrafficMonitor        │  │   │    │
│  │  │  │  (sdn_client.py)       │  │  (traffic_monitor.py)  │  │   │    │
│  │  │  │  REST → Ryu :8081      │  │  Background thread     │  │   │    │
│  │  │  └───────────┬────────────┘  │  Simulates traffic     │  │   │    │
│  │  │              │               │  + attack detection    │  │   │    │
│  │  │              │               └────────────────────────┘  │   │    │
│  │  └──────────────┼───────────────────────────────────────────┘   │    │
│  └─────────────────┼───────────────────────────────────────────────┘    │
│                    │                                                     │
│  ┌─────────────────▼───────────────────────────────────────────────┐    │
│  │                     DATA LAYER                                   │    │
│  │                                                                  │    │
│  │  ┌─────────────────────────┐  ┌──────────────────────────────┐   │    │
│  │  │  SQLAlchemy ORM         │  │  In-Memory TrafficStats      │   │    │
│  │  │  (database.py)          │  │  (models.py)                 │   │    │
│  │  │  Users / Roles /        │  │  total_packets, alerts,      │   │    │
│  │  │  Alerts / Policies /    │  │  active_rules, active_flows │   │    │
│  │  │  Logs / Settings        │  │                              │   │    │
│  │  └───────────┬─────────────┘  └──────────────────────────────┘   │    │
│  └──────────────┼───────────────────────────────────────────────────┘    │
└─────────────────┼────────────────────────────────────────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    │              │              │
    ▼              ▼              ▼
┌──────────┐ ┌──────────┐ ┌──────────────┐
│ SQLite   │ │PostgreSQL│ │ Ryu SDN      │
│ (dev)    │ │(prod)    │ │ Controller   │
│ sea.db   │ │Render DB │ │ :8081        │
└──────────┘ └──────────┘ └──────────────┘
                              │
                              ▼
                         ┌──────────┐
                         │ OpenFlow │
                         │ Switches │
                         └──────────┘
```

### 2.2 Data Flow Diagrams

#### 2.2.1 Login Flow

```
Browser                    Flask Server                 SQLite/PostgreSQL
  │                            │                              │
  │  POST /api/login           │                              │
  │  {username, password}      │                              │
  │ ─────────────────────────► │                              │
  │                            │  UserModel.query.filter_by() │
  │                            │ ────────────────────────────►│
  │                            │  ◄───────────────────────────│
  │                            │                              │
  │                            │  RoleModel.query.get(role_id)│
  │                            │ ────────────────────────────►│
  │                            │  ◄───────────────────────────│
  │                            │                              │
  │                            │  Session[permissions] = [...]│
  │                            │  Session[logged_in] = True   │
  │                            │                              │
  │  ◄─────────────────────────│                              │
  │  {status, role, username}  │                              │
```

#### 2.2.2 Alert Flow

```
TrafficMonitor (bg thread)         Flask Server           Browser (WebSocket)
        │                              │                        │
        │  Detects attack              │                        │
        │  (DDoS / Port Scan /         │                        │
        │   Suspicious Traffic)        │                        │
        │                              │                        │
        │  alert_callback(data)        │                        │
        │ ──────────────────────────►  │                        │
        │                              │                        │
        │               ┌──────────────┤                        │
        │               │ Save to DB   │                        │
        │               │ (AlertModel) │                        │
        │               └──────────────┤                        │
        │                              │                        │
        │                              │  socketio.emit         │
        │                              │  ("new_alert", alert)  │
        │                              │ ─────────────────────►│
        │                              │                        │
        │                              │                        │
        │  Every 2s                    │  Display alert in      │
        │  ──────────────────────────► │  table + notification  │
        │                              │                        │
```

#### 2.2.3 Policy Enforcement Flow

```
Admin (UI)              Flask Server             SDN Layer             Database
    │                        │                      │                    │
    │  Click "Mitigate"      │                      │                    │
    │ ──────────────────────►│                      │                    │
    │                        │                      │                    │
    │                        │  POST /api/mitigate   │                    │
    │                        │  {alertId: "..."}    │                    │
    │                        │                      │                    │
    │                        │  ┌───────────────────┤                    │
    │                        │  │ Update DB:        │                    │
    │                        │  │ mitigated = 1     │                    │
    │                        │  │                   │                    │
    │                        │  │ If Ryu connected: │                    │
    │                        │  │ ryu.mitigate()   │                    │
    │                        │  │ ─────────────────►│                    │
    │                        │  │  Install drop flow│                    │
    │                        │  │  on switch        │                    │
    │                        │  └───────────────────┤                    │
    │                        │                      │                    │
    │  ◄─────────────────────│                      │                    │
    │  {mitigated: true}     │                      │                    │
    │                        │                      │                    │
    │  WebSocket:            │                      │                    │
    │  alert_mitigated       │                      │                    │
    │ ◄──────────────────────│                      │                    │
```

### 2.3 State Diagrams

#### 2.3.1 Application States

```
┌──────────┐    ┌──────────┐    ┌────────────┐    ┌─────────────┐
│INITIALIZE├───►│   IDLE   ├───►│ MONITORING ├───►│ MITIGATING  │
│ - DB     │    │ - Waiting│    │ - Active   │    │ - Attack    │
│ - Seed   │    │   for    │    │   traffic  │    │   response  │
│ - Config │    │   login  │    │   analysis │    │   active    │
└──────────┘    └──────────┘    └─────┬──────┘    └──────┬──────┘
                                       │                  │
                                       │  Attack detected │
                                       │ ◄────────────────┘
                                       │
                                       ▼
                                  ┌──────────┐
                                  │  ERROR   │
                                  │ - Ryu    │
                                  │   conn   │
                                  │   loss   │
                                  └──────────┘
```

#### 2.3.2 Policy Lifecycle

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│ CREATED  ├────►│ ACTIVE   ├────►│ TRIGGERED│
│ (default │     │ (enabled)│     │ (applied)│
│  enabled │     │          │     │          │
└──────────┘     └────┬─────┘     └──────────┘
                      │                 │
                      │ Disable         │ Expired / Removed
                      ▼                 ▼
                 ┌──────────┐     ┌──────────┐
                 │ INACTIVE │     │ DELETED  │
                 └──────────┘     └──────────┘
```

---

## 3. Component Design

### 3.1 Backend Components (`app.py`)

#### 3.1.1 Module Structure

```
app.py
├── Configuration (SECRET_KEY, CORS, Session)
├── Database Initialization (init_db)
├── Decorators
│   ├── login_required         — Session check → 401
│   └── role_required(perms)   — Permission check → 403
├── REST Controllers (17 endpoints)
│   ├── Auth: login, logout, check-auth, change-password
│   ├── Alerts: GET, export CSV, clear, mitigate
│   ├── Policies: GET, POST, toggle, delete, import
│   ├── Users: GET, POST, DELETE
│   ├── Roles: GET, import
│   ├── Stats, Flows, Topology, Logs (GET/download), Settings
├── WebSocket Handlers (connect, disconnect)
├── Background Threads
│   ├── TrafficMonitor (2s interval)
│   └── RyuPoller (3s interval, only if connected)
└── Startup / Shutdown Logic
```

#### 3.1.2 Decorator Chain

```
Request
  │
  ▼
┌─────────────────────────────┐
│  Flask Route Match          │
│  app.route("/api/alerts")   │
└─────────┬───────────────────┘
          │
          ▼
┌─────────────────────────────┐
│  @login_required            │
│  session.get("logged_in")   │
│  ? → 401 if False           │
└─────────┬───────────────────┘
          │
          ▼
┌─────────────────────────────┐
│  @role_required("alerts.*") │
│  permisssions in session    │
│  ? → 403 if missing         │
└─────────┬───────────────────┘
          │
          ▼
┌─────────────────────────────┐
│  View Function              │
│  def get_alerts(): ...      │
└─────────────────────────────┘
```

### 3.2 Frontend Components (`dashboard.html`)

#### 3.2.1 Page Structure

```
dashboard.html
├── Login Page (#loginPage)
│   └── Login form with AuthManager JS class
│
└── Dashboard (#dashboardApp)
    ├── Sidebar (nav - 8 pages)
    ├── Top Bar (user menu, dark mode toggle, refresh)
    └── Pages
        ├── Dashboard (#dashboard-page)
        │   ├── Stats Cards (4)
        │   ├── Traffic Chart (line)
        │   ├── Alert Chart (doughnut)
        │   └── Recent Alerts Table
        ├── Alerts (#alerts-page)
        │   ├── Filter Bar (severity, status, search, dates)
        │   ├── Full Alerts Table
        │   └── Export CSV + Clear buttons
        ├── Policies (#policies-page)
        │   ├── Policy Table (name, action, priority, status)
        │   └── Import JSON + Add buttons
        ├── Topology (#topology-page)
        │   ├── Canvas Topology View
        │   └── Device List
        ├── Users (#users-page)
        │   ├── User Table
        │   └── Add User Modal
        ├── Roles (#roles-page)
        │   ├── Role Table (name, permissions)
        │   └── Import JSON button
        ├── Logs (#logs-page)
        │   └── Log Viewer + Download
        └── Settings (#settings-page)
            └── Thresholds, toggles, save/reset
```

#### 3.2.2 JavaScript Classes

```
AuthManager
├── Properties: loginForm, loginPage, dashboardApp
├── Methods:
│   ├── checkAuth()        — GET /api/check-auth on load
│   ├── doLogin()          — POST /api/login
│   ├── doLogout()         — POST /api/logout
│   └── showDashboard()    — Hide login, init SEADashboard

SEADashboard
├── Properties: socket, charts, alertsData, trafficData
├── Lifecycle:
│   ├── init()
│   │   ├── connectSocket()
│   │   ├── bindEvents()
│   │   ├── initializeCharts()
│   │   ├── loadInitialData()
│   │   ├── startAutoRefresh()
│   │   ├── updateLiveTime()
│   │   └── initDarkMode()
│   │
│   ├── WebSocket Events:
│   │   ├── stats_update      → Update stat cards + badge
│   │   ├── traffic_update    → Update line chart
│   │   ├── new_alert         → Prepend to table + notification
│   │   └── alert_mitigated   → Update alert status
│   │
│   └── REST Methods:
│       ├── fetchStats() / fetchAlerts() / fetchPolicies()
│       ├── fetchUsers() / fetchRoles() / fetchFlows()
│       ├── loadTopology() / loadLogs()
│       ├── mitigate() / togglePolicy() / deletePolicy()
│       ├── addPolicy() / addUser() / deleteUser()
│       ├── importPoliciesDialog() / importRolesDialog()
│       ├── exportAlertsCsv() / clearAlerts()
│       └── saveSettings() / resetSettings()
```

### 3.3 SDN Abstraction Layer

#### 3.3.1 Dual-Mode Architecture

```
┌─────────────────────────────────────┐
│           app.py                    │
│         (no SDN awareness)          │
└────────────────┬────────────────────┘
                 │
    ┌────────────┴────────────┐
    │                         │
    ▼                         ▼
┌──────────────┐     ┌──────────────────┐
│ RyuClient    │     │ TrafficMonitor   │
│ (sdn_client) │     │ (traffic_monitor)│
│              │     │                  │
│ Real SDN     │     │ Simulated        │
│ Controller   │     │ Standalone Mode  │
│ OpenFlow 1.3 │     │ No hardware      │
└──────┬───────┘     └──────────────────┘
       │
       ▼
┌──────────────┐
│ Ryu REST API │
│ :8081        │
│ ryu_app.py   │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ OpenFlow 1.3 │
│ Switches     │
└──────────────┘
```

#### 3.3.2 Connection Strategy

```
Startup
  │
  ├── ryu_client.check_connection()
  │     │
  │     ├── Success → Start RyuPoller thread (3s), use real data
  │     │
  │     └── Failure → log "standalone mode", use TrafficMonitor
  │
  └── All API methods fall back gracefully:
       ┌──────────┬────────────────┬──────────────┐
       │ Endpoint │ Ryu Available  │ Standalone   │
       ├──────────┼────────────────┼──────────────┤
       │ /stats   │ Ryu stats      │ Simulated    │
       │ /alerts  │ Ryu alerts     │ Generated    │
       │ /policies│ Ryu policies   │ DB policies  │
       │ /flows   │ Ryu flows      │ Generated    │
       │ /topology│ Ryu topology   │ Demo topology│
       └──────────┴────────────────┴──────────────┘
```

### 3.4 Traffic Monitor (`traffic_monitor.py`)

```
┌────────────────────────────────────────────────────────────—┐
│ TrafficMonitor                                                │
│                                                               │
│  Background Thread (2s interval)                              │
│                                                               │
│  ┌──────────────────────────────────────────────────┐         │
│  │  simulate_traffic_cycle()                         │         │
│  │                                                    │         │
│  │  1. Generate random packets (50-500)              │         │
│  │  2. Generate random bytes (packets × 64-1500)     │         │
│  │  3. Update traffic history (last 20 entries)       │         │
│  │  4. Check thresholds → callback if exceeded       │         │
│  │  5. Attack simulation:                            │         │
│  │     ├── 5% DDoS → CRITICAL                        │         │
│  │     ├── 8% Port Scan → HIGH                       │         │
│  │     └── 10% Suspicious Traffic → MEDIUM/LOW       │         │
│  └──────────────────────────────────────────────────┘         │
│                                                               │
│  Detection Thresholds (configurable via Settings API):        │
│  ┌───────────┬──────────┬────────────────────────┐            │
│  │ Threshold │ Default  │ Trigger                │            │
│  ├───────────┼──────────┼────────────────────────┤            │
│  │ pkt_rate  │ 1000 pps │ General anomaly        │            │
│  │ byte_rate │ 1M Bps   │ Bandwidth anomaly      │            │
│  │ ddos_pkts │ 10000    │ DDoS attack detection  │            │
│  └───────────┴──────────┴────────────────────────┘            │
└────────────────────────────────────────────────────────────—┘
```

---

## 4. Database Design

### 4.1 Entity-Relationship Diagram

```
┌──────────────┐       ┌──────────────┐
│    roles     │       │    users     │
├──────────────┤       ├──────────────┤
│ PK id: INT   │◄──────│ FK role_id   │
│ name: STR    │       │ PK id: INT   │
│ description  │       │ username:STR │
│ permissions  │       │ password:STR │
│ is_builtin   │       │ created_at   │
└──────────────┘       └──────────────┘

┌──────────────┐       ┌──────────────┐
│   alerts     │       │  policies    │
├──────────────┤       ├──────────────┤
│ PK id: STR   │       │ PK id: STR   │
│ timestamp    │       │ name         │
│ message      │       │ description  │
│ severity     │       │ action       │
│ source_ip    │       │ priority     │
│ dest_ip      │       │ enabled      │
│ mitigated    │       │ match_json   │
└──────────────┘       └──────────────┘

┌──────────────┐       ┌──────────────┐
│    logs      │       │  settings    │
├──────────────┤       ├──────────────┤
│ PK id: INT   │       │ PK key: STR  │
│ timestamp    │       │ value: STR   │
│ level        │       └──────────────┘
│ message      │
└──────────────┘
```

### 4.2 Schema Definitions

#### 4.2.1 `roles` Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PK, AUTO | Role identifier |
| `name` | VARCHAR(50) | UNIQUE, NOT NULL | Role name (admin, analyst, viewer) |
| `description` | VARCHAR(200) | DEFAULT '' | Human-readable description |
| `permissions` | TEXT | DEFAULT '[]' | JSON array of permission strings |
| `is_builtin` | INTEGER | DEFAULT 0 | 1 = system role (cannot be deleted) |

**Seed Data:**
| id | name | permissions |
|----|------|-------------|
| 1 | admin | alerts.*, policies.*, stats.*, topology.*, logs.*, settings.*, users.*, roles.* |
| 2 | analyst | alerts.view, alerts.mitigate, alerts.export, policies.view, stats.view, topology.view, logs.view, settings.view |
| 3 | viewer | alerts.view, policies.view, stats.view, topology.view, logs.view |

#### 4.2.2 `users` Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PK, AUTO | User identifier |
| `username` | VARCHAR(80) | UNIQUE, NOT NULL | Login name |
| `password` | VARCHAR(200) | NOT NULL | Plaintext password (dev only) |
| `role_id` | INTEGER | FK → roles.id, DEFAULT 1 | User role |
| `created_at` | VARCHAR(40) | NOT NULL | ISO-8601 timestamp |

#### 4.2.3 `alerts` Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | VARCHAR(40) | PK | UUID (e.g., "alert_a1b2c3d4") |
| `timestamp` | VARCHAR(40) | NOT NULL | ISO-8601 timestamp |
| `message` | VARCHAR(500) | NOT NULL | Alert description |
| `severity` | VARCHAR(20) | NOT NULL | CRITICAL / HIGH / MEDIUM / LOW |
| `source_ip` | VARCHAR(50) | NOT NULL | Attacker IP address |
| `destination_ip` | VARCHAR(50) | NOT NULL | Target IP address |
| `mitigated` | INTEGER | DEFAULT 0 | 0 = active, 1 = mitigated |

#### 4.2.4 `policies` Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | VARCHAR(50) | PK | UUID (e.g., "policy_x1y2z3w4") |
| `name` | VARCHAR(200) | DEFAULT '' | Policy name |
| `description` | VARCHAR(500) | DEFAULT '' | Policy description |
| `action` | VARCHAR(20) | NOT NULL | BLOCK/DROP/RATE_LIMIT/ISOLATE/QUARANTINE/REDIRECT/LOG_ONLY/ALERT |
| `priority` | INTEGER | DEFAULT 100 | Higher = more important |
| `enabled` | INTEGER | DEFAULT 1 | 0 = disabled, 1 = enabled |
| `match_json` | TEXT | DEFAULT '{}' | JSON match criteria |

#### 4.2.5 `logs` Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PK, AUTO | Sequential |
| `timestamp` | VARCHAR(40) | NOT NULL | ISO-8601 |
| `level` | VARCHAR(10) | NOT NULL | INFO / WARN / ALERT / ERROR |
| `message` | VARCHAR(1000) | NOT NULL | Log content |

#### 4.2.6 `settings` Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `key` | VARCHAR(100) | PK | Setting key |
| `value` | VARCHAR(500) | NOT NULL | Setting value (stored as string) |

### 4.3 Indexes

| Table | Column(s) | Type | Purpose |
|-------|-----------|------|---------|
| alerts | severity | Index | Filter by severity |
| alerts | mitigated | Index | Filter active/mitigated |
| alerts | timestamp | Index | Order by time |
| alerts | source_ip, destination_ip | Index | Search by IP |
| policies | enabled | Index | Count active policies |
| logs | level | Index | Filter by log level |

### 4.4 Data Flow: Read vs Write

| Operation | Frequency | Table(s) | Notes |
|-----------|-----------|----------|-------|
| Alert inserts | Every 2s (simulated) | alerts | Background thread |
| Alert reads | Every page load + WebSocket | alerts | Dashboard display |
| Policy reads | On page load | policies | Cached in session |
| Policy writes | Manual (admin actions) | policies | Occasional |
| Log writes | Per event | logs | Append-only |
| Settings reads | On settings page | settings | Rare |
| User reads | On users page | users | Rare |

---

## 5. API Design

### 5.1 REST API

#### 5.1.1 Authentication Endpoints

```
POST /api/login
  Request:  { "username": "admin", "password": "ntiyaga@1234" }
  Response: { "status": "ok", "username": "admin", "role": "admin" }
  Status:   200 OK / 401 Unauthorized

POST /api/logout
  Response: { "status": "ok" }
  Status:   200 OK

GET /api/check-auth
  Response: { "authenticated": true, "username": "admin" }
  Status:   200 OK / 401 Unauthorized

POST /api/change-password
  Auth:     Admin only
  Request:  { "oldPassword": "...", "newPassword": "..." }
  Response: { "status": "ok" }
  Status:   200 OK / 400 Bad Request
```

#### 5.1.2 Alert Endpoints

```
GET /api/alerts
  Auth:     alerts.view
  Query:    severity=[CRITICAL|HIGH|MEDIUM|LOW|all]
            status=[all|active|mitigated]
            search=<IP or message substring>
            date_from=<ISO-8601>
            date_to=<ISO-8601>
  Response: { "alerts": [...], "total": N }
  Status:   200 OK

GET /api/alerts/export
  Auth:     alerts.export
  Query:    severity=[CRITICAL|HIGH|MEDIUM|LOW|all]
  Response: CSV file download
  Status:   200 OK

POST /api/alerts/clear
  Auth:     alerts.clear
  Response: { "status": "ok" }
  Status:   200 OK

POST /api/mitigate
  Auth:     alerts.mitigate
  Request:  { "alertId": "alert_..." }
  Response: { "status": "ok", "mitigated": true }
  Status:   200 OK / 404 Not Found
```

#### 5.1.3 Policy Endpoints

```
GET /api/policies
  Auth:     policies.view
  Response: [ { id, name, description, action, priority, enabled, match }, ... ]
  Status:   200 OK

POST /api/policies
  Auth:     policies.create
  Request:  { "name": "...", "action": "BLOCK", "priority": 100, "enabled": true }
  Response: { id, name, description, action, priority, enabled, match }
  Status:   201 Created

POST /api/policies/:id/toggle
  Auth:     policies.edit
  Response: { id, ..., enabled: false }
  Status:   200 OK / 404 Not Found

DELETE /api/policies/:id
  Auth:     policies.delete
  Response: { "status": "ok" }
  Status:   200 OK / 404 Not Found

POST /api/policies/import
  Auth:     policies.import
  Request:  [ { name, action, priority, enabled, match }, ... ]
  Response: { "status": "ok", "imported": N }
  Status:   200 OK
```

#### 5.1.4 User & Role Endpoints

```
GET /api/users
  Auth:     users.view
  Response: [ { id, username, role_id, role_name, created_at }, ... ]
  Status:   200 OK

POST /api/users
  Auth:     users.create
  Request:  { "username": "...", "password": "...", "role_id": N }
  Response: { id, username, role_id, role_name, created_at }
  Status:   201 Created

DELETE /api/users/:id
  Auth:     users.delete
  Response: { "status": "ok" }
  Status:   200 OK / 400 (self-delete) / 404 Not Found

GET /api/roles
  Auth:     roles.view
  Response: [ { id, name, description, permissions, is_builtin }, ... ]
  Status:   200 OK

POST /api/roles/import
  Auth:     roles.import
  Request:  [ { name, description, permissions }, ... ]
  Response: { "status": "ok", "imported": N }
  Status:   200 OK
```

#### 5.1.5 System Endpoints

```
GET /api/stats
  Auth:     stats.view
  Response: { totalPackets, totalAlerts, activeRules, activeFlows }
  Status:   200 OK

GET /api/flows
  Auth:     stats.view
  Response: [ { id, deviceId, state, bytes, packets, priority, byteRate }, ... ]

GET /api/topology
  Auth:     topology.view
  Response: { "switches": [...], "hosts": [...], "links": [...] }

GET /api/logs
  Auth:     logs.view
  Response: Text (newline-separated log entries)

GET /api/logs/download
  Auth:     logs.download
  Response: sea_system.log file download

GET /api/settings
  Auth:     settings.view / settings.edit
  Response: { packetThreshold, byteThreshold, ddosThreshold }

POST /api/settings
  Auth:     settings.edit
  Request:  { packetThreshold, byteThreshold, ddosThreshold }
  Response: { "status": "ok" }
```

### 5.2 WebSocket API (Socket.IO)

#### 5.2.1 Event Specification

```
Client → Server:

Event: connect
  Payload: (none)
  Description: New WebSocket connection established

Event: disconnect
  Payload: (none)
  Description: Client disconnects

Server → Client:

Event: connected
  Payload: { "status": "ok" }
  Description: Acknowledgment

Event: stats_update
  Payload: { totalPackets, totalAlerts, activeRules, activeFlows }
  Trigger: Every 2 seconds (TrafficMonitor) or 3 seconds (RyuPoller)
  Description: Updates stat cards and sidebar badge

Event: traffic_update
  Payload: { timestamps: [...], rates: [...] }
  Trigger: Every 2 seconds
  Description: Updates traffic line chart

Event: new_alert
  Payload: { id, timestamp, message, severity, sourceIp, destinationIp, mitigated }
  Trigger: On attack detection
  Description: Appends alert to table + shows notification

Event: alert_mitigated
  Payload: { "id": "alert_..." }
  Trigger: On mitigate action
  Description: Updates alert status badge
```

### 5.3 Error Handling

All endpoints return consistent error responses:

```
401 Unauthorized:
  { "error": "Authentication required" }

403 Forbidden:
  { "error": "Insufficient permissions" }

400 Bad Request:
  { "error": "Descriptive message" }

404 Not Found:
  { "error": "Resource not found" }

500 Internal Server Error:
  (HTML error page in development, JSON in production)
```

---

## 6. Security Design

### 6.1 Authentication

```
┌─────────────────────────────────────────────┐
│           Authentication Flow               │
│                                             │
│  Browser                                    │
│    │                                        │
│    │  POST /api/login                       │
│    │  {username, password}                  │
│    ▼                                        │
│  Flask Server                               │
│    │                                        │
│    │  1. Query UserModel by username        │
│    │  2. Compare password (plaintext)        │
│    │  3. If match:                          │
│    │     - Set session["logged_in"] = True   │
│    │     - Set session["permissions"] = [...]│
│    │     - Set session.permanent = True       │
│    │     - Return 200 {status, role}          │
│    │  4. If no match:                        │
│    │     - Return 401 {error}                │
│    └────────────────────────────────────────┘
│                                             │
│  Session Lifetime: 8 hours                  │
│  (PERMANENT_SESSION_LIFETIME = 28800 secs)  │
│                                             │
│  Cookie: Flask session cookie (signed)      │
│  SECRET_KEY: os.urandom(24).hex()           │
└─────────────────────────────────────────────┘
```

### 6.2 Authorization (RBAC)

#### 6.2.1 Permission Model

```
Permission String Format:
  <resource>.<action>

Resources:
  alerts, policies, stats, topology, logs, settings, users, roles

Actions:
  view, create, edit, delete, import, mitigate, clear, export, download
```

#### 6.2.2 Decorator Enforcement

```python
@login_required                # Step 1: Check session exists
@role_required("alerts.clear") # Step 2: Check permission in session
def clear_alerts():
    ...
```

#### 6.2.3 Role-Permission Matrix

| Permission | admin | analyst | viewer |
|-----------|-------|---------|--------|
| alerts.view | ✓ | ✓ | ✓ |
| alerts.mitigate | ✓ | ✓ | ✗ |
| alerts.clear | ✓ | ✗ | ✗ |
| alerts.export | ✓ | ✓ | ✗ |
| policies.view | ✓ | ✓ | ✓ |
| policies.create | ✓ | ✗ | ✗ |
| policies.edit | ✓ | ✗ | ✗ |
| policies.delete | ✓ | ✗ | ✗ |
| policies.import | ✓ | ✗ | ✗ |
| stats.view | ✓ | ✓ | ✓ |
| topology.view | ✓ | ✓ | ✓ |
| logs.view | ✓ | ✓ | ✓ |
| logs.download | ✓ | ✗ | ✗ |
| settings.view | ✓ | ✓ | ✗ |
| settings.edit | ✓ | ✗ | ✗ |
| users.view | ✓ | ✗ | ✗ |
| users.create | ✓ | ✗ | ✗ |
| users.delete | ✓ | ✗ | ✗ |
| roles.view | ✓ | ✗ | ✗ |
| roles.import | ✓ | ✗ | ✗ |

### 6.3 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Session hijacking | Signed Flask cookies, HTTP-only flag |
| Brute force login | Application-layer (no rate limit yet) |
| XSS | Bootstrap sanitization, no raw HTML rendering |
| CSRF | Same-origin policy, session cookie |
| SQL injection | SQLAlchemy ORM (parameterized queries) |
| Unauthorized API access | login_required + role_required decorators |
| Weak credentials | Minimum 6-char password policy |
| Insecure direct object reference (IDOR) | Session-based user identification |

### 6.4 Data Protection

```
┌────────────────────┬──────────────────────────────┐
│ Data               │ Protection                   │
├────────────────────┼──────────────────────────────┤
│ Passwords          │ Plaintext (dev only)          │
│ Session keys       │ os.urandom(24) on each start  │
│ DB file (SQLite)   │ File permissions (OS-level)   │
│ Network traffic    │ No TLS (dev), add HTTPS in    │
│                    │ production via Render          │
│ Logs               │ Append-only, no PII logged    │
└────────────────────┴──────────────────────────────┘
```

---

## 7. Algorithm Design

### 7.1 Attack Detection Algorithm

```python
def simulate_traffic_cycle():
    """
    Runs in background thread every 2 seconds.

    Algorithm:
    1. Generate random traffic volume:
       packets = randint(50, 500)
       bytes_ = sum(randint(64, 1500) for _ in range(packets))

    2. Update traffic history (circular buffer, last 20 entries):
       timestamps.append(now)
       rates.append(bytes_ / 125000)  # Convert Bps to Mbps

    3. Threshold check:
       if packets > packet_threshold OR bytes_ > byte_threshold:
           emit stats_update

    4. Attack simulation (probabilistic):
       if random() < 0.05:       # 5% chance per cycle
           └── DDoS Alert (CRITICAL)
               source = random IP
               dest = random IP
               message = "DDoS attack detected from {source}"

       elif random() < 0.08:     # 8% chance
           └── Port Scan Alert (HIGH)
               message = "Port scan detected from {source}"

       elif random() < 0.10:     # 10% chance
           └── Suspicious Traffic Alert (MEDIUM/LOW)
               message = "Suspicious traffic to {dest}"
    """
```

### 7.2 Traffic History Buffer

```python
class TrafficStats:
    """
    In-memory statistics tracker.

    Attributes:
        total_packets:  int  — Cumulative packet count
        total_alerts:   int  — Total alerts generated
        active_rules:   int  — Active policy count
        active_flows:   int  — Current flow entries
        traffic_data:   dict — { timestamps: [...], rates: [...] }
                                Circular buffer limited to 20 entries
    """
```

### 7.3 Policy Priority Resolution

```python
def resolve_policy_conflict(policies):
    """
    When multiple policies match a packet, the highest priority wins.

    Priority scale: 0-100 (100 = highest)
    Action precedence in case of equal priority:
      1. BLOCK / DROP
      2. ISOLATE / QUARANTINE
      3. RATE_LIMIT / REDIRECT
      4. ALERT / LOG_ONLY

    Returns the winning action.
    """
```

### 7.4 WebSocket Real-Time Update Strategy

```
┌───────────────────────────────────────────────────┐
│              Update Propagation                    │
│                                                   │
│  TrafficMonitor Thread    ─────socketio.emit────► │
│  (every 2s)                    stats_update       │
│                                traffic_update      │
│                                                    │
│  Attack Detection          ─────socketio.emit────► │
│  (on trigger)                   new_alert           │
│                                                    │
│  Mitigate Action           ─────socketio.emit────► │
│  (on user click)                alert_mitigated     │
│                                                    │
│  REST API Fallback:                                │
│  Dashboard auto-refreshes via GET /api/* every 10s │
└───────────────────────────────────────────────────┘
```

---

## 8. UI/UX Prototype

### 8.1 Login Page

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│                          ┌───────────────┐              │
│                          │  🛡 SEA       │              │
│                          │  Dashboard    │              │
│                          │  Security     │              │
│                          │  Enforcement  │              │
│                          │  Application  │              │
│                          │               │              │
│                          │  👤 _______   │              │
│                          │  🔒 _______   │              │
│                          │               │              │
│                          │ [  Sign In  ] │              │
│                          │               │              │
│                          │ Default:      │              │
│                          │ admin / ...   │              │
│                          └───────────────┘              │
│                                                         │
└─────────────────────────────────────────────────────────┘
  Background: Linear gradient #0d1b2a → #1b2d3d
  Card: Glassmorphism (backdrop-filter: blur)
```

### 8.2 Dashboard Page

```
┌──────────────────────────────────────────────────────────────────────┐
│ ┌──────────────┐  ┌─────────────────────────────────────────────────┐│
│ │ 🛡 SEA       │  │ ⚡ Security Dashboard         👤 Admin  🌙 🔄  ││
│ │              │  ├─────────────────────────────────────────────────┤│
│ │ ⚡ Dashboard │  │                                                  ││
│ │ 🔔 Alerts  3 │  │ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐            ││
│ │ 🛡 Policies │  │ │Total │ │Alerts│ │Active│ │Active│            ││
│ │ 🌐 Topology │  │ │Pkts  │ │  Gen │ │Rules │ │Flows │            ││
│ │ 👥 Users    │  │ │1,234 │ │  42  │ │  8   │ │ 156  │            ││
│ │ 🪪 Roles    │  │ └──────┘ └──────┘ └──────┘ └──────┘            ││
│ │ 📋 Logs     │  │                                                  ││
│ │ ⚙ Settings  │  │ ┌──────────────────────┐ ┌────────────────────┐ ││
│ │              │  │ │ Traffic Rate (Mbps)  │ │ Alert Distribution│ ││
│ │ ○ Active     │  │ │                      │ │     🔴🔶🟡🟢     │ ││
│ │ ○ WebSocket │  │ │   ╱╲   ╱╲            │ │    Crit High Med  │ ││
│ │              │  │ │  ╱  ╲ ╱  ╲           │ │     Low           │ ││
│ │ 🕐 12:00:00  │  │ │ ╱    ╲    ╲          │ └────────────────────┘ ││
│ └──────────────┘  │ └──────────────────────┘                         ││
│                   │ ┌──────────────────────────────────────────────┐ ││
│                   │ │ 🔔 Recent Security Alerts                    │ ││
│                   │ │────┬────────┬──────────┬───────┬──────┬─────┤ ││
│                   │ │Time│Severity│ Message  │Src IP │Dst IP│Action│ ││
│                   │ │────┼────────┼──────────┼───────┼──────┼─────┤ ││
│                   │ │12:3│ 🔴CRIT │DDoS from │10.0.0.│8.8.8.│[Miti]│ ││
│                   │ │    │       │10.0.0.100│ 100   │8     │      │ ││
│                   │ └────┴────────┴──────────┴───────┴──────┴─────┘ ││
│                   └───────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
```

### 8.3 Alerts Page (with Filters)

```
┌──────────────────────────────────────────────────────────────────────┐
│ 🔔 Security Alerts History                                          │
│                                                                      │
│ Severity: [All ▼]  Status: [All ▼]  Search: [_________]             │
│ From: [____]  To: [____]  [Apply] [Reset]           [CSV] [Clear]   │
│                                                                      │
│ ┌──────┬────────────────────┬──────────┬────────────┬──────────┬────┐│
│ │ ID   │ Timestamp          │ Severity │ Message     │ Src IP   │St..││
│ ├──────┼────────────────────┼──────────┼─────────────┼──────────┼────┤│
│ │a1b2..│2026-06-15 12:34:56 │ 🔴CRIT   │ DDoS attack │10.0.0.100│Act ││
│ │c3d4..│2026-06-15 12:32:10 │ 🟡HIGH   │ Port scan   │192.168.1.5│Mit ││
│ │e5f6..│2026-06-15 12:30:05 │ 🟢MEDIUM │ Suspicious  │10.0.0.50 │Act ││
│ └──────┴────────────────────┴──────────┴─────────────┴──────────┴────┘│
└──────────────────────────────────────────────────────────────────────┘
```

### 8.4 Policies Page

```
┌──────────────────────────────────────────────────────────────────────┐
│ 🛡 Security Policies                              [Import JSON] [+Add]│
│                                                                      │
│ ┌────────────────────┬──────────┬──────────┬────────┬────────────────┐│
│ │ Name               │ Action   │ Priority │ Status │ Actions        ││
│ ├────────────────────┼──────────┼──────────┼────────┼────────────────┤│
│ │ DDoS Mitigation    │ BLOCK    │ 100      │ ● Active│ ⏸  🗑          ││
│ │ ICMP Flood Protect │RATE_LIMIT│ 95       │ ● Active│ ⏸  🗑          ││
│ │ Host Isolation     │ ISOLATE  │ 90       │ ○ Inact │ ▶️  🗑          ││
│ │ ...                │ ...      │ ...      │ ...     │ ...            ││
│ └────────────────────┴──────────┴──────────┴────────┴────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
```

### 8.5 Users & Roles Pages

```
┌───────────────────────────────────────────────────────┐
│ 👥 Users                              [+ Add User]    │
│                                                        │
│ ┌────┬──────────┬──────────┬──────────┬──────────────┐ │
│ │ ID │ Username │ Role     │ Created   │ Actions      │ │
│ ├────┼──────────┼──────────┼──────────┼──────────────┤ │
│ │ 1  │ admin    │ admin    │2026-06-01│ 🗑             │ │
│ │ 2  │ analyst1 │ analyst  │2026-06-15│ 🗑             │ │
│ └────┴──────────┴──────────┴──────────┴──────────────┘ │
│                                                        │
│ ┌─ Add User Modal ───────────────────────────────────┐ │
│ │ Username: [____________]                           │ │
│ │ Password: [____________]                           │ │
│ │ Role:     [analyst ▼]                              │ │
│ │                   [Cancel] [Save]                   │ │
│ └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ 🪪 Roles                                [Import JSON]     │
│                                                            │
│ ┌──────────┬──────────────────┬────────────────┬─────────┐ │
│ │ Name     │ Description       │ Permissions     │ Type    │ │
│ ├──────────┼──────────────────┼────────────────┼─────────┤ │
│ │ admin    │ Full access       │ alerts.*, ...   │ Built-in│ │
│ │ analyst  │ Monitor & mitigat │ alerts.view,... │ Built-in│ │
│ │ viewer   │ Read-only         │ alerts.view,... │ Built-in│ │
│ │ auditor  │ Audit access      │ logs.view,...   │ Custom  │ │
│ └──────────┴──────────────────┴────────────────┴─────────┘ │
└──────────────────────────────────────────────────────────┘
```

### 8.6 Settings Page

```
┌────────────────────────────────────────────────────────────┐
│ ⚙ System Settings                                          │
│                                                             │
│ Detection Thresholds                                        │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Packet Rate Threshold  [ 1000    ] pps                │ │
│ │ Byte Rate Threshold   [ 1000000  ] Bps                │ │
│ │ DDoS Threshold        [ 10000    ] packets            │ │
│ └────────────────────────────────────────────────────────┘ │
│                                                             │
│ Auto-Mitigation                                             │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ [✓] Enable automatic mitigation of attacks             │ │
│ │ [ ] Log all packets (may impact performance)           │ │
│ └────────────────────────────────────────────────────────┘ │
│                                                             │
│ Alert Notifications                                         │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ [✓] Critical alerts                                    │ │
│ │ [✓] High severity alerts                               │ │
│ │ [ ] Medium severity alerts                             │ │
│ └────────────────────────────────────────────────────────┘ │
│                                                             │
│ [Save Settings]  [Reset to Default]                         │
└────────────────────────────────────────────────────────────┘
```

### 8.7 Topology Page

```
┌────────────────────────────────────────────────────────────┐
│ 🌐 Network Topology                                         │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                                                       │  │
│  │               ┌──────────┐                            │  │
│  │               │Controller│                            │  │
│  │               └────┬─────┘                            │  │
│  │                    │                                   │  │
│  │     ┌──────────────┼──────────────┐                   │  │
│  │     │              │              │                   │  │
│  │  ┌──▼───┐      ┌──▼───┐          │                   │  │
│  │  │Switch│──────│Switch│          │                   │  │
│  │  │  1   │      │  2   │          │                   │  │
│  │  └──┬───┘      └──┬───┘          │                   │  │
│  │     │              │             │                   │  │
│  │  ┌──▼───┐      ┌──▼───┐         │                   │  │
│  │  │Host 1│      │Host 2│         │                   │  │
│  │  └──────┘      └──────┘         │                   │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│ Devices                                                     │
│ ┌──────────────────────────────────────────────────────┐   │
│ │ 🖥 Switch-01                        ● Active         │   │
│ │ 🖥 Switch-02                        ● Active         │   │
│ │ 💻 Host-01                          ● Active         │   │
│ │ 💻 Host-02                          ○ Inactive       │   │
│ │ 🗄 Controller                       ● Active         │   │
│ └──────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘
```

### 8.8 Logs Page

```
┌────────────────────────────────────────────────────────────┐
│ 📋 System Logs                         [Download Logs]     │
│                                                             │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ [2026-06-15T12:34:56] [ALERT] CRITICAL: DDoS attack    │ │
│ │   detected from 10.0.0.100                              │ │
│ │ [2026-06-15T12:34:55] [INFO] Traffic: 234 packets/s    │ │
│ │ [2026-06-15T12:34:54] [WARN] Port scan detected from   │ │
│ │   192.168.1.5                                            │ │
│ │ [2026-06-15T12:34:53] [INFO] Policy SYN Flood applied  │ │
│ │ [2026-06-15T12:34:52] [INFO] Admin login: admin        │ │
│ │ ...                                                     │ │
│ └────────────────────────────────────────────────────────┘ │
│   Dark terminal-style display, monospace font, 600px max-h │
└────────────────────────────────────────────────────────────┘
```

### 8.9 Dark Mode

The UI supports a toggle between light and dark themes, stored in `localStorage`:

| Element | Light Mode | Dark Mode |
|---------|-----------|-----------|
| Body | `bg-light` (#f8f9fa) | `#1a1d23` |
| Cards | `bg-white` | `#2d323b` |
| Text | `#212529` | `#e9ecef` |
| Inputs | `bg-white` | `#2d323b` |
| Borders | `#dee2e6` | `#495057` |
| Sidebar | `bg-dark` (fixed) | `#12141a` |

---

## 9. Deployment Architecture

### 9.1 Development Deployment

```
┌─────────────────────────────────────────────┐
│            Developer Machine                 │
│                                             │
│  python app.py                              │
│  → Flask dev server on 0.0.0.0:5000         │
│  → SQLite database (sea.db)                 │
│  → TrafficMonitor background thread         │
│  → Optional: Ryu controller on :8081        │
│                                             │
│  Browser: http://localhost:5000             │
└─────────────────────────────────────────────┘
```

### 9.2 Production Deployment (Render)

```
┌────────────────────────────────────────────────────────┐
│                   Render Platform                        │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Web Service (Free)                              │    │
│  │  ─────────────────────                            │    │
│  │  Runtime: Python 3.x                             │    │
│  │  Build:  pip install -r requirements.txt          │    │
│  │  Start:  gunicorn app:app                        │    │
│  │  Worker: eventlet (WebSocket support)            │    │
│  │  Port:   5000 (auto-injected via $PORT)          │    │
│  │  Replicas: 1 (free tier)                         │    │
│  │  Sleeps after 15 min inactivity (free tier)      │    │
│  │  Auto-wakes on HTTP request                      │    │
│  │                                                  │    │
│  │  Environment Variables:                          │    │
│  │  ┌────────────────────────────────────────────┐  │    │
│  │  │ DATABASE_URL → postgresql://... (auto-set) │  │    │
│  │  │ PRODUCTION = "true"                        │  │    │
│  │  └────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────┘    │
│                       │                                 │
│                       ▼                                 │
│  ┌─────────────────────────────────────────────────┐    │
│  │  PostgreSQL Database (Free)                      │    │
│  │  ─────────────────────                            │    │
│  │  Plan:  Free (1GB storage)                       │    │
│  │  Host:  sea-db.internal (auto-linked)            │    │
│  │  Auth:  Built-in TLS + password                  │    │
│  │  Backups: Daily (auto)                           │    │
│  └─────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────┘
```

### 9.3 Deployment Steps

```
1. Push to GitHub
   ─────────────────
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/YOUR_USER/sea-dashboard.git
   git push -u origin main

2. Deploy on Render
   ─────────────────
   a. Go to https://dashboard.render.com
   b. Click "New +" → "Blueprint"
   c. Connect your GitHub repository
   d. Render auto-detects render.yaml
   e. Click "Apply"

3. Verify
   ─────────────────
   a. Wait for deploy (~3 min)
   b. Open https://sea-dashboard.onrender.com
   c. Login: admin / ntiyaga@1234
   d. Update password on first login
```

### 9.4 Environment Configuration

```yaml
# render.yaml (auto-detected by Render)
services:
  - type: web
    name: sea-dashboard
    runtime: python
    buildCommand: pip install -r requirements.txt
    startCommand: gunicorn app:app
    envVars:
      - key: PRODUCTION
        value: "true"

databases:
  - name: sea-db
    databaseName: sea
    plan: free
```

```python
# gunicorn.conf.py (auto-loaded)
worker_class = "eventlet"
workers = 1
timeout = 120
keepalive = 5
```

---

## 10. Testing Strategy

### 10.1 Test Categories

| Category | Tool | Scope |
|----------|------|-------|
| Unit | Flask test client | API endpoints (14 tests) |
| Integration | Flask test client | Database + RBAC + import (14 tests) |
| Frontend | Manual (browser) | UI rendering, WebSocket, charts |
| Security | Manual | Role escalation, auth bypass |

### 10.2 API Test Matrix

```
┌────────────────────────────────────────────────────────────────────┐
│  # │ Test                         │ Method │ Endpoint    │ Pass ✓ │
│────┼─────────────────────────────┼────────┼─────────────┼────────│
│  1 │ Login with valid creds      │ POST   │ /api/login  │   ✓    │
│  2 │ Check auth after login      │ GET    │ /check-auth │   ✓    │
│  3 │ Create user (admin)         │ POST   │ /api/users  │   ✓    │
│  4 │ Reject duplicate username   │ POST   │ /api/users  │   ✓    │
│  5 │ List roles                  │ GET    │ /api/roles  │   ✓    │
│  6 │ View alerts (viewer)        │ GET    │ /api/alerts │   ✓    │
│  7 │ Block alerts.clear (viewer) │ POST   │ /alerts/clear│  ✓    │
│  8 │ Block users.view (viewer)   │ GET    │ /api/users  │   ✓    │
│  9 │ Import policies (admin)     │ POST   │ /policies/import│ ✓  │
│ 10 │ Import roles (admin)        │ POST   │ /roles/import│   ✓    │
│ 11 │ Export CSV                  │ GET    │ /alerts/export│  ✓    │
│ 12 │ Alert filters               │ GET    │ /api/alerts │   ✓    │
│ 13 │ Settings                    │ GET    │ /api/settings│  ✓    │
│ 14 │ Stats                       │ GET    │ /api/stats  │   ✓    │
└────────────────────────────────────────────────────────────────────┘
```

### 10.3 Edge Cases Handled

| Edge Case | Handling |
|-----------|----------|
| Ryu controller offline | Graceful fallback to standalone mode |
| Empty database | Auto-seed on first run |
| Duplicate usernames | 400 error with descriptive message |
| Self-deletion | 400 error (cannot delete yourself) |
| Malformed JSON | 400 Bad Request |
| Missing permissions | 403 Forbidden |
| Expired session | 401 with re-login prompt |
| Concurrent DB access | `with app.app_context()` per request |
| Date range parsing | `try/except` with silent ignore on invalid dates |

---

## 11. Appendices

### A. File Inventory

```
SDN/
├── app.py                  # Flask server (646 lines) — REST API, WebSocket, auth, RBAC
├── database.py             # SQLAlchemy models + seed data (195 lines)
├── models.py               # Python enums + data classes (81 lines)
├── sdn_client.py           # Ryu REST API client (78 lines)
├── traffic_monitor.py      # Background traffic simulation (120 lines)
├── ryu_app.py              # Ryu OpenFlow 1.3 controller (326 lines)
├── dashboard.html          # Frontend SPA (1700+ lines)
├── requirements.txt        # Python dependencies (9 packages)
├── policies.json           # 35 sample policies for bulk import
├── roles.json              # 5 sample roles for bulk import
├── render.yaml             # Render deployment blueprint
├── gunicorn.conf.py        # Production WSGI configuration
├── .gitignore              # Python + SQLite ignores
├── SYSTEM_DESIGN.md        # This document
└── README.md               # Project documentation (457 lines)
```

### B. Glossary

| Term | Definition |
|------|-----------|
| SDN | Software-Defined Networking — separates control plane from data plane |
| OpenFlow | Protocol for SDN communication between controller and switches |
| Ryu | Python-based SDN controller framework |
| DDoS | Distributed Denial-of-Service — overwhelming a target with traffic |
| Port Scan | Probing a host for open ports to identify services |
| RBAC | Role-Based Access Control — permissions assigned to roles, not users |
| Socket.IO | Library for real-time bidirectional event-based communication |
| Waitress | Production-quality WSGI server for Python (Windows-compatible) |
| Gunicorn | Production WSGI server for Unix/Linux |
| Eventlet | Coroutine-based networking library for async WebSocket support |

### C. Reference Links

| Resource | URL |
|----------|-----|
| Flask Documentation | https://flask.palletsprojects.com |
| Flask-SocketIO | https://flask-socketio.readthedocs.io |
| SQLAlchemy | https://www.sqlalchemy.org |
| Bootstrap 5 | https://getbootstrap.com |
| Chart.js | https://www.chartjs.org |
| Ryu SDN Framework | https://ryu-sdn.org |
| Render Platform | https://render.com |
| DB Browser for SQLite | https://sqlitebrowser.org |
