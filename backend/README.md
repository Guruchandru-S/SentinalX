# AEGIS — Autonomous Cyber Defense System
### Backend API Documentation

> **Full-stack cybersecurity dashboard with Node.js/Express REST API + WebSocket real-time engine.**

---

## 📁 Project Structure

```
cyber/
├── index.html          ← Frontend dashboard (AEGIS UI)
├── style.css           ← Frontend styles (Arctic Dusk theme)
├── app.js              ← Frontend logic & simulation engine
├── api.js              ← Frontend API client (connects to backend)
│
└── backend/
    ├── server.js           ← Main Express + WebSocket server
    ├── package.json        ← Dependencies manifest
    ├── start.bat           ← Windows launcher script
    ├── extract-npm.js      ← npm bootstrap (first-time setup)
    │
    ├── engine/
    │   └── dataEngine.js   ← AEGIS simulation brain (generates all data)
    │
    ├── middleware/
    │   └── auth.js         ← JWT verification middleware
    │
    └── routes/
        ├── auth.js         ← Authentication API
        ├── dashboard.js    ← Command Center API
        ├── threats.js      ← Threat Intelligence API
        ├── anomaly.js      ← Anomaly Detection API
        ├── behavior.js     ← Behavioral Analysis API
        ├── response.js     ← Adaptive Response API
        ├── forensics.js    ← Forensic Audit API
        ├── ml.js           ← Machine Learning Engine API
        ├── agents.js       ← Multi-Agent Network API
        └── monitor.js      ← Live Network Monitor API
```

---

## 🚀 How to Start

### Option 1 — Double-click (Windows)
```
backend/start.bat
```

### Option 2 — PowerShell (if Node.js is installed)
```powershell
cd backend
npm start
```

### Option 3 — Using embedded Node.js (Playwright)
```powershell
$node = "$env:LOCALAPPDATA\ms-playwright-go\1.50.1\node.exe"
& $node backend/server.js
```

The server starts on:
- **REST API** → `http://localhost:3001/api/`
- **WebSocket** → `ws://localhost:3001/ws`
- **Frontend** → `http://localhost:3001/` (auto-served)

---

## 🔌 REST API Reference

### Health
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Server health, status, and endpoint list |

---

### 🔐 Auth — `/api/auth`
| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | `{ email, password }` | Email/password login → returns JWT |
| POST | `/api/auth/google` | `{ email }` | Google SSO mock → returns JWT |
| GET | `/api/auth/google/accounts` | — | List available Google SSO accounts |
| POST | `/api/auth/logout` | — | Logout (client clears token) |
| GET | `/api/auth/me` | — | Get current user from JWT |
| POST | `/api/auth/refresh` | — | Refresh expiring JWT token |

**Demo Accounts:**
- `user@organization.corp` (Analyst role)
- `admin@aegis.system` (Admin role)

---

### 📊 Dashboard — `/api/dashboard`
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/state` | Full system state snapshot |
| GET | `/api/dashboard/kpis` | KPI metrics (threats, anomalies, accuracy, uptime) |
| GET | `/api/dashboard/threat-feed?limit=20` | Threat intelligence feed items |
| GET | `/api/dashboard/defense-layers` | Defense layer statuses & effectiveness % |
| GET | `/api/dashboard/heatmap` | 10×60 risk propagation heatmap grid |
| GET | `/api/dashboard/traffic` | Network traffic history (60 points) |
| GET | `/api/dashboard/radar` | Attack vector radar values (6 axes) |
| POST | `/api/dashboard/simulate-attack` | Trigger a simulated attack event |

---

### 🛡️ Threats — `/api/threats`
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threats/feed` | Paginated threat feed (`?limit=&page=&severity=`) |
| GET | `/api/threats/types` | All threat type definitions + CVSS scores |
| GET | `/api/threats/live` | One fresh threat event |
| GET | `/api/threats/ip-table` | Top attacking IPs with country & hit count |
| GET | `/api/threats/geo?count=20` | Geographic threat/trusted origin coordinates |
| POST | `/api/threats/report` | Manually report a custom threat |
| GET | `/api/threats/:id` | Get specific threat by UUID |

---

### ⚠️ Anomaly — `/api/anomaly`
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/anomaly/log` | Anomaly event log (`?limit=&page=&type=`) |
| GET | `/api/anomaly/categories` | Counts per category (BruteForce, DDoS, etc.) |
| GET | `/api/anomaly/baseline` | Baseline vs observed dataset (80 points) |
| GET | `/api/anomaly/risk-dist` | Risk score distribution (Low/Med/High/Critical) |
| GET | `/api/anomaly/live` | One fresh anomaly event |
| GET | `/api/anomaly/stats` | Detection rate, false positive rate, Z-score avg |

---

### 🧠 Behavior — `/api/behavior`
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/behavior/kill-chain` | Kill chain stage statuses (7 stages) |
| GET | `/api/behavior/ueba` | User & Entity Behavior Analytics risk profiles |
| GET | `/api/behavior/process-chain` | Process chain nodes + edges (malware tree) |
| GET | `/api/behavior/mitre` | MITRE ATT&CK coverage matrix |
| GET | `/api/behavior/predictions` | ML threat prediction probabilities |

---

### ⚡ Response — `/api/response`
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/response/playbooks` | All 6 response playbooks + current status |
| POST | `/api/response/playbooks/:name/activate` | Activate a playbook (ISOLATE/BLOCK/DECEPTION/etc.) |
| GET | `/api/response/timeline` | Response event timeline |
| POST | `/api/response/timeline` | Add custom timeline entry |
| GET | `/api/response/decision-matrix` | Autonomous decision matrix rows |
| GET | `/api/response/status` | Current mode, threat level, active playbooks |
| POST | `/api/response/trigger-attack` | Trigger simulated attack |

---

### 🔍 Forensics — `/api/forensics`
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/forensics/audit-log` | Paginated immutable audit trail |
| GET | `/api/forensics/integrity` | Blockchain hash chain integrity status |
| GET | `/api/forensics/compliance` | Compliance status (GDPR, ISO27001, SOC2, HIPAA, PCI-DSS, NIST) |
| GET | `/api/forensics/export` | Download full audit log as `.log` file |
| GET | `/api/forensics/live` | One fresh audit entry |
| POST | `/api/forensics/audit-log` | Manually add an audit record |

---

### 🤖 ML Engine — `/api/ml`
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ml/training-stats` | Current epoch, loss, accuracy, F1 score |
| GET | `/api/ml/training-history?points=80` | Full loss + accuracy curve data |
| GET | `/api/ml/inference-log` | Live inference log entries |
| GET | `/api/ml/inference-log/live` | One fresh inference entry |
| GET | `/api/ml/confusion-matrix` | 6×6 confusion matrix with precision/recall |
| GET | `/api/ml/feature-weights` | Decision feature importance (5 features) |
| POST | `/api/ml/generate-report` | Generate ML training report (returns markdown) |
| GET | `/api/ml/model-info` | Model architecture, version, config |

---

### 🕸️ Agents — `/api/agents`
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/agents/` | All 5 agents with status + metrics |
| GET | `/api/agents/:id` | Specific agent (`head/mon/tia/rca/lea`) |
| GET | `/api/agents/message-bus/live` | Inter-agent message bus log |
| GET | `/api/agents/topology/nodes` | Canvas topology node positions + edges |
| POST | `/api/agents/incident/trigger` | Trigger multi-agent incident simulation |
| GET | `/api/agents/risk-gauge` | Current CVSS risk score + label |

---

### 📡 Monitor — `/api/monitor`
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/monitor/event-stream` | Network event stream items |
| GET | `/api/monitor/event-stream/live` | **Server-Sent Events (SSE)** stream |
| GET | `/api/monitor/protocol-distribution` | Protocol counts + percentages |
| GET | `/api/monitor/traffic-history?points=60` | Traffic volume history |
| GET | `/api/monitor/ip-table` | Top attacking IPs |
| GET | `/api/monitor/stats` | Events/sec, blocked count, packet stats |

---

## ⚡ WebSocket Events

Connect to `ws://localhost:3001/ws`

### Server → Client events:
| Type | Payload | Frequency |
|------|---------|-----------|
| `SYSTEM_INIT` | Full system state | On connect |
| `LIVE_TICK` | eventsPerSec, blockedCount, traffic, radar | Every 600ms |
| `THREAT_FEED` | Single threat item | Every 2s |
| `ANOMALY_EVENT` | Single anomaly event | Every 3s |
| `AGENT_MESSAGE` | Inter-agent bus message | Every 2.5s |
| `ML_UPDATE` | Epoch, loss, accuracy | Every 1s |
| `ATTACK_STARTED` | Attack object | On attack trigger |
| `PLAYBOOK_DEPLOYED` | Playbook name + status | On playbook activation |
| `PONG` | timestamp | On PING |

### Client → Server messages:
| Type | Payload | Description |
|------|---------|-------------|
| `PING` | — | Heartbeat check |
| `SIMULATE_ATTACK` | — | Trigger attack simulation |
| `SUBSCRIBE` | `{ channels: [] }` | Subscribe to specific channels |

---

## 🔒 Security Notes

- JWT tokens expire in **8 hours**
- Rate limiting: **500 requests / 15 minutes** per IP
- CORS is configured for local development
- Passwords are hashed with **bcryptjs** (10 rounds)
- In production: set `JWT_SECRET` env variable and restrict CORS origins

---

## 🧩 Frontend Integration

The `api.js` file provides a global `AEGIS_API` object with methods for every endpoint:

```javascript
// Authentication
await AEGIS_API.auth.login('user@org.com', 'password');
await AEGIS_API.auth.googleSSO('admin@aegis.system');

// Real-time data
const kpis = await AEGIS_API.dashboard.kpis();
const threats = await AEGIS_API.threats.feed(20);

// WebSocket
AEGIS_API.on('LIVE_TICK', (data) => {
  console.log('Events/sec:', data.eventsPerSec);
});
AEGIS_API.connectWS();

// Trigger actions
await AEGIS_API.response.activatePlaybook('ISOLATE');
await AEGIS_API.dashboard.simulateAttack();
```

---

*AEGIS Backend v3.1 — Built with Node.js, Express, and WebSocket*
