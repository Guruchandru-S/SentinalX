const express = require('express');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const rateLimit = require('express-rate-limit');
const db = require('./db/database');
const { fetchAllRealData, startPeriodicFetch } = require('./db/realDataFetcher');
const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const threatsRoutes = require('./routes/threats');
const anomalyRoutes = require('./routes/anomaly');
const behaviorRoutes = require('./routes/behavior');
const responseRoutes = require('./routes/response');
const forensicsRoutes = require('./routes/forensics');
const mlRoutes = require('./routes/ml');
const agentsRoutes = require('./routes/agents');
const monitorRoutes = require('./routes/monitor');
const DataEngine = require('./engine/dataEngine');
const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3001;
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'null', '*'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests from this IP, please try again later.' }
});
app.use('/api/', apiLimiter);
app.use(express.static(path.join(__dirname, '..')));
app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/threats', threatsRoutes);
app.use('/api/anomaly', anomalyRoutes);
app.use('/api/behavior', behaviorRoutes);
app.use('/api/response', responseRoutes);
app.use('/api/forensics', forensicsRoutes);
app.use('/api/ml', mlRoutes);
app.use('/api/agents', agentsRoutes);
app.use('/api/monitor', monitorRoutes);
app.get('/api/health', (req, res) => {
    const threatCount = db.count('threats');
    const iocCount = db.count('ioc_entries');
    const c2Count = db.count('c2_servers');
    const cveCount = db.count('cve_entries');
    const auditCount = db.count('audit_log');
    const lastFetch = db.getConfig('last_threat_intel_fetch');
    res.json({
        status: 'OPERATIONAL',
        system: 'AEGIS Cyber Defense OS',
        version: '3.2.0',
        database: 'SQLite (aegis.db)',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        threatIntelligence: {
            threats: threatCount,
            iocs: iocCount,
            c2Servers: c2Count,
            cves: cveCount,
            lastFetch
        },
        persistence: {
            auditLog: auditCount,
        },
        endpoints: [
            '/api/auth', '/api/dashboard', '/api/threats', '/api/anomaly',
            '/api/behavior', '/api/response', '/api/forensics',
            '/api/ml', '/api/agents', '/api/monitor'
        ]
    });
});
const wss = new WebSocket.Server({ server, path: '/ws' });
const wsClients = new Set();
wss.on('connection', (ws, req) => {
    console.log(`[WS] Client connected from ${req.socket.remoteAddress}`);
    wsClients.add(ws);
    ws.send(JSON.stringify({
        type: 'SYSTEM_INIT',
        payload: {
            ...DataEngine.getSystemState(),
            db: {
                threats: db.count('threats'),
                iocs: db.count('ioc_entries'),
                c2Servers: db.count('c2_servers'),
                cves: db.count('cve_entries'),
                auditLog: db.count('audit_log'),
            }
        }
    }));
    ws.on('message', (data) => {
        try {
            const msg = JSON.parse(data);
            handleWSMessage(ws, msg);
        } catch {
            ws.send(JSON.stringify({ type: 'ERROR', message: 'Invalid JSON' }));
        }
    });
    ws.on('close', () => {
        console.log('[WS] Client disconnected');
        wsClients.delete(ws);
    });
    ws.on('error', (err) => {
        console.error('[WS] Error:', err.message);
        wsClients.delete(ws);
    });
});
function handleWSMessage(ws, msg) {
    switch (msg.type) {
        case 'PING':
            ws.send(JSON.stringify({ type: 'PONG', timestamp: Date.now() }));
            break;
        case 'SIMULATE_ATTACK':
            DataEngine.triggerAttack();
            broadcast({ type: 'ATTACK_STARTED', payload: DataEngine.getCurrentAttack() });
            break;
        case 'SUBSCRIBE':
            ws.send(JSON.stringify({ type: 'SUBSCRIBED', channels: msg.channels }));
            break;
        default:
            ws.send(JSON.stringify({ type: 'ERROR', message: `Unknown message type: ${msg.type}` }));
    }
}
function broadcast(data) {
    const msg = JSON.stringify(data);
    wsClients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) client.send(msg);
    });
}
setInterval(() => {
    if (wsClients.size === 0) return;
    broadcast({ type: 'LIVE_TICK', payload: DataEngine.generateLiveTick() });
}, 600);
setInterval(() => {
    if (wsClients.size === 0) return;
    const real = db.get('SELECT * FROM threats ORDER BY RANDOM() LIMIT 1');
    if (real) {
        broadcast({
            type: 'THREAT_FEED', payload: {
                id: real.id, name: real.name, severity: real.severity,
                source: real.source_ip || 'unknown', action: real.action,
                country: real.country, cvss: real.cvss, malware: real.malware,
                feedSource: real.feed_source, timestamp: real.timestamp, realData: true
            }
        });
    } else {
        broadcast({ type: 'THREAT_FEED', payload: DataEngine.generateThreatFeedItem() });
    }
}, 2000);
setInterval(() => {
    if (wsClients.size === 0) return;
    broadcast({ type: 'ANOMALY_EVENT', payload: DataEngine.generateAnomalyEvent() });
}, 3000);
setInterval(() => {
    if (wsClients.size === 0) return;
    broadcast({ type: 'AGENT_MESSAGE', payload: DataEngine.generateAgentMessage() });
}, 2500);
setInterval(() => {
    if (wsClients.size === 0) return;
    broadcast({ type: 'ML_UPDATE', payload: DataEngine.generateMLUpdate() });
}, 1000);
app.locals.broadcast = broadcast;
app.locals.dataEngine = DataEngine;
app.locals.db = db;
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});
app.use((err, req, res, next) => {
    console.error('[API ERROR]', err.message);
    res.status(err.status || 500).json({
        error: err.message || 'Internal Server Error',
        timestamp: new Date().toISOString()
    });
});
async function bootstrap() {
    await db.init();
    db.seedUsers(); db.seedUEBA(); db.seedAuditLog();
    await new Promise((resolve) => server.listen(PORT, resolve));
    console.log('\n╔════════════════════════════════════════════╗');
    console.log('║     AEGIS Autonomous Cyber Defense OS      ║');
    console.log('║       Backend API Server v3.2 + DB         ║');
    console.log('╚════════════════════════════════════════════╝');
    console.log(`  HTTP API   →  http://localhost:${PORT}`);
    console.log(`  WebSocket  →  ws://localhost:${PORT}/ws`);
    console.log(`  Frontend   →  http://localhost:3000`);
    console.log(`  Database   →  aegis.db (SQLite)\n`);
    console.log('  [INTEL] Starting real threat intelligence fetch...');
    fetchAllRealData()
        .then(r => {
            if (!r.cached) {
                console.log(`  [INTEL] Done — ${r.totalThreats || 0} threats, ${r.totalIOCs || 0} IOCs, ${r.totalCVEs || 0} CVEs`);
            }
            startPeriodicFetch(60 * 60 * 1000);
        })
        .catch(err => console.warn('  [INTEL] Initial fetch error:', err.message));
    console.log('  All defense layers active. System OPERATIONAL.\n');
}
bootstrap().catch(err => {
    console.error('[FATAL] Server failed to start:', err.message);
    process.exit(1);
});
module.exports = { app, server, broadcast };