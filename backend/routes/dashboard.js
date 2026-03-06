const express = require('express');
const router = express.Router();
const DataEngine = require('../engine/dataEngine');
router.get('/state', (req, res) => {
    res.json(DataEngine.getSystemState());
});
router.get('/kpis', (req, res) => {
    const { STATE } = DataEngine;
    res.json({
        neutralized: STATE.neutralized,
        anomalies: STATE.anomalies,
        accuracy: parseFloat(STATE.mlAccuracy.toFixed(1)),
        uptime: STATE.uptime,
        blockedCount: STATE.blockedCount,
        eventsPerSec: STATE.eventsPerSec,
        threatLevel: STATE.threatLevel,
        chainLength: STATE.chainLength,
        timestamp: DataEngine.nowISO()
    });
});
router.get('/threat-feed', (req, res) => {
    const limit = parseInt(req.query.limit) || 20;
    const fresh = Array.from({ length: 3 }, () => DataEngine.generateThreatFeedItem());
    DataEngine.STATE.threatFeed.unshift(...fresh);
    if (DataEngine.STATE.threatFeed.length > 100) DataEngine.STATE.threatFeed.length = 100;
    res.json({ items: DataEngine.STATE.threatFeed.slice(0, limit) });
});
router.get('/defense-layers', (req, res) => {
    const { STATE } = DataEngine;
    const attackBoost = STATE.attackInProgress ? -15 : 0;
    res.json({
        layers: [
            { name: 'Perimeter Firewall', status: 'ACTIVE', effectiveness: Math.min(100, 94 + DataEngine.randInt(-3, 3) + attackBoost) },
            { name: 'IDS/IPS Engine', status: 'ACTIVE', effectiveness: Math.min(100, 88 + DataEngine.randInt(-3, 3) + attackBoost) },
            { name: 'Behavioral AI', status: 'ACTIVE', effectiveness: Math.min(100, 97 + DataEngine.randInt(-2, 2)) },
            { name: 'Endpoint Shield', status: 'ACTIVE', effectiveness: Math.min(100, 91 + DataEngine.randInt(-3, 3) + attackBoost) },
            { name: 'Deception Grid', status: STATE.attackInProgress ? 'ACTIVE' : 'STANDBY', effectiveness: STATE.attackInProgress ? 88 : 72 },
            { name: 'Data Encryption', status: 'ACTIVE', effectiveness: 100 },
        ],
        attackInProgress: STATE.attackInProgress,
        timestamp: DataEngine.nowISO()
    });
});
router.get('/heatmap', (req, res) => {
    const ROWS = 10, COLS = 60;
    const { STATE } = DataEngine;
    const data = Array.from({ length: ROWS }, () =>
        Array.from({ length: COLS }, () => {
            let v = DataEngine.rand(0.05, 0.5);
            if (STATE.attackInProgress && Math.random() < 0.1) v = Math.min(1, v + 0.4);
            return parseFloat(v.toFixed(3));
        })
    );
    res.json({ rows: ROWS, cols: COLS, data, attackInProgress: STATE.attackInProgress, timestamp: DataEngine.nowISO() });
});
router.get('/traffic', (req, res) => {
    const { STATE } = DataEngine;
    const points = 60;
    const history = Array.from({ length: points }, () => {
        const base = STATE.attackInProgress ? DataEngine.rand(400, 900) : DataEngine.rand(80, 200);
        return parseFloat(base.toFixed(0));
    });
    res.json({ history, points, attackInProgress: STATE.attackInProgress, timestamp: DataEngine.nowISO() });
});
router.get('/radar', (req, res) => {
    const labels = ['Network', 'Endpoint', 'Identity', 'Data', 'App', 'Supply'];
    const { STATE } = DataEngine;
    const values = labels.map(() => {
        const base = STATE.attackInProgress ? DataEngine.rand(0.5, 1) : DataEngine.rand(0.1, 0.9);
        return parseFloat(base.toFixed(3));
    });
    res.json({ labels, values, attackInProgress: STATE.attackInProgress, timestamp: DataEngine.nowISO() });
});
router.post('/simulate-attack', (req, res) => {
    const attack = DataEngine.triggerAttack();
    if (!attack) {
        return res.status(409).json({ error: 'Attack simulation already in progress.' });
    }
    const broadcast = req.app.locals.broadcast;
    if (broadcast) {
        broadcast({ type: 'ATTACK_STARTED', payload: attack });
    }
    res.json({
        success: true,
        attack,
        message: `Simulated attack initiated: ${attack.threat.name}`
    });
});
module.exports = router;