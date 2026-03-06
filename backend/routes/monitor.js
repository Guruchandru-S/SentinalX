const express = require('express');
const router = express.Router();
const DataEngine = require('../engine/dataEngine');
router.get('/event-stream', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 60, 200);
    const events = [];
    for (let i = 0; i < Math.min(limit, 10); i++) {
        events.push(DataEngine.generateStreamEvent());
    }
    res.json({ events, total: events.length, timestamp: DataEngine.nowISO() });
});
router.get('/event-stream/live', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.flushHeaders();
    const sendEvent = () => {
        const event = DataEngine.generateStreamEvent();
        res.write(`data: ${JSON.stringify(event)}\n\n`);
    };
    sendEvent(); 
    const interval = setInterval(sendEvent, 800);
    req.on('close', () => {
        clearInterval(interval);
    });
});
router.get('/protocol-distribution', (req, res) => {
    const counts = DataEngine.STATE.protocolCounts;
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    const distribution = Object.entries(counts).map(([protocol, count]) => ({
        protocol,
        count,
        percentage: parseFloat(((count / total) * 100).toFixed(1))
    }));
    res.json({ distribution, total, timestamp: DataEngine.nowISO() });
});
router.get('/traffic-history', (req, res) => {
    const points = parseInt(req.query.points) || 60;
    const { STATE } = DataEngine;
    const history = Array.from({ length: points }, () => {
        const base = STATE.attackInProgress ? DataEngine.rand(400, 900) : DataEngine.rand(80, 200);
        return parseFloat(base.toFixed(0));
    });
    res.json({ history, points, attackInProgress: STATE.attackInProgress, timestamp: DataEngine.nowISO() });
});
router.get('/ip-table', (req, res) => {
    const limit = parseInt(req.query.limit) || 10;
    for (let i = 0; i < 2; i++) DataEngine.generateIPTableEntry();
    const sorted = Object.entries(DataEngine.STATE.attackerIPs)
        .sort((a, b) => b[1] - a[1])
        .slice(0, limit)
        .map(([ip, hits]) => ({ ip, country: DataEngine.pick(DataEngine.GEO_ORIGINS), hits }));
    res.json({ entries: sorted, total: Object.keys(DataEngine.STATE.attackerIPs).length });
});
router.get('/stats', (req, res) => {
    const { STATE } = DataEngine;
    res.json({
        eventsPerSec: STATE.eventsPerSec,
        blockedCount: STATE.blockedCount,
        totalAttackerIPs: Object.keys(STATE.attackerIPs).length,
        protocolCounts: { ...STATE.protocolCounts },
        attackInProgress: STATE.attackInProgress,
        timestamp: DataEngine.nowISO()
    });
});
module.exports = router;