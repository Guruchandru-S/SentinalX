const express = require('express');
const router = express.Router();
const DataEngine = require('../engine/dataEngine');
const { v4: uuidv4 } = require('uuid');
const AGENT_DEFS = {
    head: { id: 'head', name: 'Head Agent', role: 'War Room Orchestrator', color: '#7ec8c8' },
    mon: { id: 'mon', name: 'Monitoring & Detection Agent', role: 'Sensor Fusion & Alert Engine', color: '#7ec8c8' },
    tia: { id: 'tia', name: 'Threat Intel & Risk Assessment Agent', role: 'IOC Enrichment & CVSS Scorer', color: '#c9a862' },
    rca: { id: 'rca', name: 'Response & Containment Agent', role: 'Autonomous Countermeasure Executor', color: '#c27a6e' },
    lea: { id: 'lea', name: 'Learning & Audit Agent', role: 'Continuous Learning & Compliance Recorder', color: '#82b99a' },
};
const agentMetrics = {
    head: { directives: 0, escalations: 0 },
    mon: { events: 0, alerts: 0 },
    tia: { iocs: 0, cves: 0, riskAvg: 0 },
    rca: { actions: 0, rollbacks: 0, avgResponseMs: 120 },
    lea: { updates: 0, audits: 0, kb: 0 },
};
router.get('/', (req, res) => {
    const agents = Object.values(AGENT_DEFS).map(a => ({
        ...a,
        status: 'ONLINE',
        metrics: agentMetrics[a.id],
    }));
    res.json({ agents, timestamp: DataEngine.nowISO() });
});
router.get('/message-bus/live', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 30, 100);
    for (let i = 0; i < 2; i++) {
        const msg = DataEngine.generateAgentMessage();
        DataEngine.STATE.agentMessages.unshift(msg);
    }
    if (DataEngine.STATE.agentMessages.length > 200) DataEngine.STATE.agentMessages.length = 200;
    res.json({ messages: DataEngine.STATE.agentMessages.slice(0, limit), total: DataEngine.STATE.agentMessages.length, timestamp: DataEngine.nowISO() });
});
router.get('/topology/nodes', (req, res) => {
    res.json({
        nodes: [
            { id: 'head', x: 0.50, y: 0.20, label: 'HEAD', color: '#7ec8c8', radius: 30 },
            { id: 'mon', x: 0.15, y: 0.75, label: 'MON', color: '#7ec8c8', radius: 22 },
            { id: 'tia', x: 0.38, y: 0.75, label: 'TIA', color: '#c9a862', radius: 22 },
            { id: 'rca', x: 0.62, y: 0.75, label: 'RCA', color: '#c27a6e', radius: 22 },
            { id: 'lea', x: 0.85, y: 0.75, label: 'LEA', color: '#82b99a', radius: 22 },
        ],
        edges: [
            ['head', 'mon'], ['head', 'tia'], ['head', 'rca'], ['head', 'lea'],
            ['mon', 'tia'], ['tia', 'rca'], ['rca', 'lea']
        ],
        timestamp: DataEngine.nowISO()
    });
});
router.post('/incident/trigger', (req, res) => {
    const attack = DataEngine.triggerAttack();
    if (!attack) return res.status(409).json({ error: 'Incident already in progress.' });
    const broadcast = req.app.locals.broadcast;
    if (broadcast) broadcast({ type: 'INCIDENT_TRIGGERED', payload: attack });
    agentMetrics.head.escalations++;
    agentMetrics.head.directives += 4;
    agentMetrics.rca.actions += 3;
    agentMetrics.lea.updates++;
    res.json({ success: true, incident: attack, timestamp: DataEngine.nowISO() });
});
router.get('/risk-gauge', (req, res) => {
    const { STATE } = DataEngine;
    const score = STATE.attackInProgress ? DataEngine.rand(0.6, 0.97) : DataEngine.rand(0.2, 0.65);
    const label = score > 0.8 ? 'CRITICAL' : score > 0.6 ? 'HIGH' : score > 0.4 ? 'MEDIUM' : 'LOW';
    res.json({ score: parseFloat(score.toFixed(3)), cvss: parseFloat((score * 10).toFixed(1)), label, timestamp: DataEngine.nowISO() });
});
router.get('/:id', (req, res) => {
    const id = req.params.id;
    const agent = AGENT_DEFS[id];
    if (!agent) return res.status(404).json({ error: `Agent '${id}' not found.` });
    agentMetrics.mon.events += DataEngine.randInt(800, 3200);
    agentMetrics.mon.alerts += Math.random() < 0.35 ? 1 : 0;
    agentMetrics.tia.iocs += Math.random() < 0.5 ? DataEngine.randInt(1, 3) : 0;
    agentMetrics.rca.actions += Math.random() < 0.3 ? 1 : 0;
    agentMetrics.lea.audits += 1;
    agentMetrics.head.directives += Math.random() < 0.4 ? 1 : 0;
    res.json({ ...agent, status: 'ONLINE', metrics: agentMetrics[id], timestamp: DataEngine.nowISO() });
});
module.exports = router;