const express = require('express');
const router = express.Router();
const DataEngine = require('../engine/dataEngine'); const db = require('../db/database');
const KILL_CHAIN_STAGES = [
    { id: 'recon', name: 'Reconnaissance', icon: '⦿' },
    { id: 'weapon', name: 'Weaponization', icon: '⚔' },
    { id: 'delivery', name: 'Delivery', icon: '▶' },
    { id: 'exploit', name: 'Exploitation', icon: '✖' },
    { id: 'install', name: 'Installation', icon: '⚙' },
    { id: 'c2', name: 'C2 Channel', icon: '◎' },
    { id: 'action', name: 'Exfiltration', icon: '◆' },
];
router.get('/kill-chain', (req, res) => {
    const { STATE } = DataEngine;
    const stages = KILL_CHAIN_STAGES.map((stage, idx) => {
        let status = 'MONITOR';
        if (STATE.attackInProgress && idx <= STATE.currentAttack?.killChainStep) {
            status = 'DETECTED';
        } else if (!STATE.attackInProgress && STATE.currentAttack?.status === 'mitigated') {
            status = 'BLOCKED';
        }
        return { ...stage, status };
    });
    res.json({ stages, attackInProgress: STATE.attackInProgress, timestamp: DataEngine.nowISO() });
});
router.get('/ueba', (req, res) => {
    const { rand } = DataEngine;
    const entities = db.all('SELECT * FROM ueba_entities');
    const mapped = entities.map(e => ({
        id: e.id,
        email: e.email,
        name: e.name,
        role: e.role,
        riskScore: Math.round(e.risk_score + rand(-2, 4)),
        riskClass: e.risk_class,
        lastActivity: e.last_activity,
        anomalyFlags: e.anomaly_flags,
        department: e.department
    }));
    res.json({ entities: mapped, timestamp: DataEngine.nowISO() });
});
router.get('/process-chain', (req, res) => {
    res.json({
        nodes: [
            { id: 0, x: 0.5, y: 0.08, label: 'svchost.exe', color: '#7b2fff', suspicious: false },
            { id: 1, x: 0.3, y: 0.3, label: 'cmd.exe', color: '#00d4ff', suspicious: true },
            { id: 2, x: 0.7, y: 0.3, label: 'powershell', color: '#00d4ff', suspicious: true },
            { id: 3, x: 0.2, y: 0.55, label: 'net.exe', color: '#ffd700', suspicious: true },
            { id: 4, x: 0.5, y: 0.55, label: 'mshta.exe', color: '#ff8c00', suspicious: true },
            { id: 5, x: 0.7, y: 0.55, label: 'wscript', color: '#ff3366', suspicious: true },
            { id: 6, x: 0.4, y: 0.8, label: 'Payload', color: '#ff3366', suspicious: true, malicious: true },
        ],
        edges: [[0, 1], [0, 2], [1, 3], [1, 4], [2, 5], [4, 6], [5, 6]],
        timestamp: DataEngine.nowISO()
    });
});
router.get('/mitre', (req, res) => {
    const TACTICS = ['Recon', 'Resource Dev', 'Initial Access', 'Execution', 'Persistence', 'Priv Esc', 'Defense Evasion', 'Cred Access', 'Discovery', 'Lateral Move', 'Collection', 'Exfiltration'];
    const TECHS = ['T1595', 'T1583', 'T1133', 'T1059', 'T1547', 'T1068', 'T1027', 'T1003', 'T1082', 'T1021', 'T1056', 'T1048'];
    const rows = 5;
    const cells = [];
    for (let row = 0; row < rows; row++) {
        TECHS.forEach((tech, i) => {
            const r = Math.random();
            cells.push({
                tactic: TACTICS[i],
                technique: tech.replace('T', 'T' + (row * 100 + '').slice(-2)),
                coverage: r > 0.7 ? 'covered' : r > 0.45 ? 'partial' : 'uncovered',
                row
            });
        });
    }
    res.json({ tactics: TACTICS, techniques: TECHS, cells, rows, timestamp: DataEngine.nowISO() });
});
router.get('/predictions', (req, res) => {
    const { rand } = DataEngine;
    res.json({
        predictions: [
            { name: 'Brute Force Login', probability: parseFloat((0.72 + rand(-0.05, 0.1)).toFixed(3)), color: '#ff3366' },
            { name: 'Ransomware Deploy', probability: parseFloat((0.45 + rand(-0.05, 0.1)).toFixed(3)), color: '#7b2fff' },
            { name: 'Data Exfiltration', probability: parseFloat((0.38 + rand(-0.05, 0.1)).toFixed(3)), color: '#ff8c00' },
            { name: 'DDoS Campaign', probability: parseFloat((0.61 + rand(-0.05, 0.1)).toFixed(3)), color: '#ffd700' },
            { name: 'APT Intrusion', probability: parseFloat((0.29 + rand(-0.05, 0.1)).toFixed(3)), color: '#00d4ff' },
        ],
        modelVersion: 'LSTM-v3',
        confidence: parseFloat((96.7 + rand(-0.5, 0.5)).toFixed(1)),
        timestamp: DataEngine.nowISO()
    });
});
module.exports = router;
