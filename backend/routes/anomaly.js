const express = require('express');
const router = express.Router();
const DataEngine = require('../engine/dataEngine');
router.get('/log', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const page = parseInt(req.query.page) || 1;
    const typeFilter = req.query.type;
    for (let i = 0; i < 2; i++) {
        DataEngine.STATE.anomalyLog.unshift(DataEngine.generateAnomalyEvent());
    }
    if (DataEngine.STATE.anomalyLog.length > 200) DataEngine.STATE.anomalyLog.length = 200;
    let items = DataEngine.STATE.anomalyLog;
    if (typeFilter) items = items.filter(i => i.type === typeFilter);
    const total = items.length;
    const paginated = items.slice((page - 1) * limit, page * limit);
    res.json({ items: paginated, total, page, limit, pages: Math.ceil(total / limit) });
});
router.get('/categories', (req, res) => {
    const { attacks } = DataEngine.STATE;
    const total = Math.max(1, Object.values(attacks).reduce((a, b) => a + b, 0));
    res.json({
        categories: {
            BruteForce: { count: attacks.bf, percentage: parseFloat(((attacks.bf / total) * 100).toFixed(1)) },
            DataExfiltration: { count: attacks.de, percentage: parseFloat(((attacks.de / total) * 100).toFixed(1)) },
            LateralMovement: { count: attacks.lm, percentage: parseFloat(((attacks.lm / total) * 100).toFixed(1)) },
            DDoSPattern: { count: attacks.dd, percentage: parseFloat(((attacks.dd / total) * 100).toFixed(1)) },
            ZeroDay: { count: attacks.zd, percentage: parseFloat(((attacks.zd / total) * 100).toFixed(1)) },
        },
        total,
        timestamp: DataEngine.nowISO()
    });
});
router.get('/baseline', (req, res) => {
    const n = 80;
    const baseline = Array.from({ length: n }, (_, i) =>
        parseFloat((100 + 20 * Math.sin(i * 0.3) + DataEngine.rand(-5, 5)).toFixed(2))
    );
    const observed = baseline.map(v =>
        parseFloat((v + DataEngine.rand(-10, 25)).toFixed(2))
    );
    const anomalyPoints = [];
    for (let i = 0; i < 4; i++) {
        const idx = DataEngine.randInt(5, n - 5);
        const val = baseline[idx] + DataEngine.rand(40, 100);
        observed[idx] = parseFloat(val.toFixed(2));
        anomalyPoints.push({ idx, val: parseFloat(val.toFixed(2)) });
    }
    res.json({ n, baseline, observed, anomalyPoints, timestamp: DataEngine.nowISO() });
});
router.get('/risk-dist', (req, res) => {
    res.json({
        distribution: { ...DataEngine.STATE.riskBuckets },
        total: Object.values(DataEngine.STATE.riskBuckets).reduce((a, b) => a + b, 0),
        timestamp: DataEngine.nowISO()
    });
});
router.get('/live', (req, res) => {
    const event = DataEngine.generateAnomalyEvent();
    DataEngine.STATE.anomalyLog.unshift(event);
    res.json(event);
});
router.get('/stats', (req, res) => {
    const { STATE } = DataEngine;
    const totalAnomalies = STATE.anomalies;
    const criticalCount = STATE.riskBuckets.Critical;
    const detectionRate = parseFloat((97.4 + DataEngine.rand(-0.5, 0.5)).toFixed(2));
    const falsePositiveRate = parseFloat((1.2 + DataEngine.rand(-0.3, 0.3)).toFixed(2));
    res.json({
        totalAnomalies,
        criticalCount,
        detectionRate,
        falsePositiveRate,
        avgZScore: parseFloat(DataEngine.rand(2.5, 4.5).toFixed(2)),
        modelVersion: 'LSTM-v3',
        threshold: 0.55,
        attackCounts: { ...STATE.attacks },
        timestamp: DataEngine.nowISO()
    });
});
module.exports = router;