const { v4: uuidv4 } = require('uuid');
function rand(min, max) { return Math.random() * (max - min) + min; }
function randInt(min, max) { return Math.floor(rand(min, max + 1)); }
function pick(arr) { return arr[randInt(0, arr.length - 1)]; }
function nowISO() { return new Date().toISOString(); }
function shortHash() { return [...Array(8)].map(() => Math.floor(Math.random() * 16).toString(16)).join(''); }
function fullHash() { return [...Array(32)].map(() => Math.floor(Math.random() * 16).toString(16)).join(''); }
function randomIP() {
    const types = [
        `192.168.${randInt(0, 255)}`,
        `10.${randInt(0, 255)}.${randInt(0, 255)}`,
        `172.${randInt(16, 31)}.${randInt(0, 255)}`,
        `45.${randInt(33, 120)}.${randInt(1, 254)}`,
        `185.${randInt(100, 250)}.${randInt(1, 254)}`
    ];
    return `${pick(types)}.${randInt(1, 254)}`;
}
const THREAT_TYPES = [
    { name: 'Brute Force SSH', sev: 'high', category: 'bf', action: 'IP Blacklist + Rate Limit', cvss: 7.5 },
    { name: 'SQL Injection', sev: 'critical', category: 'de', action: 'WAF Block + Isolation', cvss: 9.8 },
    { name: 'DDoS Flood', sev: 'critical', category: 'dd', action: 'Throttle + CDN Reroute', cvss: 8.6 },
    { name: 'Port Scan', sev: 'medium', category: 'bf', action: 'Firewall Update', cvss: 5.3 },
    { name: 'Phishing Email', sev: 'high', category: 'de', action: 'Quarantine + User Alert', cvss: 7.2 },
    { name: 'Ransomware', sev: 'critical', category: 'zd', action: 'Isolate + Snapshot Restore', cvss: 9.9 },
    { name: 'Zero-Day Exploit', sev: 'critical', category: 'zd', action: 'Virtual Patch + Honeypot', cvss: 10.0 },
    { name: 'Lateral Movement', sev: 'high', category: 'lm', action: 'Segment Isolation', cvss: 8.1 },
    { name: 'Data Exfiltration', sev: 'critical', category: 'de', action: 'Channel Block + Forensics', cvss: 9.3 },
    { name: 'Credential Stuffing', sev: 'medium', category: 'bf', action: 'MFA Enforcement', cvss: 6.5 },
    { name: 'APT Intrusion', sev: 'critical', category: 'lm', action: 'Full Incident Response', cvss: 9.7 },
    { name: 'C2 Callback', sev: 'high', category: 'lm', action: 'Egress Block + Isolation', cvss: 8.4 },
];
const GEO_ORIGINS = ['CN', 'RU', 'KP', 'IR', 'US', 'BR', 'NG', 'TR', 'UA', 'DE', 'FR', 'IN'];
const PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'SMTP', 'FTP', 'SSH'];
const STREAM_TYPES = [
    { type: 'ALLOW', msgs: ['TCP connection accepted', 'HTTPS handshake OK', 'DNS query resolved', 'Auth token validated', 'Certificate chain verified'] },
    { type: 'DENY', msgs: ['Blacklisted IP blocked', 'SYN flood dropped', 'Bot signature matched', 'Rule 4412 triggered', 'Rate limit exceeded'] },
    { type: 'WARN', msgs: ['Rate limit threshold', 'Unusual port access', 'GeoIP mismatch', 'Certificate expiring', 'Entropy anomaly'] },
    { type: 'INFO', msgs: ['Policy updated', 'Scan completed', 'Model checkpoint saved', 'Ruleset refreshed', 'Signature DB synced'] },
];
const AGENT_NAMES = {
    head: 'HEAD-AGENT',
    mon: 'MON-AGENT',
    tia: 'TIA-AGENT',
    rca: 'RCA-AGENT',
    lea: 'LEA-AGENT'
};
const MON_MSGS = [
    'Port scan detected on subnet 10.0.1.0/24',
    'Unusual DNS query volume — 3.2× baseline',
    'Failed SSH brute-force: 847 attempts/min',
    'Endpoint EDR triggered on host WIN-042',
    'TLS certificate anomaly on :443',
    'Cloud API rate spike — us-east-1',
    'Network flow entropy increase detected',
    'Log ingestion rate: 45k events/sec',
];
const TIA_MSGS = [
    'IOC match: C2 IP 185.220.101.x in ThreatFox DB',
    'CVE-2024-1234 exploitation attempt — CVSS 9.8',
    'APT28 TTP correlation: Lateral Movement T1021',
    'Malware hash matched VirusTotal (48/62)',
    'Phishing domain registered 2h ago — lookalike',
    'SQLi payload in GET param — OWASP Cat.1',
    'Ransomware family: LockBit 3.0 variant',
    'Zero-day indicator — no existing CVE found',
];
const RCA_MSGS = [
    'IP blacklist rule pushed to perimeter FW',
    'Segment 10.0.3.0/24 isolated — VLAN 99',
    'Honeypot deployed at 10.0.1.250',
    'Rate limit: 50 req/s applied on API gateway',
    'Virtual patch deployed for CVE-2024-1234',
    'Self-healing: snapshot restored on win-042',
    'MFA policy enforced on all admin accounts',
    'C2 egress channel blocked on port 4444',
];
const LEA_MSGS = [
    'Model retrained with 128 new attack samples',
    'Forensic chain: block anchored to ledger',
    'Knowledge base updated — TTPs classified',
    'Threat pattern recorded for future inference',
    'GDPR audit record generated',
    'SIEM log export: 4,200 new entries',
    'Baseline model drift: Δ=0.003 — within bounds',
    'Signature DB synced with global threat intel',
];
const HEAD_DIRECTIVES = [
    'DIRECTIVE → MON: increase scan frequency on subnet 10.0.2.0/24',
    'DIRECTIVE → TIA: correlate IOC set #A4F7 with recent alerts',
    'DIRECTIVE → RCA: deploy honeypot on DMZ segment',
    'DIRECTIVE → LEA: trigger full model checkpoint',
    'DIRECTIVE → ALL: elevate monitoring to ORANGE posture',
    'DIRECTIVE → RCA: isolate host WIN-042 pending investigation',
    'DIRECTIVE → TIA: run CVE lookup for payload signature 0xDE4D',
    'DIRECTIVE → MON: switch to deep-packet inspection mode',
];
const STATE = {
    threatLevel: 'MODERATE',
    eventsPerSec: 0,
    blockedCount: 0,
    neutralized: 0,
    anomalies: 0,
    accuracy: 97.4,
    uptime: 99.98,
    attackInProgress: false,
    currentAttack: null,
    auditSeq: 1,
    chainLength: 0,
    epochs: 0,
    loss: 1.0,
    attacks: { bf: 0, de: 0, lm: 0, dd: 0, zd: 0 },
    mlAccuracy: 97.4,
    users: [
        { id: 'u001', email: 'user@organization.corp', name: 'Authorized User', role: 'analyst', passwordHash: '$2a$10$rQJJwQwmhfV5MjIHG5YNMOJbj.P2f/hDjqTXS.PCTU5Yap1ww5Kqe' },
        { id: 'u002', email: 'admin@aegis.system', name: 'System Admin', role: 'admin', passwordHash: '$2a$10$rQJJwQwmhfV5MjIHG5YNMOJbj.P2f/hDjqTXS.PCTU5Yap1ww5Kqe' },
    ],
    auditLog: [],
    threatFeed: [],
    anomalyLog: [],
    responseTimeline: [],
    decisionMatrix: [],
    mlInferenceLog: [],
    agentMessages: [],
    attackerIPs: {},
    riskBuckets: { Low: 0, Medium: 0, High: 0, Critical: 0 },
    protocolCounts: { TCP: 45, UDP: 18, HTTP: 12, HTTPS: 32, DNS: 8, ICMP: 5, SMTP: 3 },
};
function seed() {
    for (let i = 0; i < 10; i++) {
        STATE.auditLog.unshift(generateAuditEntry());
        STATE.threatFeed.unshift(generateThreatFeedItem());
        STATE.anomalyLog.unshift(generateAnomalyEvent());
    }
    STATE.responseTimeline.push(
        { id: uuidv4(), title: 'System Online — All Defense Layers Active', type: 'success', timestamp: nowISO() },
        { id: uuidv4(), title: 'ML Threat Model v3.1 Loaded', type: 'info', timestamp: nowISO() },
        { id: uuidv4(), title: 'Initial Baseline Scan Complete', type: 'info', timestamp: nowISO() }
    );
    for (let i = 0; i < 5; i++) {
        STATE.decisionMatrix.unshift(generateDecisionMatrixRow());
    }
}
function generateThreatFeedItem() {
    const threat = pick(THREAT_TYPES);
    return {
        id: uuidv4(),
        severity: threat.sev,
        name: threat.name,
        source: randomIP(),
        action: threat.action,
        category: threat.category,
        cvss: threat.cvss,
        country: pick(GEO_ORIGINS),
        timestamp: nowISO()
    };
}
function generateStreamEvent() {
    const type = pick(STREAM_TYPES);
    return {
        id: uuidv4(),
        type: type.type,
        message: pick(type.msgs),
        ip: randomIP(),
        port: randInt(1024, 65535),
        protocol: pick(PROTOCOLS),
        timestamp: nowISO()
    };
}
function generateIPTableEntry() {
    const ip = randomIP();
    STATE.attackerIPs[ip] = (STATE.attackerIPs[ip] || 0) + randInt(1, 10);
    return { ip, country: pick(GEO_ORIGINS), hits: STATE.attackerIPs[ip] };
}
function generateAnomalyEvent() {
    const types = ['BruteForce', 'DataExfil', 'LateralMove', 'DDoSPattern', 'ZeroDay'];
    const type = pick(types);
    const score = rand(0.55, 0.98);
    const catMap = { BruteForce: 'bf', DataExfil: 'de', LateralMove: 'lm', DDoSPattern: 'dd', ZeroDay: 'zd' };
    const cat = catMap[type] || 'bf';
    STATE.attacks[cat]++;
    STATE.anomalies++;
    const severity = score > 0.85 ? 'Critical' : score > 0.7 ? 'High' : score > 0.5 ? 'Medium' : 'Low';
    STATE.riskBuckets[severity]++;
    return {
        id: uuidv4(),
        type,
        score: parseFloat(score.toFixed(4)),
        scorePercent: parseFloat((score * 100).toFixed(1)),
        source: randomIP(),
        zScore: parseFloat(rand(2, 5).toFixed(2)),
        model: 'LSTM-v3',
        severity,
        timestamp: nowISO()
    };
}
function generateAuditEntry() {
    const EVENT_TYPES = [
        { t: 'BLOCK', msgs: ['Malicious IP blocked', 'Intrusion attempt denied', 'Ransomware quarantined', 'C2 channel severed'] },
        { t: 'ALLOW', msgs: ['Trusted connection allowed', 'Policy allowlist matched', 'Auth success'] },
        { t: 'POLICY', msgs: ['Firewall rule updated', 'Defense posture changed', 'Threshold adjusted'] },
        { t: 'SYSTEM', msgs: ['ML model retrained', 'Snapshot checkpoint', 'Merkle tree anchored', 'SIEM synchronized'] },
    ];
    const type = pick(EVENT_TYPES);
    const hash = shortHash();
    STATE.chainLength++;
    STATE.auditSeq++;
    return {
        id: uuidv4(),
        seq: String(STATE.auditSeq).padStart(6, '0'),
        type: type.t,
        message: pick(type.msgs),
        hash: '0x' + hash,
        chainLength: STATE.chainLength,
        latestBlock: '0x' + fullHash(),
        merkleRoot: '0x' + fullHash(),
        timestamp: nowISO()
    };
}
function generateDecisionMatrixRow(threatOverride) {
    const threat = threatOverride || pick(THREAT_TYPES);
    const conf = rand(0.78, 0.99);
    const ms = randInt(80, 400);
    return {
        id: uuidv4(),
        threatType: threat.name,
        severity: threat.sev,
        confidence: parseFloat((conf * 100).toFixed(1)),
        action: threat.action,
        responseTimeMs: ms,
        status: threat.sev === 'low' ? 'MONITORED' : 'MITIGATED',
        cvss: threat.cvss,
        timestamp: nowISO()
    };
}
function generateMLInferenceEntry() {
    const isMalicious = Math.random() < 0.1;
    const isSusp = Math.random() < 0.25;
    const type = isMalicious ? 'malicious' : (isSusp ? 'suspicious' : 'benign');
    const statusText = isMalicious ? 'BLOCK' : (isSusp ? 'FLAG' : 'PASS');
    const conf = parseFloat((Math.random() * 9 + 90).toFixed(1));
    const ips = ['192.168.1.14', '10.0.0.8', '172.16.0.4', '198.51.100.2', '10.5.21.3', '45.33.12.98'];
    return {
        id: uuidv4(),
        ip: pick(ips),
        confidence: conf,
        prediction: type,
        status: statusText,
        model: 'LSTM-v3',
        timestamp: nowISO()
    };
}
function generateAgentMessage() {
    const agents = ['head', 'mon', 'tia', 'rca', 'lea'];
    const msgMap = { mon: MON_MSGS, tia: TIA_MSGS, rca: RCA_MSGS, lea: LEA_MSGS, head: HEAD_DIRECTIVES };
    const tags = ['alert', 'intel', 'action', 'audit', 'directive', 'info'];
    const from = pick(agents);
    let to = pick(agents);
    while (to === from) to = pick(agents);
    return {
        id: uuidv4(),
        from,
        fromName: AGENT_NAMES[from],
        to,
        toName: AGENT_NAMES[to],
        body: pick(msgMap[from] || HEAD_DIRECTIVES),
        tag: pick(tags),
        timestamp: nowISO()
    };
}
function generateMLUpdate() {
    STATE.epochs++;
    const t = STATE.epochs / 200;
    STATE.loss = Math.max(0.01, 1 - 0.97 * (1 - Math.exp(-5 * t)) + rand(-0.005, 0.005));
    const acc = Math.min(1, 0.97 * (1 - Math.exp(-5 * t)) + rand(-0.005, 0.005));
    const f1 = Math.min(1, acc * 0.99);
    STATE.mlAccuracy = 97 + acc * 0.4;
    return {
        epochs: STATE.epochs,
        loss: parseFloat(STATE.loss.toFixed(4)),
        valAccuracy: parseFloat((acc * 100).toFixed(1)),
        f1Score: parseFloat(f1.toFixed(3)),
        accuracy: parseFloat(STATE.mlAccuracy.toFixed(2)),
        timestamp: nowISO()
    };
}
function generateLiveTick() {
    STATE.eventsPerSec = randInt(120, STATE.attackInProgress ? 850 : 350);
    STATE.blockedCount += Math.random() < 0.4 ? 1 : 0;
    return {
        eventsPerSec: STATE.eventsPerSec,
        blockedCount: STATE.blockedCount,
        neutralized: STATE.neutralized,
        anomalies: STATE.anomalies,
        accuracy: parseFloat(STATE.mlAccuracy.toFixed(1)),
        threatLevel: STATE.threatLevel,
        attackInProgress: STATE.attackInProgress,
        protocolCounts: getUpdatedProtocolCounts(),
        radarValues: Array(6).fill(0).map(() => parseFloat(rand(0.1, 1).toFixed(3))),
        traffic: randInt(80, STATE.attackInProgress ? 900 : 200),
        timestamp: nowISO()
    };
}
function getUpdatedProtocolCounts() {
    const keys = Object.keys(STATE.protocolCounts);
    keys.forEach(k => {
        STATE.protocolCounts[k] = Math.max(1, STATE.protocolCounts[k] + randInt(-2, 5));
    });
    return { ...STATE.protocolCounts };
}
function getSystemState() {
    return {
        threatLevel: STATE.threatLevel,
        eventsPerSec: STATE.eventsPerSec,
        blockedCount: STATE.blockedCount,
        neutralized: STATE.neutralized,
        anomalies: STATE.anomalies,
        accuracy: STATE.mlAccuracy,
        uptime: STATE.uptime,
        attackInProgress: STATE.attackInProgress,
        chainLength: STATE.chainLength,
        attacks: { ...STATE.attacks },
        riskBuckets: { ...STATE.riskBuckets },
        timestamp: nowISO()
    };
}
function triggerAttack() {
    if (STATE.attackInProgress) return null;
    STATE.attackInProgress = true;
    STATE.threatLevel = 'CRITICAL';
    const threat = pick(THREAT_TYPES.filter(t => t.sev === 'critical'));
    STATE.currentAttack = {
        id: uuidv4(),
        threat,
        source: randomIP(),
        startTime: nowISO(),
        status: 'active',
        killChainStep: 0
    };
    setTimeout(() => {
        STATE.attackInProgress = false;
        STATE.threatLevel = 'MODERATE';
        STATE.neutralized++;
        STATE.blockedCount++;
        if (STATE.currentAttack) {
            STATE.currentAttack.status = 'mitigated';
            STATE.currentAttack.endTime = nowISO();
        }
        const entry = generateAuditEntry();
        entry.type = 'BLOCK';
        entry.message = `Attack Neutralized: ${threat.name}`;
        STATE.auditLog.unshift(entry);
        STATE.decisionMatrix.unshift(generateDecisionMatrixRow(threat));
    }, 9000);
    return STATE.currentAttack;
}
function getCurrentAttack() {
    return STATE.currentAttack;
}
seed();
module.exports = {
    STATE,
    generateThreatFeedItem,
    generateStreamEvent,
    generateIPTableEntry,
    generateAnomalyEvent,
    generateAuditEntry,
    generateDecisionMatrixRow,
    generateMLInferenceEntry,
    generateAgentMessage,
    generateMLUpdate,
    generateLiveTick,
    getSystemState,
    triggerAttack,
    getCurrentAttack,
    pick,
    rand,
    randInt,
    randomIP,
    nowISO,
    fullHash,
    shortHash,
    GEO_ORIGINS,
    PROTOCOLS,
    THREAT_TYPES,
};