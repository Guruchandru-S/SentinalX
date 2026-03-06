const AEGIS_API = (() => {
    const BASE = 'http://localhost:3001/api';
    let _token = null;
    let _ws = null;
    let _wsListeners = {};

    function setToken(t) {
        _token = t;
        if (t) localStorage.setItem('aegis_token', t);
    }

    function getToken() {
        return _token || localStorage.getItem('aegis_token');
    }

    function clearToken() {
        _token = null;
        localStorage.removeItem('aegis_token');
    }

    async function request(method, path, body) {
        const headers = { 'Content-Type': 'application/json' };
        const tok = getToken();
        if (tok) headers['Authorization'] = `Bearer ${tok}`;
        try {
            const res = await fetch(`${BASE}${path}`, {
                method,
                headers,
                body: body ? JSON.stringify(body) : undefined
            });
            const data = await res.json();
            return { ok: res.ok, status: res.status, data };
        } catch (e) {
            console.warn('[AEGIS API] Request failed:', path, e.message);
            return { ok: false, status: 0, error: e.message, data: null };
        }
    }

    const get = (p) => request('GET', p);
    const post = (p, b) => request('POST', p, b);

    function connectWS() {
        if (_ws && _ws.readyState === WebSocket.OPEN) return;
        try {
            _ws = new WebSocket('ws://localhost:3001/ws');
            _ws.onopen = () => {
                console.log('[AEGIS WS] Connected');
                emit('ws:connected');
            };
            _ws.onmessage = (evt) => {
                try {
                    const msg = JSON.parse(evt.data);
                    emit(msg.type, msg.payload);
                    emit('ws:message', msg);
                } catch (_) { }
            };
            _ws.onclose = () => {
                console.warn('[AEGIS WS] Disconnected. Reconnecting in 3s...');
                emit('ws:disconnected');
                setTimeout(connectWS, 3000);
            };
            _ws.onerror = (e) => {
                console.warn('[AEGIS WS] Error', e);
            };
        } catch (e) {
            console.warn('[AEGIS WS] Could not connect:', e.message);
        }
    }

    function sendWS(type, payload) {
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            _ws.send(JSON.stringify({ type, payload }));
        }
    }

    function on(event, fn) {
        if (!_wsListeners[event]) _wsListeners[event] = [];
        _wsListeners[event].push(fn);
        return () => { _wsListeners[event] = _wsListeners[event].filter(f => f !== fn); };
    }

    function emit(event, data) {
        (_wsListeners[event] || []).forEach(fn => { try { fn(data); } catch (e) { } });
    }

    const auth = {
        async login(email, password) {
            const r = await post('/auth/login', { email, password });
            if (r.ok && r.data.token) setToken(r.data.token);
            return r;
        },
        async googleSSO(credential) {
            const r = await post('/auth/google', { credential });
            if (r.ok && r.data.token) setToken(r.data.token);
            return r;
        },
        logout() { clearToken(); sendWS('LOGOUT', {}); },
        me() { return get('/auth/me'); },
    };

    const dashboard = {
        state: () => get('/dashboard/state'),
        kpis: () => get('/dashboard/kpis'),
        threatFeed: (limit = 20) => get(`/dashboard/threat-feed?limit=${limit}`),
        defenseLayers: () => get('/dashboard/defense-layers'),
        heatmap: () => get('/dashboard/heatmap'),
        traffic: () => get('/dashboard/traffic'),
        radar: () => get('/dashboard/radar'),
        simulateAttack: () => post('/dashboard/simulate-attack', {}),
    };

    const threats = {
        feed: (limit = 20, page = 1, sev) => get(`/threats/feed?limit=${limit}&page=${page}${sev ? '&severity=' + sev : ''}`),
        types: () => get('/threats/types'),
        live: () => get('/threats/live'),
        ipTable: (limit = 10) => get(`/threats/ip-table?limit=${limit}`),
        geo: (count = 20) => get(`/threats/geo?count=${count}`),
        report: (name, severity, source, description) => post('/threats/report', { name, severity, source, description }),
        getById: (id) => get(`/threats/${id}`),
    };

    const anomaly = {
        log: (limit = 20, page = 1, type) => get(`/anomaly/log?limit=${limit}&page=${page}${type ? '&type=' + type : ''}`),
        categories: () => get('/anomaly/categories'),
        baseline: () => get('/anomaly/baseline'),
        riskDist: () => get('/anomaly/risk-dist'),
        live: () => get('/anomaly/live'),
        stats: () => get('/anomaly/stats'),
    };

    const behavior = {
        killChain: () => get('/behavior/kill-chain'),
        ueba: () => get('/behavior/ueba'),
        processChain: () => get('/behavior/process-chain'),
        mitre: () => get('/behavior/mitre'),
        predictions: () => get('/behavior/predictions'),
    };

    const response = {
        playbooks: () => get('/response/playbooks'),
        activatePlaybook: (name) => post(`/response/playbooks/${name}/activate`, {}),
        timeline: (limit = 30) => get(`/response/timeline?limit=${limit}`),
        addTimeline: (title, type) => post('/response/timeline', { title, type }),
        decisionMatrix: (limit = 20) => get(`/response/decision-matrix?limit=${limit}`),
        status: () => get('/response/status'),
        triggerAttack: () => post('/response/trigger-attack', {}),
    };

    const forensics = {
        auditLog: (limit = 30, page = 1, type) => get(`/forensics/audit-log?limit=${limit}&page=${page}${type ? '&type=' + type : ''}`),
        integrity: () => get('/forensics/integrity'),
        compliance: () => get('/forensics/compliance'),
        exportUrl: () => `${BASE}/forensics/export`,
        live: () => get('/forensics/live'),
        addRecord: (message, type) => post('/forensics/audit-log', { message, type }),
    };

    const ml = {
        trainingStats: () => get('/ml/training-stats'),
        trainingHistory: (points = 80) => get(`/ml/training-history?points=${points}`),
        inferenceLog: (limit = 30) => get(`/ml/inference-log?limit=${limit}`),
        inferenceLive: () => get('/ml/inference-log/live'),
        confusionMatrix: () => get('/ml/confusion-matrix'),
        featureWeights: () => get('/ml/feature-weights'),
        generateReport: () => post('/ml/generate-report', {}),
        modelInfo: () => get('/ml/model-info'),
    };

    const agents = {
        all: () => get('/agents/'),
        getAgent: (id) => get(`/agents/${id}`),
        messageBus: (limit = 30) => get(`/agents/message-bus/live?limit=${limit}`),
        topology: () => get('/agents/topology/nodes'),
        triggerIncident: () => post('/agents/incident/trigger', {}),
        riskGauge: () => get('/agents/risk-gauge'),
    };

    const monitor = {
        eventStream: (limit = 60) => get(`/monitor/event-stream?limit=${limit}`),
        protocolDist: () => get('/monitor/protocol-distribution'),
        trafficHistory: (points = 60) => get(`/monitor/traffic-history?points=${points}`),
        ipTable: (limit = 10) => get(`/monitor/ip-table?limit=${limit}`),
        stats: () => get('/monitor/stats'),
        sseUrl: () => `${BASE}/monitor/event-stream/live`,
    };

    async function isOnline() {
        const r = await get('/health');
        return r.ok;
    }

    return {
        auth, dashboard, threats, anomaly, behavior,
        response, forensics, ml, agents, monitor,
        isOnline, connectWS, sendWS, on, emit, getToken, setToken
    };
})();

document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        AEGIS_API.connectWS();
        AEGIS_API.on('LIVE_TICK', (payload) => {
            if (!payload) return;
            if (typeof STATE !== 'undefined') {
                STATE.eventsPerSec = payload.eventsPerSec || STATE.eventsPerSec;
                STATE.blockedCount = payload.blockedCount || STATE.blockedCount;
                STATE.neutralized = payload.neutralized || STATE.neutralized;
                STATE.anomalies = payload.anomalies || STATE.anomalies;
                if (payload.accuracy) STATE.accuracy = payload.accuracy;
                if (payload.threatLevel) STATE.threatLevel = payload.threatLevel;
            }
        });
        AEGIS_API.on('THREAT_FEED', (payload) => {
            if (payload && typeof addThreatFeedItemFromData === 'function') {
                addThreatFeedItemFromData(payload);
            }
        });
        AEGIS_API.on('ATTACK_STARTED', (payload) => {
            if (payload && typeof STATE !== 'undefined') {
                STATE.attackInProgress = true;
            }
        });
        console.log('[AEGIS API Client] Initialized. Backend: http://localhost:3001');
    }, 500);
});