const STATE = {
  threatLevel: 'MODERATE',
  eventsPerSec: 0,
  blockedCount: 0,
  neutralized: 0,
  anomalies: 0,
  accuracy: 97.4,
  uptime: 99.98,
  streamPaused: false,
  auditSeq: 1,
  chainLength: 0,
  epochs: 0,
  loss: 1.0,
  attacks: {
    bf: 0, de: 0, lm: 0, dd: 0, zd: 0
  },
  attackInProgress: false,
  killChainStep: -1,
};
const THREAT_TYPES = [
  { name: 'Brute Force SSH', sev: 'high', action: 'IP Blacklist + Rate Limit' },
  { name: 'SQL Injection', sev: 'critical', action: 'WAF Block + Isolation' },
  { name: 'DDoS Flood', sev: 'critical', action: 'Throttle + CDN Reroute' },
  { name: 'Port Scan', sev: 'medium', action: 'Firewall Update' },
  { name: 'Phishing Email', sev: 'high', action: 'Quarantine + User Alert' },
  { name: 'Ransomware', sev: 'critical', action: 'Isolate + Snapshot Restore' },
  { name: 'Zero-Day Exploit', sev: 'critical', action: 'Virtual Patch + Honeypot' },
  { name: 'Lateral Movement', sev: 'high', action: 'Segment Isolation' },
  { name: 'Data Exfiltration', sev: 'critical', action: 'Channel Block + Forensics' },
  { name: 'Credential Stuffing', sev: 'medium', action: 'MFA Enforcement' },
];
const GEO_ORIGINS = ['CN', 'RU', 'KP', 'IR', 'US', 'BR', 'NG', 'TR', 'UA', 'DE'];
const PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'SMTP'];
function rand(min, max) { return Math.random() * (max - min) + min; }
function randInt(min, max) { return Math.floor(rand(min, max + 1)); }
function pick(arr) { return arr[randInt(0, arr.length - 1)]; }
function now() {
  return new Date().toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}
function shortHash() {
  return [...Array(8)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
}
function fullHash() {
  return [...Array(32)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
}
function randomIP() {
  const types = [
    `192.168.${randInt(0, 255)}`,
    `10.${randInt(0, 255)}.${randInt(0, 255)}`,
    `172.${randInt(16, 31)}.${randInt(0, 255)}`,
    `127.0.0`
  ];
  return `${pick(types)}.${randInt(1, 254)}`;
}
function updateClock() {
  const el = document.getElementById('topbar-clock');
  if (el) el.textContent = new Date().toLocaleString('en-US', {
    weekday: 'short', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
  });
}
setInterval(updateClock, 1000);
updateClock();
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + name)?.classList.add('active');
  document.getElementById('nav-' + name)?.classList.add('active');
  if (name === 'monitor') {
    if (typeof liveMap === 'undefined' || !liveMap) {
      initLiveMap();
    } else {
      setTimeout(() => liveMap.invalidateSize(), 50);
      setTimeout(() => liveMap.invalidateSize(), 250);
      if (userLoc) {
        liveMap.setView([userLoc.lat, userLoc.lng], 4);
      }
    }
  }
}
function setThreatLevel(level) {
  STATE.threatLevel = level;
  const badge = document.getElementById('global-threat-badge');
  const val = document.getElementById('global-threat-value');
  if (!badge || !val) return;
  badge.className = 'threat-badge ' + level.toLowerCase();
  val.textContent = level;
}
function updateKPIs() {
  easeUpdate('kpi-neutralized', STATE.neutralized);
  easeUpdate('kpi-anomalies', STATE.anomalies);
  easeUpdate('blocked-count', STATE.blockedCount);
  easeUpdate('events-per-sec', STATE.eventsPerSec);
  const el = document.getElementById('kpi-accuracy');
  if (el) el.textContent = STATE.accuracy.toFixed(1) + '%';
}
function easeUpdate(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = Math.round(val);
}
const HEATMAP_COLS = 60;
const HEATMAP_ROWS = 10;
let heatmapData = Array.from({ length: HEATMAP_ROWS }, () =>
  Array.from({ length: HEATMAP_COLS }, () => Math.random() * 0.4));
function drawHeatmap() {
  const canvas = document.getElementById('heatmapCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  const cw = W / HEATMAP_COLS, ch = H / HEATMAP_ROWS;
  for (let r = 0; r < HEATMAP_ROWS; r++) {
    for (let c = 0; c < HEATMAP_COLS; c++) {
      const v = heatmapData[r][c];
      const alpha = v * 0.9 + 0.05;
      if (v > 0.75) ctx.fillStyle = `rgba(194,122,110,${alpha})`;
      else if (v > 0.50) ctx.fillStyle = `rgba(201,168,98,${alpha})`;
      else if (v > 0.25) ctx.fillStyle = `rgba(192,141,187,${alpha})`;
      else ctx.fillStyle = `rgba(126,200,200,${alpha * 0.5})`;
      ctx.fillRect(c * cw + 1, r * ch + 1, cw - 2, ch - 2);
      ctx.strokeStyle = 'rgba(0,0,0,0.3)';
      ctx.strokeRect(c * cw, r * ch, cw, ch);
    }
  }
}
function updateHeatmap() {
  for (let r = 0; r < HEATMAP_ROWS; r++) {
    for (let c = 0; c < HEATMAP_COLS; c++) {
      const drift = (Math.random() - 0.5) * 0.06;
      heatmapData[r][c] = Math.max(0, Math.min(1, heatmapData[r][c] + drift));
      if (STATE.attackInProgress && Math.random() < 0.02) {
        heatmapData[r][c] = Math.min(1, heatmapData[r][c] + 0.3);
      }
    }
  }
  drawHeatmap();
}
let radarValues = [0.7, 0.4, 0.6, 0.3, 0.8, 0.5];
const RADAR_LABELS = ['Network', 'Endpoint', 'Identity', 'Data', 'App', 'Supply'];
function drawRadar() {
  const canvas = document.getElementById('radarCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 260, H = 260;
  canvas.width = W; canvas.height = H;
  ctx.clearRect(0, 0, W, H);
  const cx = W / 2, cy = H / 2, r = Math.min(cx, cy) - 30;
  const n = radarValues.length;
  const step = (Math.PI * 2) / n;
  for (let ring = 1; ring <= 4; ring++) {
    ctx.beginPath();
    for (let i = 0; i < n; i++) {
      const a = step * i - Math.PI / 2;
      const rr = r * ring / 4;
      i === 0 ? ctx.moveTo(cx + rr * Math.cos(a), cy + rr * Math.sin(a))
        : ctx.lineTo(cx + rr * Math.cos(a), cy + rr * Math.sin(a));
    }
    ctx.closePath();
    ctx.strokeStyle = 'rgba(94,184,212,0.1)';
    ctx.stroke();
  }
  for (let i = 0; i < n; i++) {
    const a = step * i - Math.PI / 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + r * Math.cos(a), cy + r * Math.sin(a));
    ctx.strokeStyle = 'rgba(126,200,200,0.1)';
    ctx.stroke();
  }
  ctx.beginPath();
  for (let i = 0; i < n; i++) {
    const a = step * i - Math.PI / 2;
    const rr = r * radarValues[i];
    i === 0 ? ctx.moveTo(cx + rr * Math.cos(a), cy + rr * Math.sin(a))
      : ctx.lineTo(cx + rr * Math.cos(a), cy + rr * Math.sin(a));
  }
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, 0, W, H);
  grad.addColorStop(0, 'rgba(126,200,200,0.2)');
  grad.addColorStop(1, 'rgba(192,141,187,0.2)');
  ctx.fillStyle = grad;
  ctx.fill();
  ctx.strokeStyle = 'rgba(126,200,200,0.5)';
  ctx.lineWidth = 1.5;
  ctx.stroke();
  ctx.lineWidth = 1;
  for (let i = 0; i < n; i++) {
    const a = step * i - Math.PI / 2;
    const lx = cx + (r + 18) * Math.cos(a);
    const ly = cy + (r + 18) * Math.sin(a);
    ctx.fillStyle = 'rgba(113,139,168,0.9)';
    ctx.font = '11px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(RADAR_LABELS[i], lx, ly);
  }
}
function updateRadar() {
  radarValues = radarValues.map(v => {
    const drift = (Math.random() - 0.5) * 0.05;
    return Math.max(0.1, Math.min(1, v + drift));
  });
  drawRadar();
}
let trafficHistory = Array(60).fill(0);
function drawTraffic() {
  const canvas = document.getElementById('trafficCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 280, H = 200;
  canvas.width = W;
  ctx.clearRect(0, 0, W, H);
  const marginLeft = 45;
  const marginBottom = 25;
  const marginTop = 15;
  const marginRight = 15;
  const gw = W - marginLeft - marginRight;
  const gh = H - marginTop - marginBottom;
  const sw = gw / Math.max(trafficHistory.length - 1, 1);
  const max = Math.max(...trafficHistory, 1);
  ctx.beginPath();
  trafficHistory.forEach((v, i) => {
    const x = marginLeft + i * sw;
    const y = marginTop + gh - (v / max) * gh;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.lineTo(marginLeft + gw, marginTop + gh);
  ctx.lineTo(marginLeft, marginTop + gh);
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, marginTop, 0, marginTop + gh);
  grad.addColorStop(0, 'rgba(126,200,200,0.25)');
  grad.addColorStop(1, 'rgba(126,200,200,0)');
  ctx.fillStyle = grad;
  ctx.fill();
  ctx.beginPath();
  trafficHistory.forEach((v, i) => {
    const x = marginLeft + i * sw;
    const y = marginTop + gh - (v / max) * gh;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = 'rgba(126,200,200,0.6)';
  ctx.lineWidth = 1.5;
  ctx.stroke();
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(marginLeft, marginTop);
  ctx.lineTo(marginLeft, marginTop + gh);
  ctx.lineTo(marginLeft + gw, marginTop + gh);
  ctx.strokeStyle = 'rgba(113,139,168,0.4)';
  ctx.stroke();
  ctx.fillStyle = 'rgba(113,139,168,0.8)';
  ctx.font = '10px Inter, sans-serif';
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  for (let i = 0; i <= 2; i++) {
    const tickVal = Math.round(max * (i / 2));
    const yPos = marginTop + gh - (i / 2) * gh;
    ctx.fillText(tickVal, marginLeft - 6, yPos);
    ctx.beginPath();
    ctx.moveTo(marginLeft - 4, yPos);
    ctx.lineTo(marginLeft, yPos);
    ctx.strokeStyle = 'rgba(113,139,168,0.4)';
    ctx.stroke();
  }
  ctx.save();
  ctx.translate(12, marginTop + gh / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('Traffic Volume', 0, 0);
  ctx.restore();
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  ctx.fillText('Time (Last 60s)', marginLeft + gw / 2, marginTop + gh + 10);
}
function updateTraffic() {
  const base = STATE.attackInProgress ? rand(400, 900) : rand(80, 200);
  trafficHistory.push(base);
  trafficHistory.shift();
  drawTraffic();
}
let protocolCounts = { TCP: 45, UDP: 18, HTTP: 12, HTTPS: 32, DNS: 8, ICMP: 5, SMTP: 3 };
function drawProtocol() {
  const canvas = document.getElementById('protocolCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 300, H = 200;
  canvas.width = W;
  ctx.clearRect(0, 0, W, H);
  const COLORS = ['#7ec8c8', '#c08dbb', '#82b99a', '#c9a862', '#d4985e', '#c27a6e', '#a08bc8'];
  const total = Object.values(protocolCounts).reduce((a, b) => a + b, 0);
  const keys = Object.keys(protocolCounts);
  const cx = 90, cy = H / 2, r = 70;
  let startAngle = -Math.PI / 2;
  keys.forEach((k, i) => {
    const slice = (protocolCounts[k] / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, startAngle, startAngle + slice);
    ctx.closePath();
    ctx.fillStyle = COLORS[i % COLORS.length];
    ctx.fill();
    ctx.strokeStyle = '#121a28';
    ctx.lineWidth = 2;
    ctx.stroke();
    startAngle += slice;
  });
  keys.forEach((k, i) => {
    const lx = 180, ly = 20 + i * 24;
    ctx.fillStyle = COLORS[i % COLORS.length];
    ctx.fillRect(lx, ly, 10, 10);
    ctx.fillStyle = 'rgba(126,149,173,0.9)';
    ctx.font = '11px Inter, sans-serif';
    ctx.textBaseline = 'top';
    ctx.fillText(`${k} (${Math.round(protocolCounts[k] / total * 100)}%)`, lx + 16, ly);
  });
}
let baselineData = Array(80).fill(0).map((_, i) => 100 + 20 * Math.sin(i * 0.3) + rand(-5, 5));
let observedData = [...baselineData].map(v => v + rand(-3, 3));
let anomalyPoints = [];
function drawAnomalyChart() {
  const canvas = document.getElementById('anomalyCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 900, H = 220;
  canvas.width = W;
  ctx.clearRect(0, 0, W, H);
  const n = baselineData.length;
  const sw = W / (n - 1);
  const maxV = Math.max(...baselineData, ...observedData, 1);
  const minV = Math.min(...baselineData, ...observedData, 0);
  const range = maxV - minV + 10;
  const toY = v => H - 16 - ((v - minV) / range) * (H - 32);
  ctx.beginPath();
  baselineData.forEach((v, i) => {
    const x = i * sw, y = toY(v + 20);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  for (let i = n - 1; i >= 0; i--) {
    ctx.lineTo(i * sw, toY(baselineData[i] - 20));
  }
  ctx.closePath();
  ctx.fillStyle = 'rgba(126,200,200,0.04)';
  ctx.fill();
  ctx.beginPath();
  baselineData.forEach((v, i) => {
    const x = i * sw, y = toY(v);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = 'rgba(126,200,200,0.25)';
  ctx.setLineDash([6, 3]);
  ctx.stroke();
  ctx.setLineDash([]);
  ctx.beginPath();
  observedData.forEach((v, i) => {
    const x = i * sw, y = toY(v);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = 'rgba(130,185,154,0.65)';
  ctx.lineWidth = 1.5;
  ctx.stroke();
  ctx.lineWidth = 1;
  anomalyPoints.forEach(({ idx, val }) => {
    if (idx >= n) return;
    const x = idx * sw, y = toY(val);
    ctx.beginPath();
    ctx.arc(x, y, 5, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(194,122,110,0.7)';
    ctx.fill();
    ctx.strokeStyle = '#c27a6e';
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.lineWidth = 1;
  });
  ctx.fillStyle = 'rgba(126,200,200,0.4)'; ctx.fillRect(10, 5, 16, 3);
  ctx.fillStyle = 'rgba(113,139,168,0.8)'; ctx.font = '11px Inter'; ctx.textBaseline = 'top';
  ctx.fillText('Baseline', 32, 1);
  ctx.fillStyle = 'rgba(130,185,154,0.6)'; ctx.fillRect(100, 5, 16, 3);
  ctx.fillText('Observed', 122, 1);
  ctx.beginPath(); ctx.arc(202, 6, 5, 0, Math.PI * 2);
  ctx.fillStyle = '#c27a6e'; ctx.fill();
  ctx.fillStyle = 'rgba(113,139,168,0.8)';
  ctx.fillText('Anomaly', 212, 1);
}
const riskBuckets = { Low: 0, Medium: 0, High: 0, Critical: 0 };
function drawRiskDist() {
  const canvas = document.getElementById('riskDistCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 280, H = 200;
  canvas.width = W;
  ctx.clearRect(0, 0, W, H);
  const COLORS = { Low: '#82b99a', Medium: '#c9a862', High: '#d4985e', Critical: '#c27a6e' };
  const keys = Object.keys(riskBuckets);
  const maxV = Math.max(...Object.values(riskBuckets), 1);
  const bw = (W - 40) / keys.length;
  keys.forEach((k, i) => {
    const v = riskBuckets[k];
    const bh = ((v / maxV) * (H - 50)) || 4;
    const x = 20 + i * bw + 6;
    const y = H - 30 - bh;
    const grad = ctx.createLinearGradient(x, y, x, H - 30);
    grad.addColorStop(0, COLORS[k]);
    grad.addColorStop(1, COLORS[k] + '44');
    ctx.fillStyle = grad;
    ctx.fillRect(x, y, bw - 12, bh);
    ctx.fillStyle = 'rgba(113,139,168,0.7)';
    ctx.font = '10px Inter';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText(k, x + (bw - 12) / 2, H - 22);
    ctx.fillStyle = COLORS[k];
    ctx.fillText(v, x + (bw - 12) / 2, y - 14);
  });
}
let trainingLoss = [];
let trainingAcc = [];
const MAX_TRAIN_PTS = 80;
function drawTrainingChart() {
  const canvas = document.getElementById('trainingCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 700, H = 180;
  canvas.width = W;
  ctx.clearRect(0, 0, W, H);
  const n = trainingLoss.length;
  if (n < 2) return;
  const sw = W / (n - 1);
  ctx.beginPath();
  trainingLoss.forEach((v, i) => {
    const x = i * sw, y = H - (v / 1.2) * (H - 20) - 10;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = 'rgba(194,122,110,0.5)';
  ctx.lineWidth = 1.5;
  ctx.stroke();
  ctx.beginPath();
  trainingAcc.forEach((v, i) => {
    const x = i * sw, y = H - v * (H - 20) - 10;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = 'rgba(130,185,154,0.6)';
  ctx.stroke();
  ctx.lineWidth = 1;
  ctx.fillStyle = '#c27a6e'; ctx.fillRect(10, 6, 14, 3);
  ctx.fillStyle = 'rgba(113,139,168,0.8)'; ctx.font = '11px Inter'; ctx.textBaseline = 'top';
  ctx.fillText('Loss', 30, 2);
  ctx.fillStyle = '#82b99a'; ctx.fillRect(80, 6, 14, 3);
  ctx.fillStyle = 'rgba(113,139,168,0.8)';
  ctx.fillText('Accuracy', 100, 2);
}
function updateMLTraining() {
  STATE.epochs++;
  const t = STATE.epochs / 200;
  STATE.loss = Math.max(0.01, 1 - 0.97 * (1 - Math.exp(-5 * t)) + rand(-0.005, 0.005));
  const acc = Math.min(1, 0.97 * (1 - Math.exp(-5 * t)) + rand(-0.005, 0.005));
  const f1 = Math.min(1, acc * 0.99);
  trainingLoss.push(STATE.loss);
  trainingAcc.push(acc);
  if (trainingLoss.length > MAX_TRAIN_PTS) { trainingLoss.shift(); trainingAcc.shift(); }
  const ae = document.getElementById('ml-epochs');
  const al = document.getElementById('ml-loss');
  const av = document.getElementById('ml-vacc');
  const af = document.getElementById('ml-f1');
  if (ae) ae.textContent = STATE.epochs;
  if (al) al.textContent = STATE.loss.toFixed(4);
  if (av) av.textContent = (acc * 100).toFixed(1) + '%';
  if (af) af.textContent = f1.toFixed(3);
  STATE.accuracy = 97 + acc * 0.4;
  drawTrainingChart();
}
function drawConfusion() {
  const canvas = document.getElementById('confusionCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 600, H = 200;
  canvas.width = W;
  ctx.clearRect(0, 0, W, H);
  const labels = ['Normal', 'BruteForce', 'DDoS', 'Malware', 'SQLi', 'Phish'];
  const n = labels.length;
  const size = Math.min(W, H - 20) / (n + 1);
  const offX = 70, offY = 24;
  labels.forEach((l, i) => {
    ctx.fillStyle = 'rgba(122,155,191,0.6)';
    ctx.font = '9.5px Inter';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.fillText(l, offX - 4, offY + (i + 0.5) * size);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'bottom';
    ctx.fillText(l, offX + (i + 0.5) * size, offY - 2);
  });
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      const val = r === c ? rand(0.85, 0.98) : rand(0, 0.08);
      const x = offX + c * size, y = offY + r * size;
      ctx.fillStyle = r === c
        ? `rgba(130,185,154,${val * 0.85})`
        : `rgba(194,122,110,${val * 3.5})`;
      ctx.fillRect(x + 1, y + 1, size - 2, size - 2);
      ctx.fillStyle = val > 0.3 ? '#121a28' : 'rgba(113,139,168,0.8)';
      ctx.font = '10px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText((val * 100).toFixed(0) + '%', x + size / 2, y + size / 2);
    }
  }
}
function drawProcessChain() {
  const canvas = document.getElementById('processCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 280, H = 260;
  canvas.width = W;
  ctx.clearRect(0, 0, W, H);
  const nodes = [
    { x: 0.5, y: 0.08, label: 'svchost.exe', color: '#7b2fff' },
    { x: 0.3, y: 0.3, label: 'cmd.exe', color: '#00d4ff' },
    { x: 0.7, y: 0.3, label: 'powershell', color: '#00d4ff' },
    { x: 0.2, y: 0.55, label: 'net.exe', color: '#ffd700' },
    { x: 0.5, y: 0.55, label: 'mshta.exe', color: '#ff8c00' },
    { x: 0.7, y: 0.55, label: 'wscript', color: '#ff3366' },
    { x: 0.4, y: 0.8, label: '⚡ Payload', color: '#ff3366' },
  ];
  const edges = [[0, 1], [0, 2], [1, 3], [1, 4], [2, 5], [4, 6], [5, 6]];
  edges.forEach(([a, b]) => {
    const na = nodes[a], nb = nodes[b];
    ctx.beginPath();
    ctx.moveTo(na.x * W, na.y * H);
    ctx.lineTo(nb.x * W, nb.y * H);
    ctx.strokeStyle = 'rgba(0,212,255,0.2)';
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.lineWidth = 1;
  });
  nodes.forEach(({ x, y, label, color }) => {
    ctx.beginPath();
    ctx.arc(x * W, y * H, 12, 0, Math.PI * 2);
    ctx.fillStyle = color + '33';
    ctx.fill();
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.lineWidth = 1;
    ctx.fillStyle = 'rgba(232,244,255,0.85)';
    ctx.font = '9px Inter';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText(label, x * W, y * H + 14);
  });
}
function addThreatFeedItem() {
  const threat = pick(THREAT_TYPES);
  const div = document.createElement('div');
  div.className = `threat-item ${threat.sev}`;
  div.innerHTML = `
    <span class="ti-sev ${threat.sev}">${threat.sev.toUpperCase()}</span>
    <span class="ti-msg">${threat.name} from ${randomIP()}</span>
    <span class="ti-time">${now()}</span>`;
  _injectThreatFeedItem(div);
}
function addThreatFeedItemFromData(data) {
  if (!data) return;
  const sev = data.severity || 'medium';
  const div = document.createElement('div');
  div.className = `threat-item ${sev}`;
  div.innerHTML = `
    <span class="ti-sev ${sev}">${sev.toUpperCase()}</span>
    <span class="ti-msg">${data.name || 'Unknown Threat'} from ${data.source || randomIP()}</span>
    <span class="ti-time">${now()}</span>`;
  _injectThreatFeedItem(div);
}
function _injectThreatFeedItem(div) {
  const feed = document.getElementById('threat-feed');
  if (!feed) return;
  feed.insertBefore(div, feed.firstChild);
  while (feed.children.length > 12) feed.lastChild.remove();
}
const STREAM_TYPES = [
  { t: 'ALLOW', c: 'allow', msgs: ['TCP connection accepted', 'HTTPS handshake OK', 'DNS query resolved', 'Auth token validated'] },
  { t: 'DENY', c: 'deny', msgs: ['Blacklisted IP blocked', 'SYN flood dropped', 'Bot signature matched', 'Rule 4412 triggered'] },
  { t: 'WARN', c: 'warn', msgs: ['Rate limit threshold', 'Unusual port access', 'GeoIP mismatch', 'Certificate expiring'] },
  { t: 'INFO', c: 'info', msgs: ['Policy updated', 'Scan completed', 'Model checkpoint saved', 'Ruleset refreshed'] },
];
function addStreamEvent() {
  if (STATE.streamPaused) return;
  const el = document.getElementById('event-stream');
  if (!el) return;
  const type = pick(STREAM_TYPES);
  const msg = pick(type.msgs);
  const line = document.createElement('div');
  line.className = 'stream-line';
  line.innerHTML = `
    <span class="sl-time">${now()}</span>
    <span class="sl-type ${type.c}">[${type.t}]</span>
    <span class="sl-msg">${msg} — ${randomIP()}:${randInt(1024, 65535)}</span>`;
  el.insertBefore(line, el.firstChild);
  while (el.children.length > 60) el.lastChild.remove();
}
function toggleStream() {
  STATE.streamPaused = !STATE.streamPaused;
  const btn = document.getElementById('stream-toggle');
  if (btn) btn.textContent = STATE.streamPaused ? 'Resume' : 'Pause';
}
function clearStream() {
  const el = document.getElementById('event-stream');
  if (el) el.innerHTML = '';
}
const attackerIPs = {};
function updateIPTable() {
  const ip = randomIP();
  attackerIPs[ip] = (attackerIPs[ip] || 0) + randInt(1, 10);
  const el = document.getElementById('ip-table');
  if (!el) return;
  el.innerHTML = '';
  const sorted = Object.entries(attackerIPs)
    .sort((a, b) => b[1] - a[1]).slice(0, 8);
  sorted.forEach(([ip, cnt]) => {
    const row = document.createElement('div');
    row.className = 'ip-row';
    row.innerHTML = `<span class="ip-addr">${ip}</span>
      <span class="ip-country">${pick(GEO_ORIGINS)}</span>
      <span class="ip-count">${cnt} hits</span>`;
    el.appendChild(row);
  });
}
let anomalyCount = 0;
function addAnomalyLog() {
  const types = ['BruteForce', 'DataExfil', 'LateralMove', 'DDoSPattern', 'ZeroDay'];
  const scores = [rand(0.6, 0.99)];
  const score = rand(0.55, 0.98);
  const type = pick(types);
  const el = document.getElementById('anomaly-log');
  if (!el) return;
  const row = document.createElement('div');
  row.className = 'alog-row';
  row.innerHTML = `
    <span class="alog-time">${now()}</span>
    <span class="alog-score">[${(score * 100).toFixed(1)}%]</span>
    <span class="alog-type">${type}</span>
    <span class="alog-src">${randomIP()}</span>
    <span class="alog-desc">Z-score: ${rand(2, 5).toFixed(2)} σ — Model: LSTM-v3</span>`;
  el.insertBefore(row, el.firstChild);
  while (el.children.length > 20) el.lastChild.remove();
  STATE.anomalies++;
  anomalyCount++;
  const idx = randInt(10, baselineData.length - 1);
  const spike = baselineData[idx] + rand(40, 80);
  observedData[idx] = spike;
  anomalyPoints.push({ idx, val: spike });
  if (anomalyPoints.length > 8) anomalyPoints.shift();
  drawAnomalyChart();
  if (type === 'BruteForce') { STATE.attacks.bf++; }
  else if (type === 'DataExfil') { STATE.attacks.de++; }
  else if (type === 'LateralMove') { STATE.attacks.lm++; }
  else if (type === 'DDoSPattern') { STATE.attacks.dd++; }
  else { STATE.attacks.zd++; }
  updateAnomalyCategories();
  riskBuckets[score > 0.85 ? 'Critical' : score > 0.7 ? 'High' : score > 0.5 ? 'Medium' : 'Low']++;
  drawRiskDist();
}
function updateAnomalyCategories() {
  const total = Math.max(1, STATE.attacks.bf + STATE.attacks.de + STATE.attacks.lm + STATE.attacks.dd + STATE.attacks.zd);
  const upd = (id, fillId, val) => {
    const e = document.getElementById(id);
    if (e) e.textContent = val;
    const f = document.querySelector(`.acat-fill.${fillId}`);
    if (f) f.style.width = Math.min(100, (val / total) * 500) + '%';
  };
  upd('ac-bf', 'bf', STATE.attacks.bf);
  upd('ac-de', 'de', STATE.attacks.de);
  upd('ac-lm', 'lm', STATE.attacks.lm);
  upd('ac-dd', 'dd', STATE.attacks.dd);
  upd('ac-zd', 'zd', STATE.attacks.zd);
}
const EVENT_TYPES = [
  { t: 'BLOCK', c: 'block', msgs: ['Malicious IP blocked', 'Intrusion attempt denied', 'Ransomware quarantined', 'C2 channel severed'] },
  { t: 'ALLOW', c: 'allow', msgs: ['Trusted connection allowed', 'Policy allowlist matched', 'Auth success'] },
  { t: 'POLICY', c: 'policy', msgs: ['Firewall rule updated', 'Defense posture changed', 'Threshold adjusted'] },
  { t: 'SYSTEM', c: 'system', msgs: ['ML model retrained', 'Snapshot checkpoint', 'Merkle tree anchored', 'SIEM synchronized'] },
];
function addAuditLog() {
  const el = document.getElementById('audit-log');
  if (!el) return;
  const type = pick(EVENT_TYPES);
  const msg = pick(type.msgs);
  const hash = shortHash();
  const row = document.createElement('div');
  row.className = `audit-row event-${type.c}`;
  row.innerHTML = `
    <span class="ar-seq">#${String(STATE.auditSeq++).padStart(6, '0')}</span>
    <span class="ar-time">${now()}</span>
    <span class="ar-type ${type.c}">${type.t}</span>
    <span class="ar-msg">${msg}</span>
    <span class="ar-hash">0x${hash}</span>`;
  el.insertBefore(row, el.firstChild);
  while (el.children.length > 30) el.lastChild.remove();
  STATE.chainLength++;
  const lh = document.getElementById('latest-hash');
  const cl = document.getElementById('chain-length');
  const mr = document.getElementById('merkle-root');
  if (lh) lh.textContent = '0x' + fullHash();
  if (cl) cl.textContent = STATE.chainLength;
  if (mr) mr.textContent = '0x' + fullHash();
}
function addResponseTimeline(title, type) {
  const el = document.getElementById('response-timeline');
  if (!el) return;
  const item = document.createElement('div');
  item.className = 'tl-item';
  item.innerHTML = `<div class="tl-dot ${type}"></div>
    <div class="tl-content">
      <div class="tl-title">${title}</div>
      <div class="tl-time">${now()}</div>
    </div>`;
  el.insertBefore(item, el.firstChild);
  while (el.children.length > 15) el.lastChild.remove();
}
const DM_ACTIONS = ['IP Blacklist', 'IDS Rule Push', 'Segment Isolate', 'Rate Limit', 'Honeypot Redirect', 'Auto-Patch', 'MFA Enforce'];
let dmRows = 0;
function addDecisionMatrixRow(threat) {
  const tbody = document.getElementById('dm-tbody');
  if (!tbody || dmRows > 14) return;
  const t = threat || pick(THREAT_TYPES);
  const conf = rand(0.78, 0.99);
  const ms = randInt(80, 400);
  const action = t.action;
  const row = document.createElement('tr');
  row.innerHTML = `
    <td>${t.name}</td>
    <td><span class="dm-sev ${t.sev}">${t.sev.toUpperCase()}</span></td>
    <td>${(conf * 100).toFixed(1)}%</td>
    <td class="dm-action">${action}</td>
    <td>${ms}ms</td>
    <td><span class="dm-status-badge ${t.sev === 'low' ? 'monitored' : 'mitigated'}">${t.sev === 'low' ? 'MONITORED' : 'MITIGATED'}</span></td>`;
  tbody.insertBefore(row, tbody.firstChild);
  if (tbody.rows.length > 10) tbody.deleteRow(tbody.rows.length - 1);
  dmRows++;
}
const MITRE_TACTICS = ['Recon', 'Resource\nDev', 'Initial\nAccess', 'Execution', 'Persistence', 'Priv Esc', 'Defense\nEvasion', 'Cred\nAccess', 'Discovery', 'Lateral\nMove', 'Collection', 'Exfiltration'];
const MITRE_TECHS = ['T1595', 'T1583', 'T1133', 'T1059', 'T1547', 'T1068', 'T1027', 'T1003', 'T1082', 'T1021', 'T1056', 'T1048'];
function buildMitreGrid() {
  const el = document.getElementById('mitre-grid');
  if (!el) return;
  MITRE_TACTICS.forEach(t => {
    const cell = document.createElement('div');
    cell.className = 'mitre-cell header';
    cell.textContent = t;
    el.appendChild(cell);
  });
  for (let row = 0; row < 5; row++) {
    MITRE_TECHS.forEach((tech, i) => {
      const cell = document.createElement('div');
      const r = Math.random();
      cell.className = `mitre-cell ${r > 0.7 ? 'covered' : r > 0.45 ? 'partial' : 'uncovered'}`;
      cell.textContent = tech.replace('T', 'T' + (row * 100 + '').slice(-2));
      cell.title = cell.textContent;
      el.appendChild(cell);
    });
  }
}
const PREDICTIONS = [
  { name: 'Brute Force Login', prob: 0.72 },
  { name: 'Ransomware Deploy', prob: 0.45 },
  { name: 'Data Exfiltration', prob: 0.38 },
  { name: 'DDoS Campaign', prob: 0.61 },
  { name: 'APT Intrusion', prob: 0.29 },
];
function buildPredictions() {
  const el = document.getElementById('predictions-list');
  if (!el) return;
  el.innerHTML = '';
  PREDICTIONS.forEach((p, i) => {
    const colors = ['#ff3366', '#7b2fff', '#ff8c00', '#ffd700', '#00d4ff'];
    const item = document.createElement('div');
    item.className = 'pred-item';
    item.innerHTML = `
      <span class="pred-name">${p.name}</span>
      <div class="pred-bar"><div class="pred-fill" style="width:0%; background:${colors[i]}"></div></div>
      <span class="pred-prob">${(p.prob * 100).toFixed(0)}%</span>`;
    el.appendChild(item);
    setTimeout(() => {
      item.querySelector('.pred-fill').style.width = (p.prob * 100) + '%';
    }, 200 + i * 100);
  });
}
const KILL_CHAIN_IDS = ['kc-recon', 'kc-weapon', 'kc-delivery', 'kc-exploit', 'kc-install', 'kc-c2', 'kc-action'];
function triggerSimulatedAttack() {
  if (STATE.attackInProgress) return;
  STATE.attackInProgress = true;
  setThreatLevel('CRITICAL');
  const threat = THREAT_TYPES.find(t => t.sev === 'critical') || THREAT_TYPES[2];
  showAlert(`⚠ ATTACK DETECTED — ${threat.name}`,
    `Source: ${randomIP()} → Autonomous response initiated: ${threat.action}`);
  let step = 0;
  KILL_CHAIN_IDS.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.classList.remove('detected');
      el.querySelector('.kc-status').className = 'kc-status idle';
      el.querySelector('.kc-status').textContent = 'MONITOR';
    }
  });
  const kcInterval = setInterval(() => {
    if (step >= KILL_CHAIN_IDS.length) {
      clearInterval(kcInterval);
      setTimeout(() => {
        KILL_CHAIN_IDS.forEach(id => {
          const el = document.getElementById(id);
          if (el) {
            el.classList.remove('detected');
            const st = el.querySelector('.kc-status');
            st.className = 'kc-status blocked';
            st.textContent = 'BLOCKED';
          }
        });
        STATE.neutralized++;
        STATE.blockedCount++;
        STATE.attackInProgress = false;
        setThreatLevel('MODERATE');
        addResponseTimeline('Attack Fully Neutralized — ' + threat.name, 'success');
        document.getElementById('sidebar-mode').textContent = 'PROTECT';
      }, 2000);
      return;
    }
    const id = KILL_CHAIN_IDS[step];
    const el = document.getElementById(id);
    if (el) {
      el.classList.add('detected');
      const st = el.querySelector('.kc-status');
      st.className = 'kc-status active';
      st.textContent = 'DETECTED';
    }
    addThreatFeedItem();
    addResponseTimeline(`Detecting: ${id.replace('kc-', '')} phase — ${randomIP()}`, 'danger');
    addDecisionMatrixRow(threat);
    addAuditLog();
    STATE.blockedCount++;
    document.getElementById('sidebar-mode').textContent = 'COMBAT';
    step++;
  }, 900);
}
function activatePlaybook(name) {
  const key = name.toLowerCase();
  const pb = document.getElementById(`pb-${key}`);
  if (pb) {
    const st = pb.querySelector('.pb-status');
    if (st) { st.className = 'pb-status running'; st.textContent = 'RUNNING'; }
    pb.classList.add('active');
    setTimeout(() => {
      if (st) { st.className = 'pb-status active'; st.textContent = 'DEPLOYED'; }
    }, 1500);
  }
  addResponseTimeline(`Playbook '${name}' activated`, 'info');
  STATE.neutralized++;
}
function showAlert(msg, detail) {
  document.getElementById('alert-msg').textContent = msg;
  document.getElementById('alert-detail').textContent = detail;
  document.getElementById('alert-overlay').style.display = 'flex';
}
function closeAlert() {
  document.getElementById('alert-overlay').style.display = 'none';
}
function exportLogs() {
  if (typeof AEGIS_API !== 'undefined') {
    const url = AEGIS_API.forensics.exportUrl();
    const a = document.createElement('a');
    a.href = url;
    a.download = `AEGIS_forensic_${Date.now()}.log`;
    a.click();
    return;
  }
  const rows = document.querySelectorAll('.audit-row');
  let text = 'AEGIS FORENSIC AUDIT LOG — TAMPER-RESISTANT EXPORT\n';
  text += '='.repeat(60) + '\n';
  rows.forEach(r => { text += r.textContent.trim().replace(/\s+/g, ' ') + '\n'; });
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `AEGIS_forensic_${Date.now()}.log`;
  a.click();
  URL.revokeObjectURL(url);
}
let reportGenerating = false;
function generateMLReport() {
  if (reportGenerating) return;
  reportGenerating = true;
  const btn = document.getElementById('btn-generate-report');
  const card = document.getElementById('report-card');
  const badge = document.getElementById('report-badge');
  const status = document.getElementById('report-status-text');
  const bar = document.getElementById('report-bar');
  const output = document.getElementById('report-output');
  if (btn) btn.disabled = true;
  if (card) card.style.display = 'block';
  if (badge) { badge.textContent = 'GENERATING'; badge.className = 'card-badge running'; }
  if (status) status.textContent = 'Contacting ML Engine...';
  if (bar) bar.style.width = '5%';
  if (output) output.textContent = '';
  if (typeof AEGIS_API !== 'undefined') {
    AEGIS_API.ml.generateReport().then(r => {
      if (r.ok && r.data.report) {
        const report = r.data.report;
        const text = report.markdown || JSON.stringify(report, null, 2);
        if (bar) bar.style.width = '70%';
        if (status) status.textContent = 'Formatting report from backend...';
        const lines = text.split('\n');
        let lineIdx = 0;
        const typeInterval = setInterval(() => {
          if (lineIdx < lines.length) {
            if (output) { output.textContent += lines[lineIdx] + '\n'; output.scrollTop = output.scrollHeight; }
            lineIdx++;
          } else {
            clearInterval(typeInterval);
            if (bar) bar.style.width = '100%';
            if (status) status.textContent = 'Complete! Preparing download...';
            if (badge) { badge.textContent = 'COMPLETE'; badge.className = 'card-badge live'; }
            const blob = new Blob([text], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = `AEGIS_ML_Report_${Date.now()}.md`; a.click();
            URL.revokeObjectURL(url);
            setTimeout(() => { if (btn) btn.disabled = false; reportGenerating = false; }, 2000);
          }
        }, 80);
        return;
      }
      generateMLReportFallback(btn, card, badge, status, bar, output);
    }).catch(() => generateMLReportFallback(btn, card, badge, status, bar, output));
    return;
  }
  generateMLReportFallback(btn, card, badge, status, bar, output);
}
function generateMLReportFallback(btn, card, badge, status, bar, output) {
  const epochs = document.getElementById('ml-epochs')?.textContent || '0';
  const loss = document.getElementById('ml-loss')?.textContent || '0.000';
  const vacc = document.getElementById('ml-vacc')?.textContent || '0.0%';
  const f1 = document.getElementById('ml-f1')?.textContent || '0.000';
  let text = `# AEGIS Machine Learning Engine - Auto-Training Report\n\n`;
  text += `Generated: ${new Date().toISOString()}\n\n`;
  text += `## Model Performance\n`;
  text += `- **Epochs Completed:** ${epochs}\n`;
  text += `- **Current Loss:** ${loss}\n`;
  text += `- **Validation Accuracy:** ${vacc}\n`;
  text += `- **F1 Score:** ${f1}\n\n`;
  text += `## Sub-Network Status\n`;
  text += `- Learning & Audit Agent: ONLINE\n`;
  text += `- Threat Model Status: EVOLVING\n`;
  text += `- Latest Checkpoint: SAVED\n\n`;
  text += `*Report automatically generated by AEGIS Head Agent.*\n`;
  const lines = text.split('\n');
  let lineIdx = 0;
  setTimeout(() => {
    if (status) status.textContent = 'Extracting model metadata and metrics...';
    if (bar) bar.style.width = '30%';
    const typeInterval = setInterval(() => {
      if (lineIdx < lines.length) {
        if (output) {
          output.textContent += lines[lineIdx] + '\n';
          output.scrollTop = output.scrollHeight;
        }
        lineIdx++;
      } else {
        clearInterval(typeInterval);
      }
    }, 100);
  }, 1000);
  setTimeout(() => {
    if (status) status.textContent = 'Formatting markdown structure...';
    if (bar) bar.style.width = '70%';
  }, 2500);
  setTimeout(() => {
    if (status) status.textContent = 'Complete! Preparing download...';
    if (bar) bar.style.width = '100%';
    if (badge) {
      badge.textContent = 'COMPLETE';
      badge.className = 'card-badge live';
    }
    const blob = new Blob([text], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AEGIS_ML_Report_${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
    setTimeout(() => {
      if (btn) btn.disabled = false;
      reportGenerating = false;
    }, 2000);
  }, 4000);
}
function updateInferenceLog() {
  const log = document.getElementById('inference-log');
  if (!log) return;
  const isMalicious = Math.random() < 0.1;
  const isSusp = Math.random() < 0.25;
  const type = isMalicious ? 'malicious' : (isSusp ? 'suspicious' : 'benign');
  const statusText = isMalicious ? 'BLOCK' : (isSusp ? 'FLAG' : 'PASS');
  const conf = (Math.random() * 9 + 90).toFixed(1);
  const ips = ['192.168.1.14', '10.0.0.8', '172.16.0.4', '198.51.100.2', '10.5.21.3', '45.33.12.98'];
  const ip = ips[Math.floor(Math.random() * ips.length)];
  const time = new Date().toISOString().split('T')[1].substring(0, 12);
  const div = document.createElement('div');
  div.className = `inf-row ${type}`;
  div.innerHTML = `<span>[${time}] ${ip}</span><span>Conf: ${conf}%</span><span>${statusText}</span>`;
  log.prepend(div);
  if (log.children.length > 30) log.lastChild.remove();
}
let tick = 0;
function simulationLoop() {
  tick++;
  STATE.eventsPerSec = randInt(120, STATE.attackInProgress ? 850 : 350);
  updateHeatmap();
  updateRadar();
  updateTraffic();
  if (tick % 2 === 0) addThreatFeedItem();
  addStreamEvent();
  if (tick % 2 === 0) updateInferenceLog();
  if (tick % 3 === 0) addAnomalyLog();
  if (tick % 2 === 1) addAuditLog();
  if (tick % 4 === 0) updateIPTable();
  if (tick % 5 === 0) addDecisionMatrixRow();
  if (tick % 6 === 0) {
    const msgs = ['Baseline update applied', 'Signature DB refreshed', 'Model inference complete', 'Policy sync OK'];
    addResponseTimeline(pick(msgs), 'info');
  }
  updateMLTraining();
  if (tick % 10 === 0) drawConfusion();
  updateKPIs();
}
function resizeCanvases() {
  drawRadar();
  drawTraffic();
  drawAnomalyChart();
  drawRiskDist();
  drawTrainingChart();
  drawConfusion();
  drawProcessChain();
  drawProtocol();
}
document.addEventListener('DOMContentLoaded', () => {
  buildMitreGrid();
  buildPredictions();
  drawProcessChain();
  drawConfusion();
  drawRiskDist();
  drawAnomalyChart();
  drawProtocol();
  setThreatLevel('MODERATE');
  for (let i = 0; i < 5; i++) {
    addThreatFeedItem();
    addStreamEvent();
    addAuditLog();
    updateIPTable();
  }
  addDecisionMatrixRow();
  addResponseTimeline('System Online — All Defense Layers Active', 'success');
  addResponseTimeline('ML Threat Model v3.1 Loaded', 'info');
  addResponseTimeline('Initial Baseline Scan Complete', 'info');
  setInterval(simulationLoop, 600);
  setInterval(() => { drawRadar(); }, 800);
  setInterval(() => { updateHeatmap(); }, 700);
  setInterval(() => { drawTraffic(); }, 700);
  window.addEventListener('resize', resizeCanvases);
  initAgentNetwork();
});
const AGENT_STATE = {
  head: { directives: 0, escalations: 0 },
  mon: { events: 0, alerts: 0 },
  tia: { iocs: 0, cves: 0, riskAvg: 0, riskSum: 0, riskCount: 0 },
  rca: { actions: 0, rollbacks: 0, times: [] },
  lea: { updates: 0, audits: 0, kb: 0 },
};
const AGENT_NODES = {
  head: { x: 0.50, y: 0.20, label: 'HEAD', color: '#7ec8c8', glow: 'rgba(126,200,200,0.2)' },
  mon: { x: 0.15, y: 0.75, label: 'MON', color: '#7ec8c8', glow: 'rgba(126,200,200,0.15)' },
  tia: { x: 0.38, y: 0.75, label: 'TIA', color: '#c9a862', glow: 'rgba(201,168,98,0.15)' },
  rca: { x: 0.62, y: 0.75, label: 'RCA', color: '#c27a6e', glow: 'rgba(194,122,110,0.15)' },
  lea: { x: 0.85, y: 0.75, label: 'LEA', color: '#82b99a', glow: 'rgba(130,185,154,0.15)' },
};
const AGENT_KEYS = ['head', 'mon', 'tia', 'rca', 'lea'];
const AGENT_EDGES = [
  ['head', 'mon'], ['head', 'tia'], ['head', 'rca'], ['head', 'lea'],
  ['mon', 'tia'], ['tia', 'rca'], ['rca', 'lea'],
];
let agentParticles = [];
function spawnParticle(from, to, color) {
  agentParticles.push({ from, to, t: 0, color: color || '#7ec8c8' });
}
let agentCanvasTick = 0;
function drawAgentCanvas() {
  const canvas = document.getElementById('agentCanvas');
  if (!canvas) return;
  const W = canvas.offsetWidth || canvas.clientWidth || 900;
  const H = 280;
  canvas.width = W;
  canvas.height = H;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, W, H);
  ctx.strokeStyle = 'rgba(0,212,255,0.04)';
  ctx.lineWidth = 1;
  for (let x = 0; x < W; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
  for (let y = 0; y < H; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
  AGENT_EDGES.forEach(([a, b]) => {
    const na = AGENT_NODES[a], nb = AGENT_NODES[b];
    const x1 = na.x * W, y1 = na.y * H, x2 = nb.x * W, y2 = nb.y * H;
    const grad = ctx.createLinearGradient(x1, y1, x2, y2);
    grad.addColorStop(0, na.color + '44');
    grad.addColorStop(1, nb.color + '44');
    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.strokeStyle = grad;
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.lineWidth = 1;
  });
  agentParticles = agentParticles.filter(p => p.t <= 1);
  agentParticles.forEach(p => {
    const na = AGENT_NODES[p.from], nb = AGENT_NODES[p.to];
    const px = na.x * W + (nb.x * W - na.x * W) * p.t;
    const py = na.y * H + (nb.y * H - na.y * H) * p.t;
    ctx.beginPath();
    ctx.arc(px, py, 4, 0, Math.PI * 2);
    ctx.fillStyle = p.color;
    ctx.shadowBlur = 12;
    ctx.shadowColor = p.color;
    ctx.fill();
    ctx.shadowBlur = 0;
    p.t += 0.035;
  });
  agentCanvasTick++;
  AGENT_KEYS.forEach(key => {
    const n = AGENT_NODES[key];
    const x = n.x * W, y = n.y * H;
    const r = key === 'head' ? 30 : 22;
    const pulse = Math.sin(agentCanvasTick * 0.08 + AGENT_KEYS.indexOf(key) * 1.2) * 0.15 + 0.85;
    ctx.beginPath();
    ctx.arc(x, y, r * pulse + 6, 0, Math.PI * 2);
    ctx.strokeStyle = n.glow;
    ctx.lineWidth = 1.5;
    ctx.stroke();
    const grad = ctx.createRadialGradient(x, y, 0, x, y, r);
    grad.addColorStop(0, n.color + '55');
    grad.addColorStop(1, n.color + '18');
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.strokeStyle = n.color;
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.lineWidth = 1;
    ctx.fillStyle = n.color;
    ctx.font = key === 'head' ? 'bold 11px Inter' : 'bold 10px Inter';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(n.label, x, y);
    const names = { head: 'War Room Orchestrator', mon: 'Monitor', tia: 'Threat Intel', rca: 'Response', lea: 'Learning & Audit' };
    ctx.fillStyle = 'rgba(122,155,191,0.85)';
    ctx.font = '9.5px Inter';
    ctx.textBaseline = 'top';
    ctx.fillText(names[key], x, y + r + 8);
  });
  ['mon', 'tia', 'rca', 'lea'].forEach(key => {
    const nh = AGENT_NODES.head, ns = AGENT_NODES[key];
    const mx = (nh.x + ns.x) / 2 * W, my = (nh.y + ns.y) / 2 * H;
    ctx.fillStyle = 'rgba(122,155,191,0.4)';
    ctx.font = '8px Inter';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('↕', mx, my);
  });
}
function agentLog(agentId, msg) {
  const el = document.getElementById('log-' + agentId);
  if (!el) return;
  const entry = document.createElement('div');
  entry.className = 'al-entry';
  entry.innerHTML = `<span class="al-time">${now()}</span><span class="al-msg">${msg}</span>`;
  el.insertBefore(entry, el.firstChild);
  while (el.children.length > 6) el.lastChild.remove();
}
function setAgentBadge(agentId, state) {
  const el = document.getElementById(agentId + '-badge');
  if (!el) return;
  el.className = 'agent-online-badge ' + (state === 'online' ? '' : state);
  el.textContent = state === 'online' ? 'ONLINE' : state === 'busy' ? 'BUSY' : 'ALERT';
}
function flashCard(agentId) {
  const el = document.getElementById('agent-' + agentId);
  if (!el) return;
  el.classList.add('firing');
  setTimeout(() => el.classList.remove('firing'), 700);
}
const MSG_BUS_MAX = 60;
function pushMessage(fromKey, toKey, body, tag) {
  const el = document.getElementById('agent-msgbus');
  if (!el) return;
  const fromNames = { head: 'HEAD-AGENT', mon: 'MON-AGENT', tia: 'TIA-AGENT', rca: 'RCA-AGENT', lea: 'LEA-AGENT' };
  const toNames = { head: 'HEAD', mon: 'MON', tia: 'TIA', rca: 'RCA', lea: 'LEA' };
  const row = document.createElement('div');
  row.className = `msg-row ${fromKey}`;
  row.innerHTML = `
    <span class="msg-time">${now()}</span>
    <span class="msg-from ${fromKey}">${fromNames[fromKey]}</span>
    <span class="msg-arrow">→</span>
    <span class="msg-to">${toNames[toKey]}</span>
    <span class="msg-body">${body}</span>
    <span class="msg-tag ${tag}">${tag.toUpperCase()}</span>`;
  el.insertBefore(row, el.firstChild);
  while (el.children.length > MSG_BUS_MAX) el.lastChild.remove();
  spawnParticle(fromKey, toKey, AGENT_NODES[fromKey].color);
}
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
function updateMonitoringAgent() {
  const evDelta = randInt(800, 3200);
  const alDelta = Math.random() < 0.35 ? 1 : 0;
  AGENT_STATE.mon.events += evDelta;
  AGENT_STATE.mon.alerts += alDelta;
  const evEl = document.getElementById('am-mon-ev');
  const alEl = document.getElementById('am-mon-al');
  const fpEl = document.getElementById('am-mon-fp');
  if (evEl) evEl.textContent = AGENT_STATE.mon.events.toLocaleString();
  if (alEl) alEl.textContent = AGENT_STATE.mon.alerts;
  if (fpEl) fpEl.textContent = (1.2 + rand(-0.3, 0.3)).toFixed(1) + '%';
  const sensors = ['sb-net', 'sb-end', 'sb-log', 'sb-cld'];
  sensors.forEach(id => {
    const el = document.getElementById(id);
    const intensity = STATE.attackInProgress ? rand(70, 100) : rand(25, 70);
    if (el) el.style.width = intensity + '%';
  });
  if (alDelta) {
    const msg = pick(MON_MSGS);
    agentLog('mon', msg);
    setAgentBadge('mon', 'busy');
    flashCard('mon');
    pushMessage('mon', 'head', msg, 'alert');
    setTimeout(() => setAgentBadge('mon', 'online'), 1200);
  }
}
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
function drawRiskGauge(score) {
  const canvas = document.getElementById('riskGaugeCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 220, H = 120;
  canvas.width = W; canvas.height = H;
  ctx.clearRect(0, 0, W, H);
  const cx = W / 2, cy = H - 14, r = Math.min(W, H * 2) * 0.4;
  const startA = Math.PI, endA = 2 * Math.PI;
  ctx.beginPath();
  ctx.arc(cx, cy, r, startA, endA);
  ctx.strokeStyle = 'rgba(255,255,255,0.08)';
  ctx.lineWidth = 14;
  ctx.stroke();
  const fillAngle = startA + (endA - startA) * score;
  const color = score > 0.8 ? '#c27a6e' : score > 0.6 ? '#d4985e' : score > 0.4 ? '#c9a862' : '#82b99a';
  const grd = ctx.createLinearGradient(0, cy, W, cy);
  grd.addColorStop(0, '#82b99a');
  grd.addColorStop(0.5, '#c9a862');
  grd.addColorStop(1, '#c27a6e');
  ctx.beginPath();
  ctx.arc(cx, cy, r, startA, fillAngle);
  ctx.strokeStyle = grd;
  ctx.lineWidth = 14;
  ctx.lineCap = 'round';
  ctx.stroke();
  ctx.lineCap = 'butt';
  const needleA = startA + (endA - startA) * score;
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(cx + (r - 4) * Math.cos(needleA), cy + (r - 4) * Math.sin(needleA));
  ctx.strokeStyle = '#fff';
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.arc(cx, cy, 6, 0, Math.PI * 2);
  ctx.fillStyle = '#fff';
  ctx.fill();
  ['0', 'Low', 'Med', 'High', '10'].forEach((lbl, i) => {
    const a = startA + (endA - startA) * (i / 4);
    const lx = cx + (r + 16) * Math.cos(a), ly = cy + (r + 16) * Math.sin(a);
    ctx.fillStyle = 'rgba(122,155,191,0.6)';
    ctx.font = '8.5px Inter';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(lbl, lx, ly);
  });
  const lbl = document.getElementById('rg-label');
  const labels = score > 0.8 ? 'CRITICAL' : score > 0.6 ? 'HIGH' : score > 0.4 ? 'MEDIUM' : 'LOW';
  if (lbl) {
    lbl.textContent = `CVSS ${(score * 10).toFixed(1)} — ${labels}`;
    lbl.style.color = color;
  }
}
function updateTIAAgent() {
  const iocDelta = Math.random() < 0.5 ? randInt(1, 3) : 0;
  const cveDelta = Math.random() < 0.25 ? 1 : 0;
  AGENT_STATE.tia.iocs += iocDelta;
  AGENT_STATE.tia.cves += cveDelta;
  const riskScore = STATE.attackInProgress ? rand(0.6, 0.97) : rand(0.2, 0.65);
  AGENT_STATE.tia.riskSum += riskScore;
  AGENT_STATE.tia.riskCount += 1;
  AGENT_STATE.tia.riskAvg = AGENT_STATE.tia.riskSum / AGENT_STATE.tia.riskCount;
  const iocEl = document.getElementById('am-tia-ioc');
  const rskEl = document.getElementById('am-tia-risk');
  const cveEl = document.getElementById('am-tia-cve');
  if (iocEl) iocEl.textContent = AGENT_STATE.tia.iocs;
  if (rskEl) rskEl.textContent = (AGENT_STATE.tia.riskAvg * 10).toFixed(2);
  if (cveEl) cveEl.textContent = AGENT_STATE.tia.cves;
  drawRiskGauge(riskScore);
  if (iocDelta || cveDelta) {
    const msg = pick(TIA_MSGS);
    agentLog('tia', msg);
    setAgentBadge('tia', 'busy');
    flashCard('tia');
    pushMessage('tia', 'head',
      `Risk ${(riskScore * 10).toFixed(1)}/10 — ${msg.slice(0, 50)}`, 'intel');
    setTimeout(() => setAgentBadge('tia', 'online'), 1000);
  }
}
const RCA_ACTIONS_LIST = [
  { label: 'IP-BLOCK', cls: 'executed' },
  { label: 'ISOLATE', cls: 'executed' },
  { label: 'HONEYPOT', cls: 'executed' },
  { label: 'RATE-LIMIT', cls: 'executed' },
  { label: 'V-PATCH', cls: 'executed' },
  { label: 'ROLLBACK', cls: 'rolled-back' },
  { label: 'QUARANTINE', cls: 'executed' },
  { label: 'MFA-FORCE', cls: 'executed' },
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
function updateRCAAgent() {
  if (Math.random() < 0.3) {
    const actDelta = 1;
    const isRollback = Math.random() < 0.08;
    AGENT_STATE.rca.actions += actDelta;
    if (isRollback) AGENT_STATE.rca.rollbacks += 1;
    const ms = randInt(80, 380);
    AGENT_STATE.rca.times.push(ms);
    const avgTime = Math.round(AGENT_STATE.rca.times.slice(-20).reduce((a, b) => a + b, 0) / Math.min(AGENT_STATE.rca.times.length, 20));
    const actEl = document.getElementById('am-rca-act');
    const tmEl = document.getElementById('am-rca-time');
    const rlEl = document.getElementById('am-rca-roll');
    if (actEl) actEl.textContent = AGENT_STATE.rca.actions;
    if (tmEl) tmEl.textContent = avgTime + 'ms';
    if (rlEl) rlEl.textContent = AGENT_STATE.rca.rollbacks;
    const actionData = isRollback
      ? RCA_ACTIONS_LIST.find(a => a.cls === 'rolled-back')
      : pick(RCA_ACTIONS_LIST.filter(a => a.cls === 'executed'));
    const el = document.getElementById('rca-actions');
    if (el) {
      const chip = document.createElement('div');
      chip.className = `rca-chip ${actionData.cls}`;
      chip.textContent = actionData.label;
      el.insertBefore(chip, el.firstChild);
      while (el.children.length > 10) el.lastChild.remove();
    }
    const msg = pick(RCA_MSGS);
    agentLog('rca', msg);
    setAgentBadge('rca', 'busy');
    flashCard('rca');
    pushMessage('rca', 'head', msg, 'action');
    pushMessage('rca', 'lea', `Executed: ${msg}`, 'audit');
    setTimeout(() => setAgentBadge('rca', 'online'), 900);
  }
}
const LEA_MSGS = [
  'Model retrained with 128 new attack samples',
  'Forensic chain: block #%n anchored to ledger',
  'Knowledge base updated — TTPs classified',
  'Threat pattern recorded for future inference',
  'GDPR audit record generated',
  'SIEM log export: 4,200 new entries',
  'Baseline model drift: Δ=0.003 — within bounds',
  'Signature DB synced with global threat intel',
];
function updateLEAAgent() {
  const updDelta = Math.random() < 0.25 ? 1 : 0;
  const audDelta = 1;
  AGENT_STATE.lea.updates += updDelta;
  AGENT_STATE.lea.audits += audDelta;
  AGENT_STATE.lea.kb += updDelta ? randInt(1, 5) : 0;
  const updEl = document.getElementById('am-lea-upd');
  const audEl = document.getElementById('am-lea-aud');
  const kbEl = document.getElementById('am-lea-kb');
  if (updEl) updEl.textContent = AGENT_STATE.lea.updates;
  if (audEl) audEl.textContent = AGENT_STATE.lea.audits;
  if (kbEl) kbEl.textContent = AGENT_STATE.lea.kb + ' entries';
  if (updDelta) {
    const msg = pick(LEA_MSGS).replace('%n', AGENT_STATE.lea.audits);
    agentLog('lea', msg);
    setAgentBadge('lea', 'busy');
    flashCard('lea');
    pushMessage('lea', 'head', msg, 'audit');
    setTimeout(() => setAgentBadge('lea', 'online'), 800);
  }
}
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
function updateHeadAgent() {
  if (Math.random() < 0.4) {
    AGENT_STATE.head.directives++;
    if (Math.random() < 0.15) AGENT_STATE.head.escalations++;
    const dirEl = document.getElementById('am-head-dir');
    const escEl = document.getElementById('am-head-esc');
    if (dirEl) dirEl.textContent = AGENT_STATE.head.directives;
    if (escEl) escEl.textContent = AGENT_STATE.head.escalations;
    const msg = pick(HEAD_DIRECTIVES);
    const targets = ['mon', 'tia', 'rca', 'lea'];
    const target = pick(targets);
    agentLog('head', msg);
    flashCard('head');
    pushMessage('head', target, msg, 'directive');
    spawnParticle('head', target, '#00d4ff');
  }
}
let agentIncidentInProgress = false;
const INCIDENT_STEPS = [
  {
    actor: 'mon', target: 'head', delay: 0,
    log: 'Anomaly detected: 4,847 failed auth attempts in 60s',
    tag: 'alert',
    badge: { mon: 'alert' },
    desc: 'MON-AGENT: Mass brute-force authentication pattern detected'
  },
  {
    actor: 'head', target: 'tia', delay: 1000,
    log: 'Escalation: Request TI enrichment for IP 185.220.101.34',
    tag: 'directive',
    badge: { head: 'busy', tia: 'busy' },
    desc: 'HEAD-AGENT: Directing TIA-AGENT to enrich threat intel'
  },
  {
    actor: 'tia', target: 'head', delay: 2200,
    log: 'IOC confirmed — APT29 C2 server, CVSS 9.6 (CVE-2024-4471)',
    tag: 'intel',
    badge: { tia: 'alert', head: 'busy' },
    desc: 'TIA-AGENT: Enrichment complete — Critical IOC confirmed'
  },
  {
    actor: 'head', target: 'rca', delay: 3200,
    log: 'DIRECTIVE: Block IP, isolate subnet 10.0.2.0/24, deploy honeypot',
    tag: 'directive',
    badge: { head: 'busy', rca: 'alert' },
    desc: 'HEAD-AGENT: Dispatching autonomous containment directives'
  },
  {
    actor: 'rca', target: 'head', delay: 4400,
    log: 'Containment executed in 147ms — 3 actions deployed',
    tag: 'action',
    badge: { rca: 'busy' },
    desc: '⚔ RCA-AGENT: Isolation + honeypot + IP-block executed autonomously'
  },
  {
    actor: 'head', target: 'lea', delay: 5400,
    log: 'DIRECTIVE: Record incident, update threat model, anchor audit chain',
    tag: 'directive',
    badge: { head: 'busy', lea: 'busy' },
    desc: 'HEAD-AGENT: Directing LEA-AGENT to audit & learn'
  },
  {
    actor: 'lea', target: 'head', delay: 6600,
    log: 'Audit chain anchored — model retrained (Δacc +0.8%), KB +12 entries',
    tag: 'audit',
    badge: { lea: 'busy' },
    desc: 'LEA-AGENT: Incident learned — model & forensics updated'
  },
  {
    actor: 'head', target: 'mon', delay: 7600,
    log: 'INCIDENT CLOSED — returning to PROTECT posture',
    tag: 'info',
    badge: { head: 'online', mon: 'online', tia: 'online', rca: 'online', lea: 'online' },
    desc: 'HEAD-AGENT: All agents nominal — threat neutralised'
  },
];
function agentSimulateAttack() {
  if (agentIncidentInProgress) return;
  agentIncidentInProgress = true;
  const btn = document.getElementById('btn-agent-attack');
  if (btn) { btn.textContent = 'Incident Running...'; btn.disabled = true; }
  INCIDENT_STEPS.forEach(step => {
    setTimeout(() => {
      Object.entries(step.badge).forEach(([agentId, state]) => setAgentBadge(agentId, state));
      agentLog(step.actor, step.log);
      flashCard(step.actor);
      pushMessage(step.actor, step.target, step.log, step.tag);
      spawnParticle(step.actor, step.target, AGENT_NODES[step.actor].color);
      if (step === INCIDENT_STEPS[INCIDENT_STEPS.length - 1]) {
        setTimeout(() => {
          agentIncidentInProgress = false;
          if (btn) { btn.textContent = 'Trigger Incident'; btn.disabled = false; }
          AGENT_KEYS.forEach(k => setAgentBadge(k, 'online'));
        }, 1500);
      }
    }, step.delay);
  });
}
let agentTick = 0;
function agentSimulationLoop() {
  agentTick++;
  drawAgentCanvas();
  if (agentTick % 2 === 0) updateMonitoringAgent();
  if (agentTick % 3 === 0) updateTIAAgent();
  if (agentTick % 2 === 1) updateRCAAgent();
  if (agentTick % 4 === 0) updateLEAAgent();
  if (agentTick % 3 === 1) updateHeadAgent();
}
function initAgentNetwork() {
  drawRiskGauge(0.3);
  const bootMsgs = [
    { f: 'head', t: 'mon', b: 'System boot — begin baseline network scan', tag: 'directive' },
    { f: 'head', t: 'tia', b: 'Connect to external threat intelligence feeds', tag: 'directive' },
    { f: 'head', t: 'rca', b: 'Load response playbooks into execution engine', tag: 'directive' },
    { f: 'head', t: 'lea', b: 'Initialize forensic logging chain', tag: 'directive' },
    { f: 'mon', t: 'head', b: 'Baseline established — 243k flows/min normalised', tag: 'info' },
    { f: 'tia', t: 'head', b: 'Threat feeds connected: ThreatFox, VirusTotal, MISP', tag: 'info' },
    { f: 'lea', t: 'head', b: 'Audit ledger initialised — chain length: 0', tag: 'audit' },
  ];
  bootMsgs.forEach((m, i) => {
    setTimeout(() => pushMessage(m.f, m.t, m.b, m.tag), i * 350);
  });
  setInterval(agentSimulationLoop, 900);
  ['sb-net', 'sb-end', 'sb-log', 'sb-cld'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.width = rand(30, 65) + '%';
  });
}
let liveMap;
let userLoc = null;
let userMarker = null;
let locationFetched = false;
function initLiveMap() {
  const container = document.getElementById('geo-map');
  if (!container) return;
  if (!liveMap) {
    liveMap = L.map('geo-map', {
      center: [20, 0],
      zoom: 2,
      minZoom: 2,
      maxBounds: [
        [-90, -180],
        [90, 180]
      ],
      maxBoundsViscosity: 1.0,
      zoomControl: true,
      attributionControl: false
    });
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
      maxZoom: 19,
      noWrap: true
    }).addTo(liveMap);
  }
  setTimeout(() => { if (liveMap) liveMap.invalidateSize() }, 100);
  setTimeout(() => { if (liveMap) liveMap.invalidateSize() }, 500);
  setTimeout(() => { if (liveMap) liveMap.invalidateSize() }, 1500);
  fetchUserLocation();
  if (userLoc) plotUserLocMarker();
  pollRealThreatData();
  setInterval(pollRealThreatData, 20000);
  setInterval(() => {
    let threat = threatBuffer.length > 0 ? threatBuffer.shift() : generateRealisticEvent(true);
    let trust = trustBuffer.length > 0 ? trustBuffer.shift() : generateRealisticEvent(false);
    if (threat) plotRealMapEvent(threat, true);
    if (trust) plotRealMapEvent(trust, false);
  }, 1200);
}
function fetchUserLocation() {
  if (locationFetched) return;
  locationFetched = true;
  const fallbackAPIs = [
    'https://get.geojs.io/v1/ip/geo.json',
    'https://ipapi.co/json/',
    'https://ipwhois.app/json/'
  ];
  let fetchNext = (index) => {
    if (index >= fallbackAPIs.length) {
      if (!userLoc) {
        userLoc = { lat: 1.352, lng: 103.819 };
        if (liveMap) plotUserLocMarker();
      }
      return;
    }
    fetch(fallbackAPIs[index])
      .then(res => res.json())
      .then(data => {
        let lat = data.latitude || data.lat;
        let lng = data.longitude || data.lon;
        if (!userLoc && lat && lng) {
          userLoc = { lat: parseFloat(lat), lng: parseFloat(lng) };
          if (liveMap) plotUserLocMarker();
        } else if (!userLoc) {
          fetchNext(index + 1);
        }
      })
      .catch(e => {
        console.warn('IP Geo API failed:', fallbackAPIs[index], e);
        fetchNext(index + 1);
      });
  };
  fetchNext(0);
  if ("geolocation" in navigator) {
    navigator.geolocation.getCurrentPosition(pos => {
      userLoc = { lat: pos.coords.latitude, lng: pos.coords.longitude };
      if (liveMap) plotUserLocMarker();
    }, err => {
      console.warn("Browser GPS denied, relying on fallback.", err);
    }, { timeout: 10000, enableHighAccuracy: true });
  }
}
function plotUserLocMarker() {
  if (!liveMap || !userLoc) return;
  if (userMarker) liveMap.removeLayer(userMarker);
  const beaconIcon = L.divIcon({
    className: 'user-beacon',
    html: '<div class="beacon-core" style="width:12px; height:12px; background: #00d4ff; border-radius: 50%; box-shadow: 0 0 10px #00d4ff;"></div><div class="beacon-wave" style="border: 2px solid #00d4ff;"></div>',
    iconSize: [24, 24],
    iconAnchor: [12, 12]
  });
  userMarker = L.marker([userLoc.lat, userLoc.lng], { icon: beaconIcon }).addTo(liveMap);
  liveMap.setView([userLoc.lat, userLoc.lng], 4);
}
let threatBuffer = [];
let trustBuffer = [];
const KNOWN_TRUSTED_REGIONS = [
  { lat: 37.386, lng: -122.083 }, { lat: 51.509, lng: -0.118 }, { lat: 35.689, lng: 139.691 },
  { lat: -33.868, lng: 151.209 }, { lat: 50.110, lng: 8.682 }, { lat: 1.352, lng: 103.819 },
  { lat: 39.043, lng: -77.487 }, { lat: 46.204, lng: 6.143 }, { lat: -23.550, lng: -46.633 },
  { lat: 19.076, lng: 72.877 }, { lat: 13.082, lng: 80.270 }, { lat: 28.704, lng: 77.102 }
];
function generateRealisticEvent(isThreat) {
  let lat, lng;
  let bias = isThreat ? 0.6 : 0.25;
  if (userLoc && Math.random() < bias) {
    lat = userLoc.lat + rand(-18, 18);
    lng = userLoc.lng + rand(-18, 18);
  } else if (!isThreat) {
    let tr = pick(KNOWN_TRUSTED_REGIONS);
    lat = tr.lat + rand(-2, 2); lng = tr.lng + rand(-2, 2);
  } else {
    lat = rand(-50, 70); lng = rand(-180, 180);
  }
  return { lat, lng, radius: isThreat ? rand(60000, 200000) : rand(40000, 110000) };
}
async function pollRealThreatData() {
  try {
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/');
    const data = await res.json();
    if (data.urls) {
      const newThreats = data.urls.slice(0, 50).map(u => {
        let hash = u.host.split('').reduce((a, b) => { a = ((a << 5) - a) + b.charCodeAt(0); return a & a }, 0);
        return {
          lat: (hash % 120) - 50,
          lng: ((hash / 120) % 360) - 180,
          radius: 100000 + (Math.abs(hash % 300) * 1000)
        };
      });
      threatBuffer.push(...newThreats);
    }
  } catch (e) {
    console.warn("Could not fetch Abuse.ch feed in browser.", e);
  }
  for (let i = 0; i < 30; i++) {
    const loc = pick(KNOWN_TRUSTED_REGIONS);
    trustBuffer.push({
      lat: loc.lat + rand(-5, 5),
      lng: loc.lng + rand(-5, 5),
      radius: rand(50000, 150000)
    });
  }
}
function plotRealMapEvent(evt, isThreat) {
  if (!liveMap) return;
  const color = isThreat ? '#c27a6e' : '#82b99a';
  const circle = L.circle([evt.lat, evt.lng], {
    radius: evt.radius,
    fillColor: color,
    color: color,
    weight: 2,
    opacity: 0.6,
    fillOpacity: 0.5
  }).addTo(liveMap);
  setTimeout(() => {
    if (liveMap && liveMap.hasLayer(circle)) liveMap.removeLayer(circle);
  }, isThreat ? 8000 : 5000);
}
async function updateUEBAList() {
  if (typeof AEGIS_API === 'undefined') return;
  const res = await AEGIS_API.behavior.ueba();
  if (!res.ok) return;
  const container = document.getElementById('ueba-list');
  if (!container) return;

  // Only update if something actually changed or to keep it live
  container.innerHTML = res.data.entities.map(e => {
    const color = e.riskClass === 'high' ? '#f43f5e' : (e.riskClass === 'medium' ? '#facc15' : '#4ade80');
    const initial = e.name.charAt(0);
    return `
      <div class="ueba-entity" id="ueba-${e.id}">
        <div class="ueba-avatar" style="background:${color}20; color:${color};">${initial}</div>
        <div class="ueba-info">
          <span class="ueba-name">${e.email || e.name}</span>
          <span class="ueba-role">${e.role}</span>
        </div>
        <div class="ueba-score ${e.riskClass}">${e.riskScore}</div>
      </div>
    `;
  }).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  initLogin();
  checkAuth();
  updateUEBAList();
  setInterval(updateUEBAList, 5000);
});

async function checkAuth() {
  if (typeof AEGIS_API !== 'undefined') {
    const token = AEGIS_API.getToken();
    if (token) {
      console.log('[AUTH] Token found, verifying...');
      try {
        const result = await AEGIS_API.auth.me();
        if (result.ok) {
          console.log('[AUTH] User verified:', result.data.user.email);
          updateUserProfile(result.data.user);
          document.getElementById('login-overlay')?.classList.add('hidden');
          fetchUserLocation();
        } else {
          console.warn('[AUTH] Token invalid or expired');
          AEGIS_API.auth.logout();
        }
      } catch (err) {
        console.error('[AUTH] Auth check failed:', err.message);
      }
    }
  }
}

// Google Identity Services Callback
window.handleGoogleCredentialResponse = async function (response) {
  const loginOverlay = document.getElementById('login-overlay');
  const loginBtn = document.getElementById('login-btn');

  console.log("[AUTH] Google credential received, verifying with backend...");

  if (typeof AEGIS_API !== 'undefined') {
    try {
      const result = await AEGIS_API.auth.googleSSO(response.credential);
      if (result.ok) {
        const user = result.data.user;
        console.log('[AUTH] Google SSO successful:', user.email);

        // Update UI with user info
        updateUserProfile(user);

        // Hide login overlay
        if (loginOverlay) {
          loginOverlay.classList.add('hidden');

          // Trigger initial simulation
          setTimeout(() => {
            if (!STATE.attackInProgress) triggerSimulatedAttack();
            setInterval(() => {
              if (!STATE.attackInProgress) triggerSimulatedAttack();
            }, 45000);
          }, 2000);
        }

        fetchUserLocation();
      } else {
        console.warn('[AUTH] Google SSO backend error:', result.status);
        showAlert('Authentication Failed', 'Google login was rejected by the server.');
      }
    } catch (err) {
      console.error('[AUTH] Google SSO failed:', err.message);
      showAlert('Connection Error', 'Could not reach the authentication server.');
    }
  }
};

function updateUserProfile(user) {
  const sidebarStatus = document.querySelector('.sidebar-status');
  if (sidebarStatus && user) {
    // Create or update profile section
    let profile = document.getElementById('user-profile-sidebar');
    if (!profile) {
      profile = document.createElement('div');
      profile.id = 'user-profile-sidebar';
      profile.className = 'user-profile-sidebar';
      sidebarStatus.parentNode.insertBefore(profile, sidebarStatus);
    }

    profile.innerHTML = `
      <div class="user-avatar-small">
        <img src="${user.avatar || 'https://ui-avatars.com/api/?name=' + encodeURIComponent(user.name) + '&background=7ec8c8&color=fff'}" alt="${user.name}" style="width:32px; height:32px; border-radius:50%; border: 1px solid var(--accent-aqua);">
      </div>
      <div class="user-info-small">
        <span class="user-name-small" style="display:block; font-size:12px; font-weight:600; color:var(--text-bright);">${user.name}</span>
        <span class="user-role-small" style="display:block; font-size:10px; color:var(--accent-aqua); opacity:0.8;">${user.role.toUpperCase()}</span>
      </div>
      <button class="btn-logout-small" onclick="handleLogout()" style="background:none; border:none; color:var(--text-muted); cursor:pointer; font-size:16px; margin-left:auto; padding:4px;">⎋</button>
    `;
  }
}

function handleLogout() {
  if (typeof AEGIS_API !== 'undefined') {
    AEGIS_API.auth.logout();
    location.reload();
  }
}


function initLogin() {
  const loginForm = document.getElementById('login-form');
  const loginOverlay = document.getElementById('login-overlay');
  const loginBtn = document.getElementById('login-btn');
  const btnText = loginBtn.querySelector('span');
  const spinner = loginBtn.querySelector('.auth-spinner');
  if (!loginForm || !loginOverlay) return;
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    btnText.style.display = 'none';
    spinner.style.display = 'inline-block';
    loginBtn.disabled = true;
    let authOk = false;
    if (typeof AEGIS_API !== 'undefined') {
      try {
        const result = await AEGIS_API.auth.login(email, password);
        authOk = result.ok || result.status === 401;
        if (result.ok) {
          console.log('[AUTH] Backend login OK for:', email);
        } else {
          console.warn('[AUTH] Backend returned', result.status, '— entering demo mode');
          authOk = true;
        }
      } catch (err) {
        console.warn('[AUTH] Backend unreachable, entering demo mode:', err.message);
        authOk = true;
      }
    } else {
      authOk = true;
    }
    setTimeout(() => {
      loginOverlay.classList.add('hidden');
      setTimeout(() => {
        btnText.style.display = 'inline-block';
        spinner.style.display = 'none';
        loginBtn.disabled = false;
        loginForm.reset();
      }, 500);
      fetchUserLocation();
      setTimeout(() => {
        if (!STATE.attackInProgress) triggerSimulatedAttack();
        setInterval(() => {
          if (!STATE.attackInProgress) triggerSimulatedAttack();
        }, 45000);
      }, 3000);
    }, 900);
  });
}
// Removed legacy simulated Google login handlers

