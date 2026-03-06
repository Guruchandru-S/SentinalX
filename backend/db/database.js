const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');
const DB_PATH = path.join(__dirname, '..', 'aegis.db');
let db = null;
let _ready = false;
let _readyCallbacks = [];
let _saveTimer = null;
function scheduleSave() {
  if (_saveTimer) return;
  _saveTimer = setTimeout(() => {
    _saveTimer = null;
    saveToDisk();
  }, 500);
}
function saveToDisk() {
  if (!db) return;
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (e) {
    console.error('[DB] Save error:', e.message);
  }
}
setInterval(saveToDisk, 30000);
const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    email        TEXT UNIQUE NOT NULL,
    name         TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst', avatar_url TEXT,
    password_hash TEXT,
    created_at   TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE TABLE IF NOT EXISTS threats (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    source_ip   TEXT,
    source_host TEXT,
    country     TEXT,
    category    TEXT,
    action      TEXT,
    cvss        REAL DEFAULT 0,
    url         TEXT,
    malware     TEXT,
    tags        TEXT,
    feed_source TEXT,
    timestamp   TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id           TEXT PRIMARY KEY,
    seq          INTEGER,
    type         TEXT NOT NULL,
    message      TEXT NOT NULL,
    hash         TEXT,
    chain_length INTEGER DEFAULT 0,
    merkle_root  TEXT,
    actor        TEXT DEFAULT 'AEGIS-SYSTEM',
    manual       INTEGER DEFAULT 0,
    timestamp    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE TABLE IF NOT EXISTS anomalies (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL,
    score      REAL NOT NULL,
    severity   TEXT NOT NULL,
    source_ip  TEXT,
    z_score    REAL,
    model      TEXT DEFAULT 'LSTM-v3',
    timestamp  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE TABLE IF NOT EXISTS response_timeline (
    id        TEXT PRIMARY KEY,
    title     TEXT NOT NULL,
    type      TEXT DEFAULT 'info',
    playbook  TEXT,
    timestamp TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE TABLE IF NOT EXISTS decision_matrix (
    id               TEXT PRIMARY KEY,
    threat_type      TEXT NOT NULL,
    severity         TEXT NOT NULL,
    confidence       REAL NOT NULL,
    action           TEXT NOT NULL,
    response_time_ms INTEGER,
    status           TEXT DEFAULT 'MITIGATED',
    cvss             REAL DEFAULT 0,
    timestamp        TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE TABLE IF NOT EXISTS ml_inference_log (
    id         TEXT PRIMARY KEY,
    ip         TEXT,
    confidence REAL,
    prediction TEXT,
    status     TEXT,
    model      TEXT DEFAULT 'LSTM-v3',
    timestamp  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE TABLE IF NOT EXISTS agent_messages (
    id        TEXT PRIMARY KEY,
    from_id   TEXT NOT NULL,
    from_name TEXT,
    to_id     TEXT NOT NULL,
    to_name   TEXT,
    body      TEXT NOT NULL,
    tag       TEXT DEFAULT 'info',
    timestamp TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id      TEXT PRIMARY KEY,
    description TEXT,
    cvss_score  REAL,
    severity    TEXT,
    vendor      TEXT,
    product     TEXT,
    published   TEXT,
    fetched_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE TABLE IF NOT EXISTS ioc_entries (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    malware     TEXT,
    confidence  INTEGER,
    tags        TEXT,
    feed_source TEXT,
    first_seen  TEXT,
    fetched_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE TABLE IF NOT EXISTS c2_servers (
    ip_address  TEXT PRIMARY KEY,
    port        INTEGER,
    status      TEXT,
    malware     TEXT,
    country     TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    fetched_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE TABLE IF NOT EXISTS system_config (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
  CREATE INDEX IF NOT EXISTS idx_threats_ts       ON threats(timestamp);
  CREATE INDEX IF NOT EXISTS idx_audit_seq        ON audit_log(seq);
  CREATE INDEX IF NOT EXISTS idx_anomalies_ts     ON anomalies(timestamp);
  CREATE TABLE IF NOT EXISTS ueba_entities (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    email        TEXT UNIQUE,
    role         TEXT,
    department   TEXT,
    risk_score   REAL DEFAULT 0,
    risk_class   TEXT DEFAULT 'low',
    anomaly_flags INTEGER DEFAULT 0,
    last_activity TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );
  CREATE INDEX IF NOT EXISTS idx_ueba_risk  ON ueba_entities(risk_score);
`;
async function init() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
    console.log('[DB] Loaded existing database:', DB_PATH);
  } else {
    db = new SQL.Database();
    console.log('[DB] Created new database:', DB_PATH);
  }
  db.run(SCHEMA);
  // Migration: Add avatar_url column if it doesn't exist
  try {
    db.run("ALTER TABLE users ADD COLUMN avatar_url TEXT");
    console.log('[DB] Migration: Added avatar_url column to users table');
  } catch (e) {
    // Column likely already exists, ignore error
  }

  saveToDisk();
  _ready = true;
  _readyCallbacks.forEach(fn => fn());
  _readyCallbacks = [];
  return db;
}
function getDb() { return db; }
function run(sql, params = []) {
  db.run(sql, params);
  scheduleSave();
}
function get(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}
function all(sql, params = []) {
  const results = [];
  const stmt = db.prepare(sql);
  stmt.bind(params);
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}
function count(table, where = '', params = []) {
  const sql = `SELECT COUNT(*) as n FROM ${table}${where ? ' WHERE ' + where : ''}`;
  const row = get(sql, params);
  return row ? Number(row.n) : 0;
}
function insertMany(sql, rowsData) {
  const stmt = db.prepare(sql);
  let inserted = 0;
  db.run('BEGIN TRANSACTION');
  try {
    for (const row of rowsData) {
      stmt.run(row);
      inserted++;
    }
    db.run('COMMIT');
  } catch (e) {
    db.run('ROLLBACK');
    throw e;
  }
  stmt.free();
  scheduleSave();
  return inserted;
}
function seedUsers() {
  const bcrypt = require('bcryptjs');
  const defaultHash = bcrypt.hashSync('aegis2024!', 10);
  const existing = get('SELECT COUNT(*) as n FROM users');
  if (existing && Number(existing.n) > 0) return;
  run(`INSERT OR IGNORE INTO users (id, email, name, role, password_hash) VALUES (?, ?, ?, ?, ?)`,
    ['u001', 'user@organization.corp', 'Authorized User', 'analyst', defaultHash]);
  run(`INSERT OR IGNORE INTO users (id, email, name, role, password_hash) VALUES (?, ?, ?, ?, ?)`,
    ['u002', 'admin@aegis.system', 'System Admin', 'admin', defaultHash]);
  console.log('[DB] Seeded default users');
}
function seedUEBA() {
  const existing = get('SELECT COUNT(*) as n FROM ueba_entities');
  if (existing && Number(existing.n) > 0) return;
  const entities = [
    ['u_mwilliams', 'M. Williams', 'm.williams@corp.net', 'Finance Director', 'Finance', 16, 'low'],
    ['svc_db_backup', 'DB Backup Service', 'db-backup-svc-04', 'Automated Pipeline', 'Infrastructure', 58, 'medium'],
    ['ext_contractor', 'External Contractor', 'ext.contractor@partner.org', 'Guest Network', 'External', 82, 'high'],
    ['sys_orch', 'System Orchestrator', 'sys-orch-daemon', 'System Service', 'Systems', 5, 'low']
  ];
  db.run('BEGIN TRANSACTION');
  try {
    for (const e of entities) {
      db.run(`INSERT INTO ueba_entities (id, name, email, role, department, risk_score, risk_class) VALUES (?, ?, ?, ?, ?, ?, ?)`, e);
    }
    db.run('COMMIT');
    console.log('[DB] Seeded UEBA entities');
  } catch (e) {
    db.run('ROLLBACK');
    console.error('[DB] Seed UEBA error:', e.message);
  }
}
function getConfig(key) {
  const row = get('SELECT value FROM system_config WHERE key = ?', [key]);
  return row ? row.value : null;
}
function setConfig(key, value) {
  run(`INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
    [key, String(value)]);
}
module.exports = {
  init, getDb,
  run, get, all, count, insertMany,
  seedUsers, seedUEBA, getConfig, setConfig,
  saveToDisk
};
