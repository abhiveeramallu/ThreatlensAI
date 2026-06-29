const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const STORAGE_DIR = process.env.LOG_DIR
  || (process.env.VERCEL ? "/tmp" : path.join(__dirname, "..", "storage"));
const SESSION_FILE_PATH = process.env.SESSION_LOG_PATH || path.join(STORAGE_DIR, "sessions.json");
const BEHAVIOR_FILE_PATH = process.env.BEHAVIOR_LOG_PATH || path.join(STORAGE_DIR, "behavior_events.json");
const ACCESS_LOG_PATH = process.env.LOG_PATH || path.join(STORAGE_DIR, "access_log.csv");
const DEFAULT_PAGE_SIZE = 12;
const MAX_PAGE_SIZE = 100;

const PROVIDERS = {
  FILE: "file",
  POSTGRES: "postgres"
};

const CSV_HEADERS = [
  "session_id",
  "timestamp",
  "username",
  "ip_address",
  "country",
  "city",
  "browser",
  "operating_system",
  "user_agent",
  "threat_score",
  "threat_level",
  "prediction",
  "confidence",
  "action_taken",
  "verification_state",
  "reason_summary",
  "ai_report",
  "event_count",
  "bot_signal_count",
  "automation_flags",
  "explainability"
];

const POSTGRES_SCHEMA = `
  CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(80) UNIQUE NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    username TEXT,
    ip_address TEXT,
    country TEXT,
    city TEXT,
    browser TEXT,
    operating_system TEXT,
    user_agent TEXT,
    threat_score INTEGER,
    threat_level TEXT,
    prediction TEXT,
    confidence INTEGER,
    action_taken TEXT,
    verification_state TEXT,
    reason_summary TEXT,
    ai_report JSONB NOT NULL DEFAULT '{}'::jsonb,
    explainability JSONB NOT NULL DEFAULT '[]'::jsonb,
    automation_flags JSONB NOT NULL DEFAULT '[]'::jsonb,
    bot_signal_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS behavior_events (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(80) NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    mouse_movements INTEGER,
    clicks INTEGER,
    keystrokes INTEGER,
    scroll_events INTEGER,
    typing_speed NUMERIC(10, 2),
    average_mouse_speed NUMERIC(10, 2),
    time_to_first_click_ms INTEGER,
    time_to_submit_ms INTEGER,
    captcha_verified BOOLEAN,
    otp_verified BOOLEAN,
    attempt_index INTEGER,
    raw_features JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON sessions (timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_sessions_action_taken ON sessions (action_taken);
  CREATE INDEX IF NOT EXISTS idx_sessions_prediction ON sessions (prediction);
  CREATE INDEX IF NOT EXISTS idx_behavior_events_session_id ON behavior_events (session_id);
  ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ai_report JSONB NOT NULL DEFAULT '{}'::jsonb;
`;

let pool = null;
let initPromise = null;
let storeInfo = {
  provider: PROVIDERS.FILE,
  ready: false,
  postgresConfigured: false,
  postgresReady: false,
  reason: "Using file-based persistence."
};

async function initializeStore() {
  if (initPromise) {
    return initPromise;
  }

  initPromise = (async () => {
    ensureFileStore();

    const postgresConfig = getPostgresConfig();
    if (!postgresConfig) {
      storeInfo = {
        provider: PROVIDERS.FILE,
        ready: true,
        postgresConfigured: false,
        postgresReady: false,
        reason: "DATABASE_URL or PG* variables not set. Using file-based persistence."
      };
      return storeInfo;
    }

    const pgDriver = loadPostgresDriver();
    if (!pgDriver) {
      storeInfo = {
        provider: PROVIDERS.FILE,
        ready: true,
        postgresConfigured: true,
        postgresReady: false,
        reason: "PostgreSQL configured but the optional \"pg\" package is not installed. Falling back to file storage."
      };
      return storeInfo;
    }

    try {
      pool = new pgDriver.Pool(postgresConfig);
      await pool.query(POSTGRES_SCHEMA);
      storeInfo = {
        provider: PROVIDERS.POSTGRES,
        ready: true,
        postgresConfigured: true,
        postgresReady: true,
        reason: "Connected to PostgreSQL and ensured the analytics schema."
      };
      return storeInfo;
    } catch (error) {
      console.error("PostgreSQL initialization failed, using file-based persistence.", error);
      pool = null;
      storeInfo = {
        provider: PROVIDERS.FILE,
        ready: true,
        postgresConfigured: true,
        postgresReady: false,
        reason: "PostgreSQL connection failed. Using file-based persistence instead."
      };
      return storeInfo;
    }
  })();

  return initPromise;
}

async function getStoreInfo() {
  await initializeStore();
  return {
    ...storeInfo,
    sessionFilePath: SESSION_FILE_PATH,
    behaviorFilePath: BEHAVIOR_FILE_PATH,
    exportFilePath: ACCESS_LOG_PATH
  };
}

async function saveSecurityEvent({ session, behaviorEvent }) {
  await initializeStore();

  if (storeInfo.provider === PROVIDERS.POSTGRES && pool) {
    await upsertSessionPostgres(session);
    await insertBehaviorEventPostgres(behaviorEvent);
  } else {
    upsertSessionFile(session);
    insertBehaviorEventFile(behaviorEvent);
  }

  await syncCsvExport();
  return session;
}

async function loadSnapshot() {
  await initializeStore();

  if (storeInfo.provider === PROVIDERS.POSTGRES && pool) {
    const [sessionsResult, behaviorResult] = await Promise.all([
      pool.query("SELECT * FROM sessions ORDER BY updated_at DESC"),
      pool.query("SELECT * FROM behavior_events ORDER BY created_at DESC")
    ]);

    return {
      sessions: sessionsResult.rows.map(normalizeSessionRecord),
      behaviorEvents: behaviorResult.rows.map(normalizeBehaviorRecord)
    };
  }

  return {
    sessions: readJsonArray(SESSION_FILE_PATH).map(normalizeSessionRecord),
    behaviorEvents: readJsonArray(BEHAVIOR_FILE_PATH).map(normalizeBehaviorRecord)
  };
}

async function listSessions(filters = {}) {
  const snapshot = await loadSnapshot();
  const hydrated = hydrateSessions(snapshot.sessions, snapshot.behaviorEvents);
  const filtered = filterSessions(hydrated, filters);
  const pageSize = normalizePageSize(filters.pageSize);
  const page = normalizePage(filters.page);
  const total = filtered.length;
  const totalPages = total === 0 ? 1 : Math.ceil(total / pageSize);
  const currentPage = Math.min(page, totalPages);
  const start = (currentPage - 1) * pageSize;
  const items = filtered.slice(start, start + pageSize);

  return {
    items,
    total,
    page: currentPage,
    pageSize,
    totalPages
  };
}

async function getDashboardData(filters = {}) {
  const snapshot = await loadSnapshot();
  const hydrated = hydrateSessions(snapshot.sessions, snapshot.behaviorEvents);
  const filtered = filterSessions(hydrated, filters);
  const averageThreatScore = filtered.length
    ? Math.round(filtered.reduce((sum, item) => sum + normalizeInteger(item.threat_score), 0) / filtered.length)
    : 0;

  const totalHumans = filtered.filter((item) => item.prediction === "HUMAN").length;
  const totalBots = filtered.filter((item) => item.prediction === "BOT").length;
  const totalBlocks = filtered.filter((item) => item.action_taken === "BLOCK_SESSION").length;

  return {
    metrics: {
      total_sessions: filtered.length,
      total_humans: totalHumans,
      total_bots: totalBots,
      total_blocks: totalBlocks,
      average_threat_score: averageThreatScore
    },
    distributions: {
      threat_levels: buildCountBuckets(filtered, "threat_level", ["SAFE", "SUSPICIOUS", "HIGH_RISK", "CRITICAL"]),
      action_counts: buildCountBuckets(filtered, "action_taken", ["ALLOW_ACCESS", "SHOW_CAPTCHA", "REQUIRE_OTP", "BLOCK_SESSION"]),
      browser_breakdown: buildTopBreakdown(filtered, "browser", 6)
    },
    trends: {
      detections_per_day: buildDailySeries(filtered, (item) => item.prediction === "BOT"),
      blocks_per_day: buildDailySeries(filtered, (item) => item.action_taken === "BLOCK_SESSION")
    },
    ratio: {
      humans: totalHumans,
      bots: totalBots
    },
    recent_sessions: filtered.slice(0, 8),
    storage: await getStoreInfo()
  };
}

async function exportSessionsCsv(filters = {}) {
  const snapshot = await loadSnapshot();
  const hydrated = hydrateSessions(snapshot.sessions, snapshot.behaviorEvents);
  const filtered = filterSessions(hydrated, {
    ...filters,
    page: 1,
    pageSize: MAX_PAGE_SIZE
  });

  return buildCsv(filtered);
}

async function getRiskContext({ sessionId, ipAddress }) {
  const snapshot = await loadSnapshot();
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const localIp = isPrivateOrLoopbackIp(ipAddress);

  const recentSessionAttempts = snapshot.behaviorEvents.filter((event) => {
    if (event.session_id !== sessionId) {
      return false;
    }
    const createdAt = safeTimestamp(event.created_at);
    return createdAt && now - createdAt <= windowMs;
  }).length;

  const recentIpSessions = localIp
    ? 0
    : snapshot.sessions.filter((session) => {
      if (!ipAddress || !session.ip_address || session.ip_address !== ipAddress) {
        return false;
      }
      const updatedAt = safeTimestamp(session.updated_at || session.timestamp);
      return updatedAt && now - updatedAt <= windowMs;
    }).length;

  const blockedFromIp = localIp
    ? 0
    : snapshot.sessions.filter((session) => {
      if (!ipAddress || session.ip_address !== ipAddress) {
        return false;
      }
      return session.action_taken === "BLOCK_SESSION";
    }).length;

  return {
    recentSessionAttempts,
    recentIpSessions,
    blockedFromIp,
    isLocalIp: localIp
  };
}

module.exports = {
  initializeStore,
  getStoreInfo,
  saveSecurityEvent,
  listSessions,
  getDashboardData,
  exportSessionsCsv,
  getRiskContext,
  ACCESS_LOG_PATH
};

function loadPostgresDriver() {
  try {
    // Optional dependency so the demo still runs without PostgreSQL locally.
    return require("pg");
  } catch (error) {
    return null;
  }
}

function getPostgresConfig() {
  if (process.env.DATABASE_URL) {
    const config = { connectionString: process.env.DATABASE_URL };
    if (shouldEnableSsl()) {
      config.ssl = { rejectUnauthorized: false };
    }
    return config;
  }

  if (process.env.PGHOST && process.env.PGUSER && process.env.PGDATABASE) {
    return {
      host: process.env.PGHOST,
      port: normalizeInteger(process.env.PGPORT) || 5432,
      user: process.env.PGUSER,
      password: process.env.PGPASSWORD || "",
      database: process.env.PGDATABASE,
      ssl: shouldEnableSsl() ? { rejectUnauthorized: false } : undefined
    };
  }

  return null;
}

function shouldEnableSsl() {
  const mode = String(process.env.PGSSLMODE || "").toLowerCase();
  return mode === "require" || mode === "prefer";
}

function ensureFileStore() {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
  ensureJsonFile(SESSION_FILE_PATH);
  ensureJsonFile(BEHAVIOR_FILE_PATH);
}

function ensureJsonFile(filePath) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, "[]\n", "utf8");
  }
}

async function upsertSessionPostgres(session) {
  await pool.query(
    `
      INSERT INTO sessions (
        session_id,
        timestamp,
        username,
        ip_address,
        country,
        city,
        browser,
        operating_system,
        user_agent,
        threat_score,
        threat_level,
        prediction,
        confidence,
        action_taken,
        verification_state,
        reason_summary,
        ai_report,
        explainability,
        automation_flags,
        bot_signal_count,
        created_at,
        updated_at
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
        $11, $12, $13, $14, $15, $16, $17::jsonb, $18::jsonb, $19::jsonb, $20, $21, $22
      )
      ON CONFLICT (session_id) DO UPDATE SET
        timestamp = EXCLUDED.timestamp,
        username = EXCLUDED.username,
        ip_address = EXCLUDED.ip_address,
        country = EXCLUDED.country,
        city = EXCLUDED.city,
        browser = EXCLUDED.browser,
        operating_system = EXCLUDED.operating_system,
        user_agent = EXCLUDED.user_agent,
        threat_score = EXCLUDED.threat_score,
        threat_level = EXCLUDED.threat_level,
        prediction = EXCLUDED.prediction,
        confidence = EXCLUDED.confidence,
        action_taken = EXCLUDED.action_taken,
        verification_state = EXCLUDED.verification_state,
        reason_summary = EXCLUDED.reason_summary,
        ai_report = EXCLUDED.ai_report,
        explainability = EXCLUDED.explainability,
        automation_flags = EXCLUDED.automation_flags,
        bot_signal_count = EXCLUDED.bot_signal_count,
        updated_at = EXCLUDED.updated_at
    `,
    [
      session.session_id,
      session.timestamp,
      session.username || "",
      session.ip_address || "",
      session.country || "",
      session.city || "",
      session.browser || "",
      session.operating_system || "",
      session.user_agent || "",
      normalizeInteger(session.threat_score),
      session.threat_level || "",
      session.prediction || "",
      normalizeInteger(session.confidence),
      session.action_taken || "",
      session.verification_state || "",
      session.reason_summary || "",
      JSON.stringify(normalizeObject(session.ai_report)),
      JSON.stringify(Array.isArray(session.explainability) ? session.explainability : []),
      JSON.stringify(Array.isArray(session.automation_flags) ? session.automation_flags : []),
      normalizeInteger(session.bot_signal_count),
      session.created_at || session.timestamp,
      session.updated_at || session.timestamp
    ]
  );
}

async function insertBehaviorEventPostgres(event) {
  await pool.query(
    `
      INSERT INTO behavior_events (
        session_id,
        mouse_movements,
        clicks,
        keystrokes,
        scroll_events,
        typing_speed,
        average_mouse_speed,
        time_to_first_click_ms,
        time_to_submit_ms,
        captcha_verified,
        otp_verified,
        attempt_index,
        raw_features,
        created_at
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14
      )
    `,
    [
      event.session_id,
      normalizeInteger(event.mouse_movements),
      normalizeInteger(event.clicks),
      normalizeInteger(event.keystrokes),
      normalizeInteger(event.scroll_events),
      normalizeDecimal(event.typing_speed),
      normalizeDecimal(event.average_mouse_speed),
      normalizeInteger(event.time_to_first_click_ms),
      normalizeInteger(event.time_to_submit_ms),
      Boolean(event.captcha_verified),
      Boolean(event.otp_verified),
      normalizeInteger(event.attempt_index),
      JSON.stringify(event.raw_features || {}),
      event.created_at
    ]
  );
}

function upsertSessionFile(session) {
  const sessions = readJsonArray(SESSION_FILE_PATH);
  const index = sessions.findIndex((item) => item.session_id === session.session_id);

  if (index >= 0) {
    sessions[index] = {
      ...sessions[index],
      ...session,
      created_at: sessions[index].created_at || session.created_at || session.timestamp,
      updated_at: session.updated_at || session.timestamp
    };
  } else {
    sessions.push({
      id: session.id || createRecordId("session"),
      ...session,
      created_at: session.created_at || session.timestamp,
      updated_at: session.updated_at || session.timestamp
    });
  }

  writeJsonArray(SESSION_FILE_PATH, sessions);
}

function insertBehaviorEventFile(event) {
  const behaviorEvents = readJsonArray(BEHAVIOR_FILE_PATH);
  behaviorEvents.push({
    id: event.id || createRecordId("behavior"),
    ...event
  });
  writeJsonArray(BEHAVIOR_FILE_PATH, behaviorEvents);
}

async function syncCsvExport() {
  const snapshot = await loadSnapshot();
  const hydrated = hydrateSessions(snapshot.sessions, snapshot.behaviorEvents);
  fs.writeFileSync(ACCESS_LOG_PATH, buildCsv(hydrated), "utf8");
}

function hydrateSessions(sessions, behaviorEvents) {
  const latestBySession = new Map();
  const countBySession = new Map();

  behaviorEvents
    .slice()
    .sort((left, right) => safeTimestamp(right.created_at) - safeTimestamp(left.created_at))
    .forEach((event) => {
      const count = countBySession.get(event.session_id) || 0;
      countBySession.set(event.session_id, count + 1);
      if (!latestBySession.has(event.session_id)) {
        latestBySession.set(event.session_id, event);
      }
    });

  return sessions
    .map((session) => ({
      ...session,
      event_count: countBySession.get(session.session_id) || 0,
      last_behavior_event: latestBySession.get(session.session_id) || null
    }))
    .sort((left, right) => safeTimestamp(right.updated_at || right.timestamp) - safeTimestamp(left.updated_at || left.timestamp));
}

function filterSessions(sessions, filters) {
  const search = String(filters.search || "").trim().toLowerCase();
  const action = String(filters.action || "").trim().toUpperCase();
  const prediction = String(filters.prediction || "").trim().toUpperCase();
  const level = String(filters.level || "").trim().toUpperCase();

  return sessions.filter((session) => {
    if (action && session.action_taken !== action) {
      return false;
    }
    if (prediction && session.prediction !== prediction) {
      return false;
    }
    if (level && session.threat_level !== level) {
      return false;
    }
    if (!search) {
      return true;
    }

    const haystack = [
      session.session_id,
      session.username,
      session.ip_address,
      session.browser,
      session.operating_system,
      session.user_agent,
      session.prediction,
      session.action_taken,
      session.reason_summary
    ]
      .join(" ")
      .toLowerCase();

    return haystack.includes(search);
  });
}

function buildCountBuckets(items, field, order) {
  return order.map((key) => ({
    key,
    count: items.filter((item) => item[field] === key).length
  }));
}

function buildTopBreakdown(items, field, limit) {
  const counts = new Map();

  items.forEach((item) => {
    const key = item[field] || "Unknown";
    counts.set(key, (counts.get(key) || 0) + 1);
  });

  return Array.from(counts.entries())
    .map(([key, count]) => ({ key, count }))
    .sort((left, right) => right.count - left.count)
    .slice(0, limit);
}

function buildDailySeries(items, predicate) {
  const counts = new Map();

  items.forEach((item) => {
    if (!predicate(item)) {
      return;
    }
    const day = formatDay(item.timestamp || item.updated_at);
    counts.set(day, (counts.get(day) || 0) + 1);
  });

  return Array.from(counts.entries())
    .map(([day, count]) => ({ day, count }))
    .sort((left, right) => left.day.localeCompare(right.day));
}

function buildCsv(items) {
  const lines = [CSV_HEADERS.join(",")];

  items.forEach((item) => {
    const row = CSV_HEADERS.map((header) => {
      if (header === "automation_flags" || header === "explainability") {
        return escapeCsv(JSON.stringify(item[header] || []));
      }
      if (header === "ai_report") {
        return escapeCsv(JSON.stringify(item[header] || {}));
      }
      return escapeCsv(item[header]);
    });
    lines.push(row.join(","));
  });

  return `${lines.join("\n")}\n`;
}

function normalizeSessionRecord(record) {
  return {
    id: record.id || createRecordId("session"),
    session_id: record.session_id || "",
    timestamp: toIsoString(record.timestamp) || new Date().toISOString(),
    username: record.username || "",
    ip_address: record.ip_address || "",
    country: record.country || "",
    city: record.city || "",
    browser: record.browser || "",
    operating_system: record.operating_system || "",
    user_agent: record.user_agent || "",
    threat_score: normalizeInteger(record.threat_score),
    threat_level: record.threat_level || "SAFE",
    prediction: record.prediction || "HUMAN",
    confidence: normalizeInteger(record.confidence),
    action_taken: record.action_taken || "ALLOW_ACCESS",
    verification_state: record.verification_state || "NONE",
    reason_summary: record.reason_summary || "",
    ai_report: normalizeObject(record.ai_report),
    explainability: normalizeArray(record.explainability),
    automation_flags: normalizeArray(record.automation_flags),
    bot_signal_count: normalizeInteger(record.bot_signal_count),
    created_at: toIsoString(record.created_at) || toIsoString(record.timestamp) || new Date().toISOString(),
    updated_at: toIsoString(record.updated_at) || toIsoString(record.timestamp) || new Date().toISOString()
  };
}

function normalizeBehaviorRecord(record) {
  return {
    id: record.id || createRecordId("behavior"),
    session_id: record.session_id || "",
    mouse_movements: normalizeInteger(record.mouse_movements),
    clicks: normalizeInteger(record.clicks),
    keystrokes: normalizeInteger(record.keystrokes),
    scroll_events: normalizeInteger(record.scroll_events),
    typing_speed: normalizeDecimal(record.typing_speed),
    average_mouse_speed: normalizeDecimal(record.average_mouse_speed),
    time_to_first_click_ms: normalizeInteger(record.time_to_first_click_ms),
    time_to_submit_ms: normalizeInteger(record.time_to_submit_ms),
    captcha_verified: Boolean(record.captcha_verified),
    otp_verified: Boolean(record.otp_verified),
    attempt_index: normalizeInteger(record.attempt_index),
    raw_features: record.raw_features && typeof record.raw_features === "object"
      ? record.raw_features
      : {},
    created_at: toIsoString(record.created_at) || new Date().toISOString()
  };
}

function readJsonArray(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      ensureJsonFile(filePath);
      return [];
    }

    const content = fs.readFileSync(filePath, "utf8").trim();
    if (!content) {
      return [];
    }
    const parsed = JSON.parse(content);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.error(`Failed to read ${filePath}`, error);
    return [];
  }
}

function writeJsonArray(filePath, data) {
  fs.writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
}

function createRecordId(prefix) {
  if (typeof crypto.randomUUID === "function") {
    return `${prefix}_${crypto.randomUUID()}`;
  }
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function normalizeArray(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
      return value ? [value] : [];
    }
  }
  return [];
}

function normalizeObject(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value;
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch (error) {
      return {};
    }
  }
  return {};
}

function escapeCsv(value) {
  if (value === null || value === undefined) {
    return "";
  }

  const stringValue = String(value);
  if (stringValue.includes(",") || stringValue.includes('"') || stringValue.includes("\n")) {
    return `"${stringValue.replace(/"/g, '""')}"`;
  }
  return stringValue;
}

function normalizePage(value) {
  const parsed = normalizeInteger(value);
  return parsed > 0 ? parsed : 1;
}

function normalizePageSize(value) {
  const parsed = normalizeInteger(value);
  if (!parsed) {
    return DEFAULT_PAGE_SIZE;
  }
  return Math.max(1, Math.min(MAX_PAGE_SIZE, parsed));
}

function normalizeInteger(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

function normalizeDecimal(value) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? Number(parsed.toFixed(2)) : 0;
}

function safeTimestamp(value) {
  const date = value ? new Date(value) : null;
  const timestamp = date ? date.getTime() : Number.NaN;
  return Number.isFinite(timestamp) ? timestamp : 0;
}

function toIsoString(value) {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return date.toISOString();
}

function formatDay(value) {
  const iso = toIsoString(value);
  return iso ? iso.slice(0, 10) : "Unknown";
}

function isPrivateOrLoopbackIp(value) {
  const ip = String(value || "").replace(/^::ffff:/, "");
  if (!ip) {
    return true;
  }
  if (ip === "::1" || ip === "127.0.0.1" || ip.startsWith("127.")) {
    return true;
  }
  if (ip.startsWith("10.") || ip.startsWith("192.168.")) {
    return true;
  }
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) {
    return true;
  }
  return false;
}
