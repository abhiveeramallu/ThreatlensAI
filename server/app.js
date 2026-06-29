const crypto = require("crypto");
const path = require("path");
const express = require("express");
const { spawn } = require("child_process");

const { scoreAttempt } = require("./aiScoring");
const { generateThreatReport } = require("./geminiThreatAnalyst");
const {
  initializeStore,
  getStoreInfo,
  saveSecurityEvent,
  listSessions,
  getDashboardData,
  exportSessionsCsv,
  getRiskContext
} = require("./storage");

const app = express();
const botRunState = {
  status: "idle",
  startedAt: null,
  finishedAt: null,
  exitCode: null,
  logs: []
};
const challengeRegistry = new Map();
const simulationClients = new Set();
const liveState = {
  events: [],
  sessions: [],
  activeSimulations: 0,
  metrics: {
    botDetections: 0,
    humanSessions: 0,
    blockedSessions: 0,
    averageRiskScore: 0
  }
};
const MAX_CAPTCHA_ATTEMPTS = 3;
const MAX_OTP_ATTEMPTS = 3;

initializeStore().catch((error) => {
  console.error("Storage initialization failed.", error);
});

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "..", "public")));

app.get("/api/health", async (req, res) => {
  const storage = await getStoreInfo();
  res.json({
    status: "ok",
    storage,
    live: {
      activeSimulations: liveState.activeSimulations,
      sessionCount: liveState.sessions.length,
      eventCount: liveState.events.length
    }
  });
});

app.get("/api/live-events", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  const client = res;
  simulationClients.add(client);
  client.write(`data: ${JSON.stringify({ type: "snapshot", payload: buildLiveSnapshot() })}\n\n`);

  req.on("close", () => {
    simulationClients.delete(client);
  });
});

app.get("/api/current-events", (req, res) => {
  res.json({
    items: liveState.events.slice(0, 50),
    activeSimulations: liveState.activeSimulations
  });
});

app.get("/api/current-sessions", (req, res) => {
  res.json({
    items: liveState.sessions.slice(0, 20),
    activeSimulations: liveState.activeSimulations,
    metrics: liveState.metrics
  });
});

app.post("/api/reset-demo", (req, res) => {
  liveState.events = [];
  liveState.sessions = [];
  liveState.activeSimulations = 0;
  liveState.metrics = {
    botDetections: 0,
    humanSessions: 0,
    blockedSessions: 0,
    averageRiskScore: 0
  };
  broadcastLive("reset", buildLiveSnapshot());
  res.json({ message: "Live simulation state cleared." });
});


app.post("/api/simulations/suspicious", async (req, res) => {
  const accepted = startSimulation("suspicious", buildSimulationProfile("suspicious"));
  if (!accepted) {
    return res.status(409).json({ message: "Simulation already running for this actor." });
  }
  return res.json({ message: "Suspicious simulation started." });
});

app.post("/api/simulations/selenium", async (req, res) => {
  const accepted = startSimulation("selenium", buildSimulationProfile("selenium"));
  if (!accepted) {
    return res.status(409).json({ message: "Simulation already running for this actor." });
  }
  return res.json({ message: "Selenium simulation started." });
});

app.post("/api/simulations/playwright", async (req, res) => {
  const accepted = startSimulation("playwright", buildSimulationProfile("playwright"));
  if (!accepted) {
    return res.status(409).json({ message: "Simulation already running for this actor." });
  }
  return res.json({ message: "Playwright simulation started." });
});

app.post("/api/simulations/puppeteer", async (req, res) => {
  const accepted = startSimulation("puppeteer", buildSimulationProfile("puppeteer"));
  if (!accepted) {
    return res.status(409).json({ message: "Simulation already running for this actor." });
  }
  return res.json({ message: "Puppeteer simulation started." });
});

app.post("/api/login", async (req, res) => {
  try {
    pruneChallengeRegistry();

    const payload = req.body || {};
    const sessionId = sanitizeSessionId(payload.sessionId) || createSessionId();
    const username = sanitizeUsername(payload.username);
    const fingerprint = payload.fingerprint || {};
    const behavior = payload.behavior || {};
    const timingMs = behavior.timingMs || {};
    const trapClicked = Boolean(payload.trapClicked);
    const automationSignals = normalizeAutomationSignals(payload.automationSignals);

    const botDetectDecision = normalizeBotDetectDecision(payload.botDetect?.decision ?? payload.botDetectDecision);
    const botSignals = Array.isArray(payload.botDetect?.results)
      ? payload.botDetect.results
      : Array.isArray(payload.botDetectResults)
        ? payload.botDetectResults
        : [];
    const botSignalCount = countBotSignals(botSignals);
    const botDetectFlags = summarizeBotDetect(botSignals);

    const ipAddress = getClientIp(req);
    const location = { country: "Unknown", city: "Unknown" };
    const riskContext = await getRiskContext({ sessionId, ipAddress });
    const challengeState = getChallengeState(sessionId);
    const submittedChallengeState = resolveSubmittedChallenges(sessionId, payload);

    const scoring = scoreAttempt({
      botDetectDecision,
      botSignalCount,
      botSignals: botDetectFlags,
      automationSignals,
      trapClicked,
      timingMs,
      mouseMoveCount: normalizeInteger(behavior.mouseMoveCount),
      clickCount: normalizeInteger(behavior.clickCount),
      scrollCount: normalizeInteger(behavior.scrollCount),
      keystrokeCount: normalizeInteger(behavior.keystrokeCount),
      typingDurationMs: normalizeInteger(behavior.typingDurationMs),
      averageMouseSpeed: normalizeDecimal(behavior.averageMouseSpeed),
      fingerprint,
      riskContext,
      challengeState: {
        ...submittedChallengeState,
        failedCaptchaAttempts: challengeState.failedCaptchaAttempts,
        failedOtpAttempts: challengeState.failedOtpAttempts
      }
    });

    const decision = resolveSecurityDecision({
      sessionId,
      scoring,
      trapClicked,
      submittedChallengeState
    });
    const aiReport = await generateThreatReport(buildThreatReportInput({
      scoring,
      action: decision.action,
      behavior,
      verificationState: decision.verificationState,
      submittedChallengeState
    }));

    const timestamp = new Date().toISOString();
    const platform = parseUserAgent(fingerprint.userAgent);
    const automationFlags = summarizeAutomationFlags({
      automationSignals,
      botDetectDecision,
      botSignalCount
    });

    await saveSecurityEvent({
      session: {
        session_id: sessionId,
        timestamp,
        username,
        ip_address: ipAddress,
        country: location.country,
        city: location.city,
        browser: platform.browser,
        operating_system: platform.operatingSystem,
        user_agent: fingerprint.userAgent || "",
        threat_score: scoring.score,
        threat_level: scoring.level,
        prediction: scoring.prediction,
        confidence: scoring.confidence,
        action_taken: decision.action,
        verification_state: decision.verificationState,
        reason_summary: buildReasonSummary(scoring.explainability, decision.action, decision.verificationState),
        ai_report: aiReport,
        explainability: scoring.explainability,
        automation_flags: automationFlags,
        bot_signal_count: botSignalCount,
        updated_at: timestamp
      },
      behaviorEvent: {
        session_id: sessionId,
        mouse_movements: normalizeInteger(behavior.mouseMoveCount),
        clicks: normalizeInteger(behavior.clickCount),
        keystrokes: normalizeInteger(behavior.keystrokeCount),
        scroll_events: normalizeInteger(behavior.scrollCount),
        typing_speed: scoring.telemetry.typing_cps,
        average_mouse_speed: normalizeDecimal(behavior.averageMouseSpeed),
        time_to_first_click_ms: normalizeInteger(timingMs.timeToFirstClickMs),
        time_to_submit_ms: normalizeInteger(timingMs.timeToSubmitMs),
        captcha_verified: Boolean(submittedChallengeState.captchaVerified),
        otp_verified: Boolean(submittedChallengeState.otpVerified),
        attempt_index: normalizeInteger(riskContext.recentSessionAttempts) + 1,
        raw_features: {
          bot_detect_decision: botDetectDecision,
          bot_detect_flags: botDetectFlags,
          automation_signals: automationSignals,
          challenge_state: submittedChallengeState,
          telemetry: scoring.telemetry,
          fingerprint: {
            user_agent: fingerprint.userAgent || "",
            platform: fingerprint.platform || "",
            language: fingerprint.language || "",
            timezone: fingerprint.timezone || ""
          }
        },
        created_at: timestamp
      }
    });

    res.json({
      sessionId,
      status: decision.status,
      decision: decision.result,
      action: decision.action,
      verificationState: decision.verificationState,
      threat: {
        score: scoring.score,
        level: scoring.level,
        confidence: scoring.confidence,
        prediction: scoring.prediction
      },
      aiReport,
      explainability: scoring.explainability,
      challenge: decision.challenge || null,
      userMessage: decision.userMessage,
      userReason: decision.userReason
    });
  } catch (error) {
    console.error("Login analysis failed.", error);
    res.status(500).json({
      status: "error",
      userMessage: "Security analysis failed.",
      userReason: "Please try again in a moment."
    });
  }
});

app.get("/api/logs", async (req, res) => {
  try {
    const result = await listSessions({
      search: req.query.search,
      action: req.query.action,
      prediction: req.query.prediction,
      level: req.query.level,
      page: req.query.page,
      pageSize: req.query.pageSize
    });

    res.json({
      ...result,
      storage: await getStoreInfo()
    });
  } catch (error) {
    console.error("Failed to load sessions.", error);
    res.status(500).json({
      items: [],
      total: 0,
      page: 1,
      pageSize: 12,
      totalPages: 1
    });
  }
});

app.get("/api/logs/export", async (req, res) => {
  try {
    const csv = await exportSessionsCsv({
      search: req.query.search,
      action: req.query.action,
      prediction: req.query.prediction,
      level: req.query.level
    });

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=\"security-sessions.csv\"");
    res.send(csv);
  } catch (error) {
    console.error("Failed to export sessions.", error);
    res.status(500).send("export_failed");
  }
});

app.get("/api/dashboard", async (req, res) => {
  try {
    const dashboard = await getDashboardData({
      search: req.query.search,
      action: req.query.action,
      prediction: req.query.prediction,
      level: req.query.level
    });

    res.json(dashboard);
  } catch (error) {
    console.error("Failed to load dashboard data.", error);
    res.status(500).json({
      metrics: {
        total_sessions: 0,
        total_humans: 0,
        total_bots: 0,
        total_blocks: 0,
        average_threat_score: 0
      },
      distributions: {
        threat_levels: [],
        action_counts: [],
        browser_breakdown: []
      },
      trends: {
        detections_per_day: [],
        blocks_per_day: []
      },
      ratio: {
        humans: 0,
        bots: 0
      },
      recent_sessions: []
    });
  }
});

app.post("/api/run-bots", (req, res) => {
  const allowBotRun = process.env.ALLOW_BOT_RUN === "true"
    || (!process.env.VERCEL && process.env.NODE_ENV !== "production");

  if (!allowBotRun) {
    return res.status(403).json({
      message: "Bot test disabled.",
      reason: "Enable ALLOW_BOT_RUN=true for local demos."
    });
  }

  if (botRunState.status === "running") {
    return res.status(409).json({
      message: "Bot test already running.",
      reason: "Please wait for the current run to finish."
    });
  }

  const baseUrl = buildBaseUrl(req);
  const scriptPath = path.join(__dirname, "..", "bots", "run-all.js");
  const env = {
    ...process.env,
    BOT_TARGET_URL: baseUrl,
    BOT_TIMEOUT_MS: process.env.BOT_TIMEOUT_MS || "60000"
  };

  botRunState.status = "running";
  botRunState.startedAt = new Date().toISOString();
  botRunState.finishedAt = null;
  botRunState.exitCode = null;
  botRunState.logs = [`Bot run started for ${baseUrl}`];

  const child = spawn(process.execPath, [scriptPath], {
    env,
    stdio: ["ignore", "pipe", "pipe"]
  });

  child.stdout.on("data", (data) => {
    const lines = String(data).split("\n").map((line) => line.trim()).filter(Boolean);
    pushBotLogs(lines);
    lines.forEach((line) => console.log(`[bot-runner] ${line}`));
  });

  child.stderr.on("data", (data) => {
    const lines = String(data).split("\n").map((line) => line.trim()).filter(Boolean);
    pushBotLogs(lines);
    lines.forEach((line) => console.error(`[bot-runner] ${line}`));
  });

  child.on("close", (code) => {
    botRunState.status = code === 0 ? "completed" : "failed";
    botRunState.finishedAt = new Date().toISOString();
    botRunState.exitCode = code;
    pushBotLogs([`Bot run ${code === 0 ? "completed" : "failed"} (exit ${code}).`]);
    if (code !== 0) {
      console.error(`Bot run exited with code ${code}`);
    }
  });

  return res.json({
    message: "Bot test started.",
    target: baseUrl
  });
});

app.get("/api/bot-status", (req, res) => {
  const allowBotRun = process.env.ALLOW_BOT_RUN === "true"
    || (!process.env.VERCEL && process.env.NODE_ENV !== "production");

  res.json({
    allowed: allowBotRun,
    status: botRunState.status,
    startedAt: botRunState.startedAt,
    finishedAt: botRunState.finishedAt,
    exitCode: botRunState.exitCode,
    logs: botRunState.logs
  });
});

module.exports = app;

function startSimulation(type, profile) {
  const label = String(type || "").toLowerCase();
  const running = liveState.sessions.some((item) => item.attackType === label && item.status === "running");
  if (running) {
    return false;
  }

  const simulationId = createSessionId();
  const startedAt = new Date().toISOString();
  const timeline = buildSimulationTimeline(profile);

  liveState.activeSimulations += 1;
  const session = {
    simulationId,
    sessionId: simulationId,
    attackType: label,
    status: "running",
    riskScore: 0,
    classification: "PENDING",
    action: "ANALYZING",
    confidence: 0,
    timestamp: startedAt,
    startedAt,
    explainability: [],
    threatLevel: "SAFE"
  };

  liveState.sessions.unshift(session);
  liveState.sessions = liveState.sessions.slice(0, 20);
  broadcastLive("simulation_started", { session });

  let offsetMs = 0;
  timeline.forEach((step, index) => {
    offsetMs += step.delayMs;
    setTimeout(async () => {
      if (index === timeline.length - 1) {
        await finalizeSimulation(session, profile, step.message);
        return;
      }

      pushLiveEvent({
        sessionId: session.sessionId,
        attackType: session.attackType,
        message: step.message,
        tone: step.tone || "info"
      });
    }, offsetMs);
  });

  return true;
}

async function finalizeSimulation(session, profile, finalMessage) {
  const scoring = scoreAttempt({
    botDetectDecision: profile.botDetectDecision,
    botSignalCount: profile.botSignalCount,
    botSignals: profile.botSignals,
    automationSignals: profile.automationSignals,
    trapClicked: Boolean(profile.trapClicked),
    timingMs: profile.behavior.timingMs,
    mouseMoveCount: profile.behavior.mouseMoveCount,
    clickCount: profile.behavior.clickCount,
    scrollCount: profile.behavior.scrollCount,
    keystrokeCount: profile.behavior.keystrokeCount,
    typingDurationMs: profile.behavior.typingDurationMs,
    averageMouseSpeed: profile.behavior.averageMouseSpeed,
    fingerprint: profile.fingerprint,
    riskContext: { recentSessionAttempts: 0, recentIpSessions: 0, blockedFromIp: 0 },
    challengeState: {
      captchaVerified: false,
      otpVerified: false,
      failedCaptchaAttempts: 0,
      failedOtpAttempts: 0
    }
  });

  const action = actionForLevel(scoring.level);
  const verificationState = verificationStateForAction(action);
  const aiReport = await generateThreatReport(buildThreatReportInput({
    scoring,
    action,
    behavior: profile.behavior,
    verificationState,
    submittedChallengeState: {
      captchaVerified: false,
      otpVerified: false
    }
  }));
  const timestamp = new Date().toISOString();
  const sessionRecord = {
    session_id: session.sessionId,
    timestamp,
    username: profile.username,
    ip_address: profile.ipAddress,
    country: "Local Demo",
    city: "Simulation Lab",
    browser: profile.browser,
    operating_system: profile.operatingSystem,
    user_agent: profile.fingerprint.userAgent,
    threat_score: scoring.score,
    threat_level: scoring.level,
    prediction: scoring.prediction,
    confidence: scoring.confidence,
    action_taken: action,
    verification_state: verificationState,
    reason_summary: buildReasonSummary(scoring.explainability, action, verificationState),
    ai_report: aiReport,
    explainability: scoring.explainability,
    automation_flags: profile.automationFlags,
    bot_signal_count: profile.botSignalCount,
    updated_at: timestamp
  };
  const behaviorRecord = {
    session_id: session.sessionId,
    mouse_movements: profile.behavior.mouseMoveCount,
    clicks: profile.behavior.clickCount,
    keystrokes: profile.behavior.keystrokeCount,
    scroll_events: profile.behavior.scrollCount,
    typing_speed: scoring.telemetry.typing_cps,
    average_mouse_speed: profile.behavior.averageMouseSpeed,
    time_to_first_click_ms: profile.behavior.timingMs.timeToFirstClickMs,
    time_to_submit_ms: profile.behavior.timingMs.timeToSubmitMs,
    captcha_verified: action === "ALLOW_ACCESS" && scoring.level === "SUSPICIOUS",
    otp_verified: action === "ALLOW_ACCESS" && scoring.level === "HIGH_RISK",
    attempt_index: 1,
    raw_features: {
      simulation: true,
      attack_type: profile.attackType,
      automation_signals: profile.automationSignals,
      telemetry: scoring.telemetry
    },
    created_at: timestamp
  };

  await saveSecurityEvent({
    session: sessionRecord,
    behaviorEvent: behaviorRecord
  });

  session.status = "completed";
  session.riskScore = scoring.score;
  session.classification = scoring.prediction;
  session.action = action;
  session.confidence = scoring.confidence;
  session.timestamp = timestamp;
  session.explainability = scoring.explainability;
  session.threatLevel = scoring.level;
  session.reasonSummary = sessionRecord.reason_summary;
  session.aiReport = aiReport;

  liveState.activeSimulations = Math.max(0, liveState.activeSimulations - 1);
  recomputeLiveMetrics();

  pushLiveEvent({
    sessionId: session.sessionId,
    attackType: session.attackType,
    message: `Risk Score = ${scoring.score}`,
    tone: scoring.prediction === "BOT" ? "critical" : "safe"
  });
  pushLiveEvent({
    sessionId: session.sessionId,
    attackType: session.attackType,
    message: `Classification = ${scoring.prediction}`,
    tone: scoring.prediction === "BOT" ? "critical" : "safe"
  });
  pushLiveEvent({
    sessionId: session.sessionId,
    attackType: session.attackType,
    message: `Action = ${actionForLabel(action)}`,
    tone: action === "BLOCK_SESSION" ? "critical" : action === "ALLOW_ACCESS" ? "safe" : "warning"
  });
  pushLiveEvent({
    sessionId: session.sessionId,
    attackType: session.attackType,
    message: finalMessage || "Simulation Complete",
    tone: "info"
  });

  broadcastLive("simulation_completed", { session, metrics: liveState.metrics });
}

function buildSimulationProfile(type) {
  const base = {
    human: {
      attackType: "human",
      username: "human_analyst",
      browser: "Chrome",
      operatingSystem: "macOS",
      ipAddress: "127.0.0.1",
      botDetectDecision: "human",
      botSignalCount: 0,
      botSignals: [],
      automationFlags: [],
      automationSignals: {
        webdriver: false,
        headlessUA: false,
        suspiciousUserAgent: false,
        pluginsLength: 5,
        languagesLength: 2,
        frameworks: { selenium: false, playwright: false, puppeteer: false }
      },
      fingerprint: {
        userAgent: "Mozilla/5.0 Human Demo Chrome",
        platform: "MacIntel",
        language: "en-US",
        timezone: "UTC"
      },
      behavior: {
        timingMs: { timeToFirstClickMs: 1100, timeToSubmitMs: 4200 },
        mouseMoveCount: 28,
        clickCount: 3,
        scrollCount: 2,
        keystrokeCount: 18,
        typingDurationMs: 3200,
        averageMouseSpeed: 540
      }
    },
    suspicious: {
      attackType: "suspicious",
      username: "suspicious_session",
      browser: "Chrome",
      operatingSystem: "Windows",
      ipAddress: "127.0.0.1",
      botDetectDecision: "unknown",
      botSignalCount: 0,
      botSignals: [],
      automationFlags: ["rapid-submit", "low-mouse-activity"],
      automationSignals: {
        webdriver: false,
        headlessUA: false,
        suspiciousUserAgent: false,
        pluginsLength: 2,
        languagesLength: 1,
        frameworks: { selenium: false, playwright: false, puppeteer: false }
      },
      fingerprint: {
        userAgent: "Mozilla/5.0 Suspicious Demo Chrome",
        platform: "Win32",
        language: "en-US",
        timezone: "UTC"
      },
      behavior: {
        timingMs: { timeToFirstClickMs: 220, timeToSubmitMs: 760 },
        mouseMoveCount: 2,
        clickCount: 1,
        scrollCount: 0,
        keystrokeCount: 14,
        typingDurationMs: 760,
        averageMouseSpeed: 38
      }
    },
    selenium: {
      attackType: "selenium",
      username: "selenium_bot",
      browser: "Chrome",
      operatingSystem: "Linux",
      ipAddress: "127.0.0.1",
      botDetectDecision: "bot",
      botSignalCount: 3,
      botSignals: ["webdriver", "chrome_driver", "cdc_signature"],
      automationFlags: ["bot-detect", "webdriver", "selenium"],
      automationSignals: {
        webdriver: true,
        headlessUA: true,
        suspiciousUserAgent: true,
        pluginsLength: 0,
        languagesLength: 0,
        frameworks: { selenium: true, playwright: false, puppeteer: false }
      },
      fingerprint: {
        userAgent: "Mozilla/5.0 HeadlessChrome Selenium",
        platform: "Linux x86_64",
        language: "en-US",
        timezone: "UTC"
      },
      behavior: {
        timingMs: { timeToFirstClickMs: 90, timeToSubmitMs: 540 },
        mouseMoveCount: 0,
        clickCount: 1,
        scrollCount: 0,
        keystrokeCount: 14,
        typingDurationMs: 520,
        averageMouseSpeed: 0
      }
    },
    playwright: {
      attackType: "playwright",
      username: "playwright_bot",
      browser: "Chromium",
      operatingSystem: "Linux",
      ipAddress: "127.0.0.1",
      botDetectDecision: "bot",
      botSignalCount: 3,
      botSignals: ["playwright_binding", "headless", "stealth_mismatch"],
      automationFlags: ["bot-detect", "headless", "playwright"],
      automationSignals: {
        webdriver: true,
        headlessUA: true,
        suspiciousUserAgent: true,
        pluginsLength: 0,
        languagesLength: 1,
        frameworks: { selenium: false, playwright: true, puppeteer: false }
      },
      fingerprint: {
        userAgent: "Mozilla/5.0 HeadlessChrome Playwright",
        platform: "Linux x86_64",
        language: "en-US",
        timezone: "UTC"
      },
      behavior: {
        timingMs: { timeToFirstClickMs: 120, timeToSubmitMs: 680 },
        mouseMoveCount: 1,
        clickCount: 1,
        scrollCount: 0,
        keystrokeCount: 16,
        typingDurationMs: 700,
        averageMouseSpeed: 40
      }
    },
    puppeteer: {
      attackType: "puppeteer",
      username: "puppeteer_bot",
      browser: "Chromium",
      operatingSystem: "Linux",
      ipAddress: "127.0.0.1",
      botDetectDecision: "bot",
      botSignalCount: 3,
      botSignals: ["headless_chrome", "automation_evaluation", "pptr_runtime"],
      automationFlags: ["bot-detect", "headless", "puppeteer"],
      automationSignals: {
        webdriver: true,
        headlessUA: true,
        suspiciousUserAgent: true,
        pluginsLength: 0,
        languagesLength: 0,
        frameworks: { selenium: false, playwright: false, puppeteer: true }
      },
      fingerprint: {
        userAgent: "Mozilla/5.0 HeadlessChrome Puppeteer",
        platform: "Linux x86_64",
        language: "en-US",
        timezone: "UTC"
      },
      behavior: {
        timingMs: { timeToFirstClickMs: 100, timeToSubmitMs: 610 },
        mouseMoveCount: 0,
        clickCount: 1,
        scrollCount: 0,
        keystrokeCount: 12,
        typingDurationMs: 480,
        averageMouseSpeed: 0
      }
    }
  };

  return base[type];
}

function buildSimulationTimeline(profile) {
  const actor = titleize(profile.attackType);
  const detectionMessage = profile.attackType === "human"
    ? "Behavior looks human"
    : profile.attackType === "suspicious"
      ? "Low mouse activity and rapid submission detected"
      : `${actor} artifacts detected`;

  return [
    { message: "Simulation Started", delayMs: 150, tone: "info" },
    { message: `Launching ${actor}`, delayMs: 400, tone: "info" },
    { message: "Opening Demo Login", delayMs: 500, tone: "info" },
    { message: "Analyzing Browser Signals", delayMs: 550, tone: "info" },
    { message: detectionMessage, delayMs: 650, tone: profile.attackType === "human" ? "safe" : "warning" },
    { message: "Calculating Threat Score", delayMs: 600, tone: "info" },
    { message: "Generating AI Threat Assessment", delayMs: 550, tone: "info" },
    { message: "Classification Complete", delayMs: 500, tone: "info" },
    { message: "Response Action Applied", delayMs: 450, tone: "info" },
    { message: "Simulation Finished", delayMs: 450, tone: "info" }
  ];
}

function pushLiveEvent(event) {
  const payload = {
    id: createSessionId(),
    timestamp: new Date().toISOString(),
    ...event
  };
  liveState.events.unshift(payload);
  liveState.events = liveState.events.slice(0, 80);
  broadcastLive("event", payload);
}

function buildLiveSnapshot() {
  return {
    events: liveState.events.slice(0, 50),
    sessions: liveState.sessions.slice(0, 20),
    activeSimulations: liveState.activeSimulations,
    metrics: liveState.metrics
  };
}

function broadcastLive(type, payload) {
  const message = `data: ${JSON.stringify({ type, payload })}\n\n`;
  simulationClients.forEach((client) => {
    client.write(message);
  });
}

function recomputeLiveMetrics() {
  const completed = liveState.sessions.filter((item) => item.status === "completed");
  const total = completed.length || 1;
  liveState.metrics = {
    botDetections: completed.filter((item) => item.classification === "BOT").length,
    humanSessions: completed.filter((item) => item.classification === "HUMAN").length,
    blockedSessions: completed.filter((item) => item.action === "BLOCK_SESSION").length,
    averageRiskScore: completed.length
      ? Math.round(completed.reduce((sum, item) => sum + Number(item.riskScore || 0), 0) / completed.length)
      : 0
  };
  broadcastLive("metrics", {
    metrics: liveState.metrics,
    activeSimulations: liveState.activeSimulations,
    sessions: liveState.sessions.slice(0, 20)
  });
}

function actionForLevel(level) {
  if (level === "CRITICAL") return "BLOCK_SESSION";
  if (level === "HIGH_RISK") return "REQUIRE_OTP";
  if (level === "SUSPICIOUS") return "SHOW_CAPTCHA";
  return "ALLOW_ACCESS";
}

function verificationStateForAction(action) {
  if (action === "BLOCK_SESSION") return "BLOCKED";
  if (action === "REQUIRE_OTP") return "OTP_REQUIRED";
  if (action === "SHOW_CAPTCHA") return "CAPTCHA_REQUIRED";
  return "NONE";
}

function actionForLabel(action) {
  const mapping = {
    ALLOW_ACCESS: "ALLOW",
    SHOW_CAPTCHA: "CAPTCHA",
    REQUIRE_OTP: "OTP",
    BLOCK_SESSION: "BLOCK"
  };
  return mapping[action] || action;
}

function titleize(value) {
  return String(value || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function sanitizeUsername(username) {
  if (!username || typeof username !== "string") {
    return "anonymous";
  }
  return username.trim().slice(0, 64);
}

function sanitizeSessionId(value) {
  if (!value || typeof value !== "string") {
    return "";
  }
  return value.trim().replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 80);
}

function createSessionId() {
  if (typeof crypto.randomUUID === "function") {
    return `sess_${crypto.randomUUID()}`;
  }
  return `sess_${crypto.randomBytes(8).toString("hex")}`;
}

function normalizeBotDetectDecision(decision) {
  if (!decision) {
    return "unknown";
  }
  if (typeof decision === "string") {
    return decision.toLowerCase();
  }
  if (typeof decision === "boolean") {
    return decision ? "bot" : "human";
  }
  if (typeof decision === "object") {
    if (decision.bot === true) return "bot";
    if (decision.human === true) return "human";
    if (decision.result) return String(decision.result).toLowerCase();
  }
  return "unknown";
}

function countBotSignals(results) {
  if (!Array.isArray(results)) {
    return 0;
  }

  return results.reduce((count, item) => {
    if (!item) return count;
    if (item.bot === true || item.bot === "true") return count + 1;
    if (item.result === "bot" || item.state === "bot") return count + 1;
    if (typeof item.score === "number" && item.score >= 1) return count + 1;
    return count;
  }, 0);
}

function summarizeBotDetect(results) {
  if (!Array.isArray(results)) {
    return [];
  }

  return results
    .filter((item) => {
      if (!item) return false;
      if (item.bot === true || item.bot === "true") return true;
      if (item.result === "bot" || item.state === "bot") return true;
      if (typeof item.score === "number" && item.score >= 1) return true;
      return false;
    })
    .map((item) => {
      const label = item.name || item.type || item.key || item.id || item.rule || item.title;
      if (label) {
        if (item.value !== undefined) return `${label}=${item.value}`;
        return String(label);
      }
      return JSON.stringify(item).slice(0, 80);
    });
}

function normalizeAutomationSignals(signals = {}) {
  const frameworks = signals.frameworks || {};
  const userAgent = String(signals.userAgent || "");

  return {
    webdriver: signals.webdriver === true,
    headlessUA: signals.headlessUA === true,
    pluginsLength: normalizeInteger(signals.pluginsLength),
    languagesLength: normalizeInteger(signals.languagesLength),
    suspiciousUserAgent: signals.suspiciousUserAgent === true || /Headless|PhantomJS|Electron|curl|wget/i.test(userAgent),
    frameworks: {
      selenium: frameworks.selenium === true,
      playwright: frameworks.playwright === true,
      puppeteer: frameworks.puppeteer === true
    }
  };
}

function summarizeAutomationFlags({ automationSignals, botDetectDecision, botSignalCount }) {
  const flags = [];

  if (botDetectDecision === "bot") {
    flags.push("bot-detect");
  }

  if (botSignalCount > 0) {
    flags.push(`signals:${botSignalCount}`);
  }

  if (automationSignals.webdriver) flags.push("webdriver");
  if (automationSignals.headlessUA) flags.push("headless");
  if (automationSignals.suspiciousUserAgent) flags.push("suspicious-ua");
  if (automationSignals.frameworks.selenium) flags.push("selenium");
  if (automationSignals.frameworks.playwright) flags.push("playwright");
  if (automationSignals.frameworks.puppeteer) flags.push("puppeteer");

  return flags;
}

function resolveSecurityDecision({ sessionId, scoring, trapClicked, submittedChallengeState }) {
  const state = getChallengeState(sessionId);

  if (trapClicked || submittedChallengeState.honeypotTriggered) {
    state.blocked = true;
  }

  const repeatedCaptchaFailures = state.failedCaptchaAttempts >= MAX_CAPTCHA_ATTEMPTS;
  const repeatedOtpFailures = state.failedOtpAttempts >= MAX_OTP_ATTEMPTS;

  if (state.blocked || scoring.level === "CRITICAL" || repeatedCaptchaFailures || repeatedOtpFailures) {
    state.blocked = true;
    return {
      status: "blocked",
      result: "BLOCKED",
      action: "BLOCK_SESSION",
      verificationState: "BLOCKED",
      userMessage: "Session blocked.",
      userReason: repeatedOtpFailures || repeatedCaptchaFailures
        ? "Repeated verification failures triggered an automated block."
        : "Critical automation risk was detected."
    };
  }

  if (scoring.level === "HIGH_RISK") {
    if (submittedChallengeState.otpVerified) {
      clearChallenges(sessionId);
      return {
        status: "allowed",
        result: "ACCEPTED",
        action: "ALLOW_ACCESS",
        verificationState: "OTP_VERIFIED",
        userMessage: "OTP verification succeeded.",
        userReason: "High-risk access was allowed only after the one-time code check."
      };
    }

    const otpChallenge = ensureOtpChallenge(sessionId);
    return {
      status: "challenge_required",
      result: "PENDING",
      action: "REQUIRE_OTP",
      verificationState: "OTP_REQUIRED",
      userMessage: "One-time code required.",
      userReason: submittedChallengeState.otpSubmitted
        ? "The code did not match. Please try the latest OTP."
        : "High-risk sessions must complete one-time verification.",
      challenge: {
        type: "otp",
        prompt: "Enter the 6-digit verification code.",
        demoCode: otpChallenge.code,
        expiresAt: otpChallenge.expiresAt,
        attemptsRemaining: Math.max(0, MAX_OTP_ATTEMPTS - state.failedOtpAttempts)
      }
    };
  }

  if (scoring.level === "SUSPICIOUS") {
    if (submittedChallengeState.captchaVerified) {
      clearChallenges(sessionId);
      return {
        status: "allowed",
        result: "ACCEPTED",
        action: "ALLOW_ACCESS",
        verificationState: "CAPTCHA_VERIFIED",
        userMessage: "Verification complete.",
        userReason: "The session passed the additional CAPTCHA challenge."
      };
    }

    const captchaChallenge = ensureCaptchaChallenge(sessionId);
    return {
      status: "challenge_required",
      result: "PENDING",
      action: "SHOW_CAPTCHA",
      verificationState: "CAPTCHA_REQUIRED",
      userMessage: "Additional verification required.",
      userReason: submittedChallengeState.captchaSubmitted
        ? "The challenge answer did not match. Please try the refreshed CAPTCHA."
        : "Suspicious sessions must complete a CAPTCHA before access is allowed.",
      challenge: {
        type: "captcha",
        prompt: captchaChallenge.prompt,
        challengeType: captchaChallenge.type,
        expiresAt: captchaChallenge.expiresAt,
        attemptsRemaining: Math.max(0, MAX_CAPTCHA_ATTEMPTS - state.failedCaptchaAttempts)
      }
    };
  }

  clearChallenges(sessionId);
  return {
    status: "allowed",
    result: "ACCEPTED",
    action: "ALLOW_ACCESS",
    verificationState: "NONE",
    userMessage: "Access allowed.",
    userReason: "The session stayed within the safe threat threshold."
  };
}

function resolveSubmittedChallenges(sessionId, payload) {
  const state = getChallengeState(sessionId);
  const result = {
    captchaSubmitted: false,
    captchaVerified: false,
    otpSubmitted: false,
    otpVerified: false,
    honeypotTriggered: Boolean(payload.captcha?.honeypotTriggered),
    failedCaptchaAttempts: state.failedCaptchaAttempts,
    failedOtpAttempts: state.failedOtpAttempts
  };

  if (result.honeypotTriggered) {
    state.failedCaptchaAttempts += 1;
    result.failedCaptchaAttempts = state.failedCaptchaAttempts;
  }

  const captchaAnswer = String(payload.captcha?.answer || "").trim();
  if (captchaAnswer) {
    result.captchaSubmitted = true;
    const challenge = state.captcha;
    const stillValid = challenge && new Date(challenge.expiresAt).getTime() > Date.now();

    if (stillValid && normalizeAnswer(captchaAnswer) === normalizeAnswer(challenge.answer) && !result.honeypotTriggered) {
      result.captchaVerified = true;
      state.captcha = null;
    } else {
      state.failedCaptchaAttempts += 1;
      result.failedCaptchaAttempts = state.failedCaptchaAttempts;
      state.captcha = createCaptchaChallenge();
    }
  }

  const otpCode = String(payload.otp?.code || "").trim();
  if (otpCode) {
    result.otpSubmitted = true;
    const otpChallenge = state.otp;
    const stillValid = otpChallenge && new Date(otpChallenge.expiresAt).getTime() > Date.now();

    if (stillValid && otpCode === otpChallenge.code) {
      result.otpVerified = true;
      state.otp = null;
    } else {
      state.failedOtpAttempts += 1;
      result.failedOtpAttempts = state.failedOtpAttempts;
      state.otp = createOtpChallenge();
    }
  }

  result.failedCaptchaAttempts = state.failedCaptchaAttempts;
  result.failedOtpAttempts = state.failedOtpAttempts;
  return result;
}

function getChallengeState(sessionId) {
  if (!challengeRegistry.has(sessionId)) {
    challengeRegistry.set(sessionId, {
      captcha: null,
      otp: null,
      failedCaptchaAttempts: 0,
      failedOtpAttempts: 0,
      blocked: false,
      createdAt: Date.now(),
      updatedAt: Date.now()
    });
  }

  const state = challengeRegistry.get(sessionId);
  state.updatedAt = Date.now();
  return state;
}

function ensureCaptchaChallenge(sessionId) {
  const state = getChallengeState(sessionId);
  if (!state.captcha || new Date(state.captcha.expiresAt).getTime() <= Date.now()) {
    state.captcha = createCaptchaChallenge();
  }
  return state.captcha;
}

function ensureOtpChallenge(sessionId) {
  const state = getChallengeState(sessionId);
  if (!state.otp || new Date(state.otp.expiresAt).getTime() <= Date.now()) {
    state.otp = createOtpChallenge();
  }
  return state.otp;
}

function clearChallenges(sessionId) {
  challengeRegistry.delete(sessionId);
}

function createCaptchaChallenge() {
  const types = ["word", "math", "code"];
  const type = types[Math.floor(Math.random() * types.length)];

  if (type === "math") {
    const a = randomBetween(2, 9);
    const b = randomBetween(3, 11);
    return withExpiry({
      type,
      prompt: `What is ${a} + ${b}?`,
      answer: String(a + b)
    }, 5 * 60 * 1000);
  }

  if (type === "code") {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let code = "";
    for (let index = 0; index < 5; index += 1) {
      code += chars[Math.floor(Math.random() * chars.length)];
    }
    return withExpiry({
      type,
      prompt: `Enter the code: ${code}`,
      answer: code
    }, 5 * 60 * 1000);
  }

  const words = ["secure", "signal", "vector", "human", "shield", "verify", "session", "trusted"];
  const word = words[Math.floor(Math.random() * words.length)];
  return withExpiry({
    type,
    prompt: `Type the word: ${word}`,
    answer: word
  }, 5 * 60 * 1000);
}

function createOtpChallenge() {
  const code = String(randomBetween(100000, 999999));
  return withExpiry({ code }, 5 * 60 * 1000);
}

function withExpiry(value, ttlMs) {
  const now = Date.now();
  return {
    ...value,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttlMs).toISOString()
  };
}

function parseUserAgent(userAgent) {
  const value = String(userAgent || "");
  const browser = /Edg\//i.test(value)
    ? "Microsoft Edge"
    : /Chrome\//i.test(value)
      ? "Chrome"
      : /Firefox\//i.test(value)
        ? "Firefox"
        : /Safari\//i.test(value) && !/Chrome\//i.test(value)
          ? "Safari"
          : /Headless/i.test(value)
            ? "Headless Browser"
            : "Unknown Browser";

  const operatingSystem = /Windows NT/i.test(value)
    ? "Windows"
    : /Mac OS X/i.test(value)
      ? "macOS"
      : /Android/i.test(value)
        ? "Android"
        : /iPhone|iPad|iPod/i.test(value)
          ? "iOS"
          : /Linux/i.test(value)
            ? "Linux"
            : "Unknown OS";

  return { browser, operatingSystem };
}

function buildReasonSummary(explainability, action, verificationState) {
  const reasons = Array.isArray(explainability)
    ? explainability
      .slice(0, 2)
      .map((item) => item.detail || item.title || "")
      .filter(Boolean)
    : [];

  if (action === "BLOCK_SESSION") {
    return reasons.length
      ? `Session was blocked because ${reasons.join(" and ").replace(/\.$/, "")}.`
      : "Session was blocked because the threat engine marked the activity as critical.";
  }

  if (action === "SHOW_CAPTCHA") {
    return reasons.length
      ? `CAPTCHA was triggered because ${reasons.join(" and ").replace(/\.$/, "")}.`
      : "CAPTCHA was triggered because the activity looked suspicious.";
  }

  if (action === "REQUIRE_OTP") {
    return reasons.length
      ? `OTP verification was required because ${reasons.join(" and ").replace(/\.$/, "")}.`
      : "OTP verification was required because the activity was high risk.";
  }

  if (verificationState === "CAPTCHA_VERIFIED") {
    return "Access was allowed after the session completed the CAPTCHA challenge successfully.";
  }

  if (verificationState === "OTP_VERIFIED") {
    return "Access was allowed after the session completed the OTP verification successfully.";
  }

  if (reasons.length) {
    return `Access was allowed because ${reasons.join(" and ").replace(/\.$/, "")}.`;
  }

  return "Access was allowed because the interaction stayed within the safe risk threshold.";
}

function buildThreatReportInput({ scoring, action, behavior, verificationState, submittedChallengeState }) {
  return {
    score: scoring.score,
    classification: scoring.prediction,
    confidence: scoring.confidence,
    threatLevel: scoring.level,
    action,
    reasons: Array.isArray(scoring.explainability)
      ? scoring.explainability.map((item) => item.detail || item.title || "").filter(Boolean)
      : [],
    behaviorMetrics: {
      mouseMoveCount: normalizeInteger(behavior?.mouseMoveCount),
      clickCount: normalizeInteger(behavior?.clickCount),
      scrollCount: normalizeInteger(behavior?.scrollCount),
      keystrokeCount: normalizeInteger(behavior?.keystrokeCount),
      typingSpeed: normalizeDecimal(scoring?.telemetry?.typing_cps),
      timeToFirstClickMs: normalizeInteger(behavior?.timingMs?.timeToFirstClickMs),
      timeToSubmitMs: normalizeInteger(behavior?.timingMs?.timeToSubmitMs),
      captchaVerified: Boolean(submittedChallengeState?.captchaVerified || verificationState === "CAPTCHA_VERIFIED"),
      otpVerified: Boolean(submittedChallengeState?.otpVerified || verificationState === "OTP_VERIFIED")
    }
  };
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }

  const ip = req.ip || req.socket?.remoteAddress || "";
  return String(ip).replace(/^::ffff:/, "");
}

function buildBaseUrl(req) {
  const forwardedProto = req.headers["x-forwarded-proto"];
  const proto = forwardedProto ? forwardedProto.split(",")[0] : req.protocol || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

function pushBotLogs(lines) {
  if (!Array.isArray(lines)) {
    return;
  }

  botRunState.logs.push(...lines);
  if (botRunState.logs.length > 40) {
    botRunState.logs = botRunState.logs.slice(-40);
  }
}

function pruneChallengeRegistry() {
  const maxIdleMs = 20 * 60 * 1000;
  const now = Date.now();

  challengeRegistry.forEach((state, sessionId) => {
    if (now - state.updatedAt > maxIdleMs) {
      challengeRegistry.delete(sessionId);
    }
  });
}

function normalizeInteger(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

function normalizeDecimal(value) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? Number(parsed.toFixed(2)) : 0;
}

function normalizeAnswer(value) {
  return String(value || "").trim().toLowerCase();
}

function randomBetween(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
