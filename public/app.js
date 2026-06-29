const SESSION_STORAGE_KEY = "bot_detection_demo_session_id";

const state = {
  sessionId: loadOrCreateSessionId(),
  pageLoadTs: performance.now(),
  firstClickMs: null,
  clickCount: 0,
  mouseMoveCount: 0,
  scrollCount: 0,
  keystrokeCount: 0,
  typingStartMs: null,
  typingEndMs: null,
  trapClicked: false,
  mouseDistance: 0,
  mouseDurationMs: 0,
  lastMousePoint: null,
  pending: false,
  loadingTimer: null
};

const challengeState = {
  currentType: null,
  captchaPrompt: "",
  captchaAnswer: "",
  honeypotTriggered: false,
  otpCode: ""
};

const statusEl = document.getElementById("status");
const statusMessageEl = document.getElementById("status-message");
const statusReasonEl = document.getElementById("status-reason");
const formEl = document.getElementById("login-form");
const trapBtn = document.getElementById("trap-btn");
const usernameEl = document.getElementById("username");
const passwordEl = document.getElementById("password");
const loginBtn = document.getElementById("login-btn");
const captchaPanelEl = document.getElementById("captcha-panel");
const captchaPromptEl = document.getElementById("captcha-prompt");
const captchaHintEl = document.getElementById("captcha-hint");
const captchaAttemptsEl = document.getElementById("captcha-attempts");
const captchaAnswerEl = document.getElementById("captcha-answer");
const captchaHpEl = document.getElementById("captcha-hp");
const otpPanelEl = document.getElementById("otp-panel");
const otpHintEl = document.getElementById("otp-hint");
const otpAttemptsEl = document.getElementById("otp-attempts");
const otpCodeEl = document.getElementById("otp-code");
const otpDemoEl = document.getElementById("otp-demo");
const storageModeEl = document.getElementById("storage-mode");
const storageReasonEl = document.getElementById("storage-reason");
const insightActionEl = document.getElementById("insight-action");
const insightScoreEl = document.getElementById("insight-score");
const insightPredictionEl = document.getElementById("insight-prediction");
const insightConfidenceEl = document.getElementById("insight-confidence");
const threatMeterFillEl = document.getElementById("threat-meter-fill");
const reportExecutiveEl = document.getElementById("report-executive");
const reportThreatEl = document.getElementById("report-threat");
const reportRiskEl = document.getElementById("report-risk");
const reportActionEl = document.getElementById("report-action");
const reportNotesEl = document.getElementById("report-notes");
const explainListEl = document.getElementById("explain-list");
const simulationButtons = Array.from(document.querySelectorAll("[data-simulation]"));
const resetLiveBtnEl = document.getElementById("reset-live-btn");
const simulationsActiveEl = document.getElementById("simulations-active");
const liveFeedEl = document.getElementById("live-feed");
const simulationSessionBodyEl = document.getElementById("simulation-session-body");
const miniActiveEl = document.getElementById("mini-active");
const miniBotsEl = document.getElementById("mini-bots");
const miniHumansEl = document.getElementById("mini-humans");
const miniBlockedEl = document.getElementById("mini-blocked");
const miniAverageEl = document.getElementById("mini-average");
const simulationPipelineEl = document.getElementById("simulation-pipeline");

initBotDetect();
initBehaviorTracking();
initChallengeTracking();
loadPlatformStatus();
initSimulationCenter();
loadLiveState();

formEl.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (state.pending) {
    return;
  }

  setPending(true);
  startAnalysisProgress();

  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildPayload())
    });

    const result = await response.json();

    if (!response.ok || result.status === "error") {
      throw new Error(result.userReason || "Security analysis failed.");
    }

    renderResult(result);
  } catch (error) {
    console.error(error);
    setStatus("Security analysis failed.", "danger", "The threat engine could not complete this scan. Please try again.");
  } finally {
    stopAnalysisProgress();
    setPending(false);
  }
});

function initBotDetect() {
  if (!window.BotDetect?.collector || !window.BotDetect?.detector) {
    setStatus("Client detection bundle missing.", "warning", "The demo will still run with server-side behavioral analysis.");
    return;
  }

  try {
    if (typeof window.BotDetect.collector.enableTraps === "function") {
      window.BotDetect.collector.enableTraps();
    }
  } catch (error) {
    console.warn("BotDetect traps failed to initialize", error);
  }
}

function initBehaviorTracking() {
  document.addEventListener("click", (event) => {
    if (event.target === trapBtn) {
      return;
    }
    state.clickCount += 1;
    if (state.firstClickMs === null) {
      state.firstClickMs = Math.round(performance.now() - state.pageLoadTs);
    }
  });

  document.addEventListener("mousemove", (event) => {
    if (state.mouseMoveCount < 1000) {
      state.mouseMoveCount += 1;
    }

    const now = performance.now();
    if (state.lastMousePoint) {
      const dx = event.clientX - state.lastMousePoint.x;
      const dy = event.clientY - state.lastMousePoint.y;
      const dt = now - state.lastMousePoint.t;
      if (dt > 0) {
        state.mouseDistance += Math.hypot(dx, dy);
        state.mouseDurationMs += dt;
      }
    }

    state.lastMousePoint = {
      x: event.clientX,
      y: event.clientY,
      t: now
    };
  });

  document.addEventListener("scroll", () => {
    if (state.scrollCount < 500) {
      state.scrollCount += 1;
    }
  }, { passive: true });

  const typingHandler = () => {
    const now = performance.now();
    if (state.typingStartMs === null) {
      state.typingStartMs = now;
    }
    state.typingEndMs = now;
    state.keystrokeCount += 1;
  };

  [usernameEl, passwordEl, captchaAnswerEl, otpCodeEl].forEach((input) => {
    if (!input) return;
    input.addEventListener("keydown", typingHandler);
  });

  trapBtn.addEventListener("click", () => {
    state.trapClicked = true;
  });
}

function initChallengeTracking() {
  if (captchaAnswerEl) {
    captchaAnswerEl.addEventListener("input", () => {
      challengeState.captchaAnswer = String(captchaAnswerEl.value || "").trim();
    });
  }

  if (captchaHpEl) {
    captchaHpEl.addEventListener("input", () => {
      challengeState.honeypotTriggered = true;
    });
    captchaHpEl.addEventListener("focus", () => {
      challengeState.honeypotTriggered = true;
    });
  }

  if (otpCodeEl) {
    otpCodeEl.addEventListener("input", () => {
      challengeState.otpCode = String(otpCodeEl.value || "").trim();
    });
  }
}

async function loadPlatformStatus() {
  if (!storageModeEl || !storageReasonEl) {
    return;
  }

  try {
    const response = await fetch("/api/health");
    const data = await parseApiResponse(response);
    const storage = data.storage || {};
    storageModeEl.textContent = String(storage.provider || "file").toUpperCase();
    storageReasonEl.textContent = storage.reason || "Storage status unavailable.";
  } catch (error) {
    console.error("Failed to load storage health", error);
    storageModeEl.textContent = "FILE";
    storageReasonEl.textContent = "Unable to load storage status. File persistence is assumed for this demo.";
  }
}

function initSimulationCenter() {
  simulationButtons.forEach((button) => {
    button.addEventListener("click", async () => {
      const type = button.dataset.simulation;
      if (!type) {
        return;
      }

      const originalText = button.textContent;
      button.disabled = true;
      button.textContent = "Launching...";

      try {
        const response = await fetch(`/api/simulations/${type}`, { method: "POST" });
        const result = await parseApiResponse(response);
        if (!response.ok) {
          throw new Error(result.message || "Simulation failed.");
        }
      } catch (error) {
        console.error(error);
        setStatus("Simulation launch failed.", "danger", error.message || "Unable to start the live bot simulation.");
      } finally {
        window.setTimeout(() => {
          button.disabled = false;
          button.textContent = originalText;
        }, 600);
      }
    });
  });

  if (resetLiveBtnEl) {
    resetLiveBtnEl.addEventListener("click", async () => {
      resetLiveBtnEl.disabled = true;
      try {
        const response = await fetch("/api/reset-demo", { method: "POST" });
        await parseApiResponse(response);
      } catch (error) {
        console.error(error);
      } finally {
        resetLiveBtnEl.disabled = false;
      }
    });
  }

  if ("EventSource" in window) {
    const source = new EventSource("/api/live-events");
    source.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        handleLiveMessage(message);
      } catch (error) {
        console.error("Failed to parse live event", error);
      }
    };
  }
}

async function loadLiveState() {
  try {
    const [eventsResponse, sessionsResponse] = await Promise.all([
      fetch("/api/current-events"),
      fetch("/api/current-sessions")
    ]);
    const events = await parseApiResponse(eventsResponse);
    const sessions = await parseApiResponse(sessionsResponse);
    renderLiveFeed(events.items || []);
    renderSimulationSessions(sessions.items || []);
    renderSimulationMetrics({
      activeSimulations: sessions.activeSimulations || 0,
      metrics: sessions.metrics || {}
    });
  } catch (error) {
    console.error("Failed to load live simulation state", error);
  }
}

function handleLiveMessage(message) {
  if (!message || typeof message !== "object") {
    return;
  }

  if (message.type === "snapshot" || message.type === "reset") {
    const payload = message.payload || {};
    renderLiveFeed(payload.events || []);
    renderSimulationSessions(payload.sessions || []);
    renderSimulationMetrics({
      activeSimulations: payload.activeSimulations || 0,
      metrics: payload.metrics || {}
    });
    updatePipeline(payload.events?.[0]);
    return;
  }

  if (message.type === "event") {
    prependLiveFeedItem(message.payload);
    updatePipeline(message.payload);
    return;
  }

  if (message.type === "metrics" || message.type === "simulation_completed") {
    const payload = message.payload || {};
    renderSimulationMetrics({
      activeSimulations: payload.activeSimulations || 0,
      metrics: payload.metrics || {}
    });
    if (Array.isArray(payload.sessions)) {
      renderSimulationSessions(payload.sessions);
    } else {
      loadLiveState();
    }
    return;
  }

  if (message.type === "simulation_started") {
    loadLiveState();
  }
}

async function parseApiResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  const text = await response.text();

  if (contentType.includes("application/json")) {
    return text ? JSON.parse(text) : {};
  }

  try {
    return text ? JSON.parse(text) : {};
  } catch (error) {
    if (/^\s*</.test(text)) {
      throw new Error("The API returned HTML instead of JSON. Restart the local server and refresh the page.");
    }
    throw new Error(text || "Unexpected API response.");
  }
}

function buildPayload() {
  const typingDurationMs = state.typingStartMs !== null && state.typingEndMs !== null
    ? Math.round(state.typingEndMs - state.typingStartMs)
    : 0;

  const averageMouseSpeed = state.mouseDurationMs > 0
    ? Number((state.mouseDistance / (state.mouseDurationMs / 1000)).toFixed(2))
    : 0;

  return {
    sessionId: state.sessionId,
    username: usernameEl.value.trim(),
    trapClicked: state.trapClicked,
    behavior: {
      timingMs: {
        timeToFirstClickMs: state.firstClickMs,
        timeToSubmitMs: Math.round(performance.now() - state.pageLoadTs)
      },
      mouseMoveCount: state.mouseMoveCount,
      clickCount: state.clickCount,
      scrollCount: state.scrollCount,
      keystrokeCount: state.keystrokeCount,
      typingDurationMs,
      averageMouseSpeed
    },
    botDetect: collectBotDetect(),
    automationSignals: collectAutomationSignals(),
    captcha: {
      answer: challengeState.captchaAnswer,
      honeypotTriggered: challengeState.honeypotTriggered
    },
    otp: {
      code: challengeState.otpCode
    },
    fingerprint: collectFingerprint()
  };
}

function collectBotDetect() {
  if (!window.BotDetect?.collector || !window.BotDetect?.detector) {
    return {
      decision: "unknown",
      results: [],
      error: "bot-detect not loaded"
    };
  }

  try {
    const results = window.BotDetect.collector.collect();
    const decision = window.BotDetect.detector.detect(results);
    return { results, decision };
  } catch (error) {
    console.warn("BotDetect collection failed", error);
    return {
      decision: "unknown",
      results: [],
      error: error?.message || "collection failed"
    };
  }
}

function collectAutomationSignals() {
  const userAgent = navigator.userAgent || "";

  return {
    userAgent,
    webdriver: navigator.webdriver === true,
    headlessUA: /Headless|PhantomJS|SlimerJS|Electron/i.test(userAgent),
    suspiciousUserAgent: /Headless|PhantomJS|SlimerJS|Electron|curl|wget/i.test(userAgent),
    pluginsLength: navigator.plugins ? navigator.plugins.length : 0,
    languagesLength: navigator.languages ? navigator.languages.length : 0,
    frameworks: {
      selenium: detectSeleniumArtifacts(),
      playwright: Boolean(window.__playwright__binding__ || window.__pwInitScripts),
      puppeteer: detectPuppeteerArtifacts(userAgent)
    }
  };
}

function collectFingerprint() {
  return {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
  };
}

function detectSeleniumArtifacts() {
  const windowKeys = Object.keys(window);
  return Boolean(
    window.navigator.webdriver
    || window.document.documentElement.getAttribute("webdriver")
    || windowKeys.some((key) => key.startsWith("$cdc_") || key.startsWith("$wdc_"))
    || window.domAutomation
    || window.domAutomationController
  );
}

function detectPuppeteerArtifacts(userAgent) {
  return Boolean(
    /HeadlessChrome/i.test(userAgent)
    || window.__nightmare
    || (navigator.webdriver === true && window.chrome && !window.__playwright__binding__)
  );
}

function renderResult(result) {
  renderInsightPanel(result);

  if (result.status === "challenge_required") {
    applyChallenge(result.challenge);
    setStatus(result.userMessage || "Verification required.", "warning", result.userReason || "Complete the requested security step.");
    loginBtn.textContent = result.action === "REQUIRE_OTP" ? "Verify OTP" : "Submit CAPTCHA";
    triggerHaptic("warning");
    return;
  }

  clearChallenges();
  loginBtn.textContent = "Run Security Analysis";

  if (result.status === "allowed") {
    setStatus(result.userMessage || "Access allowed.", "success", result.userReason || "Low-risk session accepted.");
    triggerHaptic("accepted");
    rotateSessionContext();
    return;
  }

  if (result.status === "blocked") {
    setStatus(result.userMessage || "Session blocked.", "danger", result.userReason || "Critical threat detected.");
    triggerHaptic("blocked");
    rotateSessionContext();
    return;
  }

  setStatus("Analysis complete.", "info", result.userReason || "");
}

function renderInsightPanel(result) {
  if (!insightActionEl || !insightScoreEl || !insightPredictionEl || !insightConfidenceEl || !threatMeterFillEl || !explainListEl) {
    return;
  }

  const threat = result.threat || {};
  const explainability = Array.isArray(result.explainability) ? result.explainability : [];
  const aiReport = result.aiReport && typeof result.aiReport === "object" ? result.aiReport : {};

  insightActionEl.textContent = formatAction(result.action);
  insightScoreEl.textContent = Number.isFinite(threat.score) ? `${threat.score}/100` : "--";
  insightPredictionEl.textContent = formatThreatValue(threat.prediction);
  insightConfidenceEl.textContent = Number.isFinite(threat.confidence) ? `${threat.confidence}%` : "--";

  const score = Number.isFinite(threat.score) ? Math.max(0, Math.min(100, threat.score)) : 0;
  threatMeterFillEl.style.width = `${score}%`;
  threatMeterFillEl.className = `threat-meter__fill threat-meter__fill--${normalizeTone(threat.level)}`;

  if (reportExecutiveEl) reportExecutiveEl.textContent = aiReport.executiveSummary || "No executive summary available.";
  if (reportThreatEl) reportThreatEl.textContent = aiReport.threatAssessment || "No threat assessment available.";
  if (reportRiskEl) reportRiskEl.textContent = aiReport.riskAssessment || "No risk assessment available.";
  if (reportActionEl) reportActionEl.textContent = aiReport.recommendedAction || formatAction(result.action);
  if (reportNotesEl) reportNotesEl.textContent = aiReport.analystNotes || "No analyst notes available.";

  explainListEl.innerHTML = "";
  if (!explainability.length) {
    explainListEl.innerHTML = "<div class=\"empty-state\">Threat indicators will appear here after analysis.</div>";
    return;
  }

  explainability.forEach((item) => {
    const card = document.createElement("article");
    card.className = `reason-card reason-card--${item.direction === "risk" ? "risk" : "support"}`;

    const header = document.createElement("div");
    header.className = "reason-card__header";

    const title = document.createElement("strong");
    title.textContent = item.title || "Signal";

    const meta = document.createElement("span");
    meta.className = "reason-card__meta";
    meta.textContent = item.direction === "risk" && item.weight
      ? `+${item.weight}`
      : formatThreatValue(item.category || "support");

    header.appendChild(title);
    header.appendChild(meta);

    const body = document.createElement("p");
    body.textContent = item.detail || "";

    card.appendChild(header);
    card.appendChild(body);
    explainListEl.appendChild(card);
  });
}

function applyChallenge(challenge) {
  if (!challenge || !challenge.type) {
    clearChallenges();
    return;
  }

  if (challenge.type === "captcha") {
    captchaPanelEl.classList.remove("challenge--hidden");
    otpPanelEl.classList.add("challenge--hidden");
    captchaPromptEl.textContent = challenge.prompt || "Complete the challenge.";
    captchaHintEl.textContent = "Type the exact answer shown below.";
    if (captchaAttemptsEl) {
      captchaAttemptsEl.textContent = `${challenge.attemptsRemaining || 0} attempts left`;
    }
    captchaAnswerEl.value = "";
    challengeState.captchaAnswer = "";
    challengeState.currentType = "captcha";
    challengeState.captchaPrompt = challenge.prompt || "";
    captchaAnswerEl.focus();
    return;
  }

  if (challenge.type === "otp") {
    otpPanelEl.classList.remove("challenge--hidden");
    captchaPanelEl.classList.add("challenge--hidden");
    otpHintEl.textContent = "Use the latest one-time code to continue.";
    if (otpAttemptsEl) {
      otpAttemptsEl.textContent = `${challenge.attemptsRemaining || 0} attempts left`;
    }
    otpDemoEl.textContent = challenge.demoCode
      ? `Demo delivery channel: code ${challenge.demoCode}`
      : "";
    otpCodeEl.value = "";
    challengeState.otpCode = "";
    challengeState.currentType = "otp";
    otpCodeEl.focus();
  }
}

function clearChallenges() {
  challengeState.currentType = null;
  challengeState.captchaPrompt = "";
  challengeState.captchaAnswer = "";
  challengeState.otpCode = "";
  challengeState.honeypotTriggered = false;
  captchaPanelEl.classList.add("challenge--hidden");
  otpPanelEl.classList.add("challenge--hidden");
  captchaAnswerEl.value = "";
  otpCodeEl.value = "";
  captchaHpEl.value = "";
  otpDemoEl.textContent = "";
}

function rotateSessionContext() {
  state.sessionId = createSessionId();
  sessionStorage.setItem(SESSION_STORAGE_KEY, state.sessionId);
  state.pageLoadTs = performance.now();
  state.firstClickMs = null;
  state.clickCount = 0;
  state.mouseMoveCount = 0;
  state.scrollCount = 0;
  state.keystrokeCount = 0;
  state.typingStartMs = null;
  state.typingEndMs = null;
  state.trapClicked = false;
  state.mouseDistance = 0;
  state.mouseDurationMs = 0;
  state.lastMousePoint = null;
  passwordEl.value = "";
  clearChallenges();
}

function setPending(value) {
  state.pending = Boolean(value);
  loginBtn.disabled = state.pending;
  loginBtn.textContent = state.pending ? "Analyzing..." : "Run Security Analysis";
  usernameEl.disabled = state.pending;
  passwordEl.disabled = state.pending;
  captchaAnswerEl.disabled = state.pending;
  otpCodeEl.disabled = state.pending;
}

function startAnalysisProgress() {
  stopAnalysisProgress();
  const phases = [
    ["Collecting Signals...", "info", "Capturing behavior, browser, and fingerprint telemetry from the current session."],
    ["Analyzing Session...", "info", "Reviewing automation indicators, timing signals, and interaction patterns."],
    ["Calculating Threat Score...", "info", "Scoring risk severity and classifying the session."],
    ["Generating AI Threat Assessment...", "info", "Producing a concise analyst-style report from the observed evidence."],
    ["Finalizing Report...", "info", "Packaging the decision, action, and explainability details."]
  ];

  let index = 0;
  const applyPhase = () => {
    const [message, tone, reason] = phases[Math.min(index, phases.length - 1)];
    setStatus(message, tone, reason);
    if (index < phases.length - 1) {
      index += 1;
    }
  };

  applyPhase();
  state.loadingTimer = window.setInterval(applyPhase, 700);
}

function stopAnalysisProgress() {
  if (state.loadingTimer) {
    window.clearInterval(state.loadingTimer);
    state.loadingTimer = null;
  }
}

function setStatus(message, tone, reason) {
  statusMessageEl.textContent = message || "";
  statusReasonEl.textContent = reason || "";
  statusEl.className = `status status--visible status--${tone || "info"}`.trim();
}

function renderLiveFeed(items) {
  if (!liveFeedEl) {
    return;
  }

  liveFeedEl.innerHTML = "";
  if (!Array.isArray(items) || !items.length) {
    liveFeedEl.innerHTML = "<div class=\"empty-state\">Run a simulation to stream threat events.</div>";
    return;
  }

  items.slice(0, 12).forEach((item) => {
    liveFeedEl.appendChild(buildLiveFeedItem(item));
  });
}

function prependLiveFeedItem(item) {
  if (!liveFeedEl) {
    return;
  }

  const empty = liveFeedEl.querySelector(".empty-state");
  if (empty) {
    liveFeedEl.innerHTML = "";
  }

  liveFeedEl.prepend(buildLiveFeedItem(item));
  while (liveFeedEl.children.length > 12) {
    liveFeedEl.removeChild(liveFeedEl.lastElementChild);
  }
}

function buildLiveFeedItem(item) {
  const article = document.createElement("article");
  article.className = "feed-item";
  article.innerHTML = `
    <span class="feed-pulse feed-pulse--${toneToPulse(item?.tone)}"></span>
    <div class="feed-item__body">
      <span>${escapeHtml(formatClock(item?.timestamp))}</span>
      <strong>${escapeHtml(item?.message || "Live event")}</strong>
      <p>${escapeHtml(formatThreatValue(item?.attackType || "simulation"))}</p>
    </div>
  `;
  return article;
}

function renderSimulationSessions(items) {
  if (!simulationSessionBodyEl) {
    return;
  }

  simulationSessionBodyEl.innerHTML = "";
  if (!Array.isArray(items) || !items.length) {
    simulationSessionBodyEl.innerHTML = "<tr><td colspan=\"6\" class=\"table-empty\">Run a simulation to populate the session table.</td></tr>";
    return;
  }

  items.slice(0, 8).forEach((item) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${escapeHtml(formatThreatValue(item.attackType || "--"))}</td>
      <td>${escapeHtml(item.riskScore ? `${item.riskScore}` : item.status === "running" ? "..." : "0")}</td>
      <td>${escapeHtml(item.classification || "PENDING")}</td>
      <td>${escapeHtml(formatAction(item.action || ""))}</td>
      <td>${escapeHtml(item.confidence ? `${item.confidence}%` : item.status === "running" ? "..." : "0%")}</td>
      <td>${escapeHtml(formatClock(item.timestamp || item.startedAt))}</td>
    `;
    simulationSessionBodyEl.appendChild(row);
  });
}

function renderSimulationMetrics(payload) {
  const activeSimulations = Number(payload?.activeSimulations || 0);
  const metrics = payload?.metrics || {};

  if (simulationsActiveEl) {
    simulationsActiveEl.textContent = `${activeSimulations} active simulation${activeSimulations === 1 ? "" : "s"}`;
  }
  if (miniActiveEl) miniActiveEl.textContent = activeSimulations;
  if (miniBotsEl) miniBotsEl.textContent = Number(metrics.botDetections || 0);
  if (miniHumansEl) miniHumansEl.textContent = Number(metrics.humanSessions || 0);
  if (miniBlockedEl) miniBlockedEl.textContent = Number(metrics.blockedSessions || 0);
  if (miniAverageEl) miniAverageEl.textContent = Number(metrics.averageRiskScore || 0);
}

function updatePipeline(event) {
  if (!simulationPipelineEl || !event) {
    return;
  }

  const message = String(event.message || "").toLowerCase();
  const nodes = Array.from(simulationPipelineEl.querySelectorAll(".pipeline__node"));
  nodes.forEach((node) => node.classList.remove("pipeline__node--active"));

  if (message.includes("simulation") || message.includes("launching")) {
    nodes[0]?.classList.add("pipeline__node--active");
  } else if (message.includes("opening")) {
    nodes[1]?.classList.add("pipeline__node--active");
  } else if (message.includes("analyzing") || message.includes("detected")) {
    nodes[2]?.classList.add("pipeline__node--active");
  } else if (message.includes("risk score") || message.includes("calculating")) {
    nodes[3]?.classList.add("pipeline__node--active");
  } else {
    nodes[4]?.classList.add("pipeline__node--active");
  }
}

function triggerHaptic(type) {
  if (!("vibrate" in navigator)) {
    return;
  }

  const patterns = {
    accepted: [24],
    blocked: [35, 40, 35],
    warning: [18, 22, 18]
  };

  navigator.vibrate(patterns[type] || 0);
}

function loadOrCreateSessionId() {
  const existing = sessionStorage.getItem(SESSION_STORAGE_KEY);
  if (existing) {
    return existing;
  }

  const next = createSessionId();
  sessionStorage.setItem(SESSION_STORAGE_KEY, next);
  return next;
}

function createSessionId() {
  if (window.crypto && typeof window.crypto.randomUUID === "function") {
    return `sess_${window.crypto.randomUUID()}`;
  }

  return `sess_${Math.random().toString(16).slice(2, 10)}`;
}

function formatAction(value) {
  const mapping = {
    ALLOW_ACCESS: "Access Granted",
    SHOW_CAPTCHA: "CAPTCHA Triggered",
    REQUIRE_OTP: "OTP Verification Required",
    BLOCK_SESSION: "Session Blocked"
  };
  return mapping[value] || "Awaiting analysis";
}

function formatThreatValue(value) {
  return String(value || "--").replace(/_/g, " ");
}

function normalizeTone(level) {
  const value = String(level || "SAFE").toLowerCase();
  if (value === "critical") return "critical";
  if (value === "high_risk") return "high";
  if (value === "suspicious") return "warning";
  return "safe";
}

function toneToPulse(tone) {
  const value = String(tone || "info").toLowerCase();
  if (value === "critical") return "critical";
  if (value === "warning") return "warning";
  if (value === "safe") return "safe";
  return "info";
}

function formatClock(value) {
  if (!value) {
    return "--:--:--";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
