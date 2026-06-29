const state = {
  page: 1,
  pageSize: 10,
  selectedSessionId: "",
  refreshTimer: null,
  dashboard: null,
  currentItems: []
};

const logBodyEl = document.getElementById("log-body");
const pageMetaEl = document.getElementById("page-meta");
const prevPageEl = document.getElementById("prev-page");
const nextPageEl = document.getElementById("next-page");
const paginationEl = document.getElementById("pagination");
const metricAcceptedEl = document.getElementById("metric-accepted");
const metricAcceptedMetaEl = document.getElementById("metric-accepted-meta");
const metricAverageEl = document.getElementById("metric-average");
const metricBotsEl = document.getElementById("metric-bots");
const metricBlockedEl = document.getElementById("metric-blocked");
const metricBlockedMetaEl = document.getElementById("metric-blocked-meta");
const metricActiveEl = document.getElementById("metric-active");
const metricTotalEl = document.getElementById("metric-total");
const logsStatusEl = document.getElementById("logs-status");
const logsProgressFillEl = document.getElementById("logs-progress-fill");
const riskBarsEl = document.getElementById("risk-bars");
const actionCardsEl = document.getElementById("action-cards");
const detailSummaryEl = document.getElementById("detail-summary");
const detailAiReportEl = document.getElementById("detail-ai-report");
const detailReasonsEl = document.getElementById("detail-reasons");
const detailBehaviorEl = document.getElementById("detail-behavior");

bindEvents();
refreshAll();
state.refreshTimer = window.setInterval(refreshAll, 12000);

function bindEvents() {
  prevPageEl.addEventListener("click", () => {
    if (state.page > 1) {
      state.page -= 1;
      loadSessions();
    }
  });

  nextPageEl.addEventListener("click", () => {
    state.page += 1;
    loadSessions();
  });
}

async function refreshAll() {
  await Promise.all([loadDashboard(), loadSessions()]);
}

async function loadDashboard() {
  try {
    const response = await fetch("/api/dashboard");
    const data = await response.json();
    state.dashboard = data;
    renderSummary(data);
    renderRiskBars(data.distributions?.threat_levels || []);
    renderActionCards(data.distributions?.action_counts || []);
  } catch (error) {
    console.error("Failed to load dashboard summary", error);
    state.dashboard = null;
    renderSummary(null);
    renderRiskBars([]);
    renderActionCards([]);
  }
}

async function loadSessions() {
  try {
    const response = await fetch(`/api/logs?page=${state.page}&pageSize=${state.pageSize}`);
    const data = await response.json();
    state.currentItems = Array.isArray(data.items) ? data.items : [];
    renderSessions(state.currentItems);
    renderPagination(data.page || 1, data.totalPages || 1, data.total || 0);
  } catch (error) {
    console.error("Failed to load sessions", error);
    state.currentItems = [];
    renderSessions([]);
    renderPagination(1, 1, 0);
  }
}

function renderSummary(dashboard) {
  const metrics = dashboard?.metrics || {};
  const actions = dashboard?.distributions?.action_counts || [];
  const threatLevels = dashboard?.distributions?.threat_levels || [];
  const total = Number(metrics.total_sessions || 0);
  const accepted = Number(metrics.total_humans || 0);
  const bots = Number(metrics.total_bots || 0);
  const blocked = Number(metrics.total_blocks || 0);
  const challenged = getActionCount(actions, "SHOW_CAPTCHA") + getActionCount(actions, "REQUIRE_OTP");
  const acceptedPercent = total ? Math.round((accepted / total) * 100) : 0;
  const blockedPercent = total ? Math.round((blocked / total) * 100) : 0;
  const activeThreats = threatLevels
    .filter((item) => item.key === "HIGH_RISK" || item.key === "CRITICAL")
    .reduce((sum, item) => sum + Number(item.count || 0), 0);

  metricTotalEl.textContent = total;
  metricAcceptedEl.textContent = accepted;
  metricAcceptedMetaEl.textContent = total ? `${acceptedPercent}% of attempts cleared` : "No attempts yet";
  metricBotsEl.textContent = bots;
  metricBlockedEl.textContent = blocked;
  metricBlockedMetaEl.textContent = total ? `${blockedPercent}% of attempts blocked` : "Automated blocks";
  metricAverageEl.textContent = `${Number(metrics.average_threat_score || 0)}`;
  metricActiveEl.textContent = activeThreats;
  logsProgressFillEl.style.width = `${Math.max(0, Math.min(100, acceptedPercent))}%`;
  logsStatusEl.textContent = total
    ? `${total} access attempt${total === 1 ? "" : "s"} stored. Adaptive actions issued ${challenged} time${challenged === 1 ? "" : "s"}, with ${activeThreats} active threat${activeThreats === 1 ? "" : "s"} currently in high-risk bands.`
    : "No attempts yet.";
}

function renderRiskBars(items) {
  riskBarsEl.innerHTML = "";
  const palette = {
    SAFE: "safe",
    SUSPICIOUS: "warning",
    HIGH_RISK: "high",
    CRITICAL: "critical"
  };

  if (!items.length) {
    riskBarsEl.innerHTML = "<div class=\"empty-state empty-state--classic\">Threat distribution will appear here after sessions are analyzed.</div>";
    return;
  }

  const max = Math.max(...items.map((item) => Number(item.count || 0)), 1);
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "dashboard-bar";

    const label = document.createElement("span");
    label.className = "dashboard-bar__label";
    label.textContent = formatLabel(item.key);

    const track = document.createElement("div");
    track.className = "dashboard-bar__track";

    const fill = document.createElement("span");
    fill.className = `dashboard-bar__fill dashboard-bar__fill--${palette[item.key] || "safe"}`;
    fill.style.width = `${Math.max(10, Math.round((Number(item.count || 0) / max) * 100))}%`;
    track.appendChild(fill);

    const count = document.createElement("strong");
    count.className = "dashboard-bar__count";
    count.textContent = Number(item.count || 0);

    row.appendChild(label);
    row.appendChild(track);
    row.appendChild(count);
    riskBarsEl.appendChild(row);
  });
}

function renderActionCards(items) {
  actionCardsEl.innerHTML = "";
  const cards = [
    { key: "ALLOW_ACCESS", title: "Allow", body: "Low-risk users granted access immediately." },
    { key: "SHOW_CAPTCHA", title: "CAPTCHA", body: "Mid-risk sessions challenged with verification." },
    { key: "REQUIRE_OTP", title: "OTP", body: "High-risk sessions escalated to one-time code checks." },
    { key: "BLOCK_SESSION", title: "Block", body: "Critical or repeatedly failing sessions blocked." }
  ];

  cards.forEach((card) => {
    const article = document.createElement("article");
    article.className = "action-card";
    article.innerHTML = `
      <span class="action-card__label">${card.title}</span>
      <strong class="action-card__value">${getActionCount(items, card.key)}</strong>
      <p class="action-card__body">${card.body}</p>
    `;
    actionCardsEl.appendChild(article);
  });
}

function renderSessions(items) {
  logBodyEl.innerHTML = "";

  if (!items.length) {
    logBodyEl.innerHTML = "<tr><td colspan=\"8\" class=\"table-empty table-empty--classic\">No attempts yet.</td></tr>";
    renderDetail(null);
    return;
  }

  items.forEach((item) => {
    const decision = deriveDecision(item);
    const row = document.createElement("tr");
    row.className = "logs-row";
    row.dataset.sessionId = item.session_id;

    row.appendChild(buildCell(formatTimestamp(item.timestamp)));
    row.appendChild(buildCell(item.username || "demo_user"));
    row.appendChild(buildDecisionCell(decision));
    row.appendChild(buildCell(item.reason_summary || "Verification completed.", "cell--wrap"));
    row.appendChild(buildScoreCell(item.threat_score));
    row.appendChild(buildScoreCell(deriveBehaviorScore(item)));
    row.appendChild(buildScoreCell(deriveCaptchaScore(item)));
    row.appendChild(buildCell(formatAutomationFlags(item.automation_flags), "cell--wrap"));

    row.addEventListener("click", () => {
      state.selectedSessionId = item.session_id;
      highlightSelectedRow();
      renderDetail(item);
    });

    logBodyEl.appendChild(row);
  });

  const selected = items.find((item) => item.session_id === state.selectedSessionId) || items[0];
  state.selectedSessionId = selected.session_id;
  highlightSelectedRow();
  renderDetail(selected);
}

function renderDetail(item) {
  if (!item) {
    detailSummaryEl.innerHTML = "<div class=\"empty-state empty-state--classic\">No session selected yet.</div>";
    detailAiReportEl.innerHTML = "<div class=\"empty-state empty-state--classic\">AI analyst output will appear here once a session is selected.</div>";
    detailReasonsEl.innerHTML = "<div class=\"empty-state empty-state--classic\">Threat indicators will appear here once a session is selected.</div>";
    detailBehaviorEl.innerHTML = "<div class=\"empty-state empty-state--classic\">Behavior telemetry will appear here once a session is selected.</div>";
    return;
  }

  const behavior = item.last_behavior_event || {};
  const explainability = Array.isArray(item.explainability) ? item.explainability : [];
  const aiReport = item.ai_report && typeof item.ai_report === "object" ? item.ai_report : {};

  detailSummaryEl.innerHTML = "";
  [
    ["Session", item.session_id || "--"],
    ["Action", formatAction(item.action_taken)],
    ["Threat Score", `${Number(item.threat_score || 0)}/100`],
    ["Threat Level", formatLabel(item.threat_level || "--")],
    ["Prediction", formatLabel(item.prediction || "--")],
    ["Verification", formatLabel(item.verification_state || "--")],
    ["Confidence", `${Number(item.confidence || 0)}%`],
    ["Browser", item.browser || "Unknown"],
    ["Attempts", Number(item.event_count || 0)]
  ].forEach(([label, value]) => {
    const card = document.createElement("article");
    card.className = "detail-pill";
    card.innerHTML = `<span>${label}</span><strong>${escapeHtml(String(value))}</strong>`;
    detailSummaryEl.appendChild(card);
  });

  detailAiReportEl.innerHTML = "";
  [
    ["Executive Summary", aiReport.executiveSummary || "No AI executive summary available."],
    ["Threat Assessment", aiReport.threatAssessment || "No threat assessment available."],
    ["Risk Assessment", aiReport.riskAssessment || "No risk assessment available."],
    ["Recommended Action", aiReport.recommendedAction || formatAction(item.action_taken)],
    ["Analyst Notes", aiReport.analystNotes || "No analyst notes available."]
  ].forEach(([label, value]) => {
    const article = document.createElement("article");
    article.className = "ai-report__section";
    article.innerHTML = `<span>${escapeHtml(label)}</span><p>${escapeHtml(String(value))}</p>`;
    detailAiReportEl.appendChild(article);
  });

  detailReasonsEl.innerHTML = "";
  if (!explainability.length) {
    detailReasonsEl.innerHTML = "<div class=\"empty-state empty-state--classic\">No explainability signals captured for this session.</div>";
  } else {
    explainability.forEach((reason) => {
      const card = document.createElement("article");
      card.className = `reason-card reason-card--${reason.direction === "risk" ? "risk" : "support"} reason-card--classic`;
      card.innerHTML = `
        <div class="reason-card__header">
          <strong>${escapeHtml(reason.title || "Signal")}</strong>
          <span class="reason-card__meta">${escapeHtml(reason.direction === "risk" && reason.weight ? `+${reason.weight}` : formatLabel(reason.category || "support"))}</span>
        </div>
        <p>${escapeHtml(reason.detail || "")}</p>
      `;
      detailReasonsEl.appendChild(card);
    });
  }

  detailBehaviorEl.innerHTML = "";
  [
    ["Mouse movements", Number(behavior.mouse_movements || 0)],
    ["Clicks", Number(behavior.clicks || 0)],
    ["Keystrokes", Number(behavior.keystrokes || 0)],
    ["Scroll events", Number(behavior.scroll_events || 0)],
    ["Typing speed", `${Number(behavior.typing_speed || 0)} cps`],
    ["Time to submit", `${Number(behavior.time_to_submit_ms || 0)} ms`],
    ["CAPTCHA verified", behavior.captcha_verified ? "Yes" : "No"],
    ["OTP verified", behavior.otp_verified ? "Yes" : "No"]
  ].forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "detail-behavior__row";
    row.innerHTML = `<span>${label}</span><strong>${escapeHtml(String(value))}</strong>`;
    detailBehaviorEl.appendChild(row);
  });
}

function renderPagination(page, totalPages, total) {
  const safeTotalPages = Math.max(totalPages, 1);
  state.page = Math.min(page, safeTotalPages);
  pageMetaEl.textContent = `Page ${page} of ${safeTotalPages} (${total} attempts)`;
  prevPageEl.disabled = page <= 1;
  nextPageEl.disabled = page >= safeTotalPages;
  paginationEl.classList.toggle("logs-pagination--hidden", safeTotalPages <= 1);
}

function buildCell(value, className) {
  const cell = document.createElement("td");
  cell.textContent = value ? String(value) : "—";
  if (className) {
    cell.className = className;
  }
  return cell;
}

function buildDecisionCell(decision) {
  const cell = document.createElement("td");
  const badge = document.createElement("span");
  badge.className = `decision-badge decision-badge--${decision.toLowerCase()}`;
  badge.textContent = decision;
  cell.appendChild(badge);
  return cell;
}

function buildScoreCell(value) {
  const numeric = Number(value);
  return buildCell(Number.isFinite(numeric) ? `${numeric}` : "—");
}

function highlightSelectedRow() {
  document.querySelectorAll(".logs-row").forEach((row) => {
    row.classList.toggle("logs-row--selected", row.dataset.sessionId === state.selectedSessionId);
  });
}

function deriveDecision(item) {
  const action = String(item.action_taken || "").toUpperCase();
  const verificationState = String(item.verification_state || "").toUpperCase();
  const prediction = String(item.prediction || "").toUpperCase();

  if (action === "ALLOW_ACCESS" || verificationState === "VERIFIED" || verificationState === "OTP_VERIFIED" || prediction === "HUMAN") {
    return "ACCEPTED";
  }

  if (action === "BLOCK_SESSION") {
    return "REJECTED";
  }

  if (action === "SHOW_CAPTCHA" || action === "REQUIRE_OTP") {
    return "CHALLENGED";
  }

  return "REVIEW";
}

function deriveBehaviorScore(item) {
  const behavior = item.last_behavior_event || {};
  const explainability = Array.isArray(item.explainability) ? item.explainability : [];
  let score = 0;

  explainability.forEach((entry) => {
    if (entry.direction === "risk" && entry.category === "behavior") {
      score += Number(entry.weight || 0);
    }
  });

  if (Number(behavior.mouse_movements || 0) === 0) {
    score += 20;
  }
  if (Number(behavior.time_to_submit_ms || 0) > 0 && Number(behavior.time_to_submit_ms) < 900) {
    score += 12;
  }
  if (Number(behavior.typing_speed || 0) > 12) {
    score += 10;
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

function deriveCaptchaScore(item) {
  const behavior = item.last_behavior_event || {};
  const features = behavior.raw_features || {};
  const challengeState = features.challenge_state || {};
  let score = 0;

  if (item.action_taken === "SHOW_CAPTCHA") {
    score += 50;
  }
  if (challengeState.honeypotTriggered) {
    score += 35;
  }
  if (Number(challengeState.failedCaptchaAttempts || 0) > 0) {
    score += Number(challengeState.failedCaptchaAttempts) * 15;
  }
  if (behavior.captcha_verified) {
    score = Math.max(score - 20, 10);
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

function formatAutomationFlags(flags) {
  if (!Array.isArray(flags) || !flags.length) {
    return "None";
  }

  return flags.map((flag) => formatLabel(flag)).join(", ");
}

function getActionCount(items, key) {
  const match = items.find((item) => item.key === key);
  return Number(match?.count || 0);
}

function formatLabel(value) {
  return String(value || "")
    .replace(/_/g, " ")
    .replace(/-/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function formatAction(value) {
  const mapping = {
    ALLOW_ACCESS: "Access Granted",
    SHOW_CAPTCHA: "CAPTCHA Triggered",
    REQUIRE_OTP: "OTP Verification Required",
    BLOCK_SESSION: "Session Blocked"
  };
  return mapping[value] || formatLabel(value || "Awaiting analysis");
}

function formatTimestamp(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
