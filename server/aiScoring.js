const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const LEVEL_THRESHOLDS = [
  { level: "SAFE", max: 30 },
  { level: "SUSPICIOUS", max: 60 },
  { level: "HIGH_RISK", max: 80 },
  { level: "CRITICAL", max: 100 }
];

function scoreAttempt({
  botDetectDecision,
  botSignalCount,
  botSignals,
  automationSignals,
  trapClicked,
  timingMs,
  mouseMoveCount,
  clickCount,
  scrollCount,
  keystrokeCount,
  typingDurationMs,
  averageMouseSpeed,
  fingerprint,
  riskContext,
  challengeState
}) {
  const signals = [];
  const supportSignals = [];

  const typingCps = computeTypingCps(keystrokeCount, typingDurationMs);
  const suspiciousUserAgent = automationSignals?.suspiciousUserAgent === true
    || detectSuspiciousUserAgent(fingerprint?.userAgent);
  const frameworks = automationSignals?.frameworks || {};

  if (trapClicked) {
    addSignal(signals, 50, "Hidden trap interaction", "Invisible honeypot control was activated.", "trap");
  }

  if (challengeState?.honeypotTriggered) {
    addSignal(signals, 45, "Hidden field triggered", "A protected verification field was modified.", "challenge");
  }

  if (frameworks.selenium) {
    addSignal(signals, 30, "Selenium detected", "Browser globals matched Selenium/WebDriver markers.", "automation");
  }

  if (frameworks.playwright) {
    addSignal(signals, 30, "Playwright detected", "Playwright-specific runtime bindings were present.", "automation");
  }

  if (frameworks.puppeteer) {
    addSignal(signals, 30, "Puppeteer detected", "Chromium automation signatures matched Puppeteer behavior.", "automation");
  }

  if (automationSignals?.headlessUA) {
    addSignal(signals, 25, "Headless browser", "The user agent or browser profile indicates headless execution.", "automation");
  }

  if (automationSignals?.webdriver) {
    addSignal(signals, 20, "WebDriver enabled", "navigator.webdriver was true during the session.", "automation");
  }

  if (botDetectDecision === "bot") {
    addSignal(signals, 18, "Bot-detect verdict", "The client-side detection layer classified the session as automation.", "automation");
  }

  if (typeof botSignalCount === "number" && botSignalCount > 0) {
    addSignal(
      signals,
      Math.min(15, botSignalCount * 4),
      "Automation fingerprints",
      `${botSignalCount} automation fingerprint${botSignalCount === 1 ? "" : "s"} matched.`,
      "automation"
    );
  }

  if (mouseMoveCount === 0) {
    addSignal(signals, 20, "No mouse activity", "No pointer movement was recorded before submission.", "behavior");
  } else if (mouseMoveCount > 0 && mouseMoveCount < 3) {
    addSignal(signals, 10, "Low mouse activity", "Pointer movement was unusually low for a login flow.", "behavior");
  }

  if (typingCps > 12) {
    addSignal(signals, 10, "Typing too fast", `Typing cadence reached ${typingCps.toFixed(1)} characters per second.`, "behavior");
  }

  if (suspiciousUserAgent) {
    addSignal(signals, 10, "Suspicious user agent", "The user agent string matched known automation or scripting patterns.", "fingerprint");
  }

  if ((riskContext?.recentSessionAttempts || 0) >= 2 || (riskContext?.recentIpSessions || 0) >= 4) {
    addSignal(signals, 20, "Excessive requests", "Repeated verification attempts were seen in a short time window.", "traffic");
  }

  if ((riskContext?.blockedFromIp || 0) > 0) {
    addSignal(signals, 10, "Prior blocked activity", "This IP address has prior blocked sessions in the local history.", "traffic");
  }

  if (automationSignals?.pluginsLength === 0) {
    addSignal(signals, 5, "No plugins detected", "navigator.plugins returned an empty list.", "fingerprint");
  }

  if (automationSignals?.languagesLength === 0) {
    addSignal(signals, 5, "No languages detected", "navigator.languages returned an empty list.", "fingerprint");
  }

  const firstClickMs = normalizeInteger(timingMs?.timeToFirstClickMs);
  if (firstClickMs > 0 && firstClickMs < 300) {
    addSignal(signals, 8, "Very fast first click", `The first click happened in ${firstClickMs}ms.`, "behavior");
  }

  const submitMs = normalizeInteger(timingMs?.timeToSubmitMs);
  if (submitMs > 0 && submitMs < 900) {
    addSignal(signals, 12, "Very fast submission", `The form was submitted after ${submitMs}ms.`, "behavior");
  }

  if ((challengeState?.failedCaptchaAttempts || 0) > 0) {
    addSignal(signals, 10, "CAPTCHA failures", "The session failed one or more CAPTCHA attempts.", "challenge");
  }

  if ((challengeState?.failedOtpAttempts || 0) > 0) {
    addSignal(signals, 15, "OTP failures", "The session failed one or more OTP verification attempts.", "challenge");
  }

  if (mouseMoveCount >= 8) {
    addSupport(supportSignals, "Natural mouse activity", "The session generated sustained pointer movement.", "behavior");
  }

  if (clickCount >= 1 && scrollCount >= 1) {
    addSupport(supportSignals, "Multi-step interaction", "Clicks and scrolling suggest a human exploration pattern.", "behavior");
  }

  if (typingCps > 0 && typingCps <= 10) {
    addSupport(supportSignals, "Human typing cadence", `Typing speed stayed within a more typical human range at ${typingCps.toFixed(1)} cps.`, "behavior");
  }

  if (submitMs >= 1800) {
    addSupport(supportSignals, "Measured completion time", "The form completion time was not overly aggressive.", "behavior");
  }

  if (challengeState?.captchaVerified) {
    addSupport(supportSignals, "CAPTCHA verified", "The session passed the additional challenge step.", "challenge");
  }

  if (challengeState?.otpVerified) {
    addSupport(supportSignals, "OTP verified", "The one-time code verification succeeded.", "challenge");
  }

  if (!automationSignals?.webdriver && !automationSignals?.headlessUA && !frameworks.selenium && !frameworks.playwright && !frameworks.puppeteer) {
    addSupport(supportSignals, "No strong automation markers", "The browser did not expose the strongest automation signatures.", "fingerprint");
  }

  const score = clamp(
    signals.reduce((sum, signal) => sum + signal.weight, 0),
    0,
    100
  );
  const level = resolveThreatLevel(score);
  const prediction = score <= 30 ? "HUMAN" : "BOT";
  const confidence = resolveConfidence({
    score,
    prediction,
    riskSignals: signals,
    supportSignals
  });

  const explainability = buildExplainability({
    prediction,
    riskSignals: signals,
    supportSignals
  });

  return {
    score,
    level,
    prediction,
    confidence,
    reasons: explainability.map((item) => item.detail),
    explainability,
    telemetry: {
      typing_cps: typingCps,
      mouse_move_count: normalizeInteger(mouseMoveCount),
      click_count: normalizeInteger(clickCount),
      scroll_count: normalizeInteger(scrollCount),
      time_to_first_click_ms: firstClickMs,
      time_to_submit_ms: submitMs,
      average_mouse_speed: normalizeDecimal(averageMouseSpeed),
      bot_signal_count: normalizeInteger(botSignalCount),
      bot_signal_labels: Array.isArray(botSignals) ? botSignals.slice(0, 6) : []
    }
  };
}

module.exports = {
  scoreAttempt
};

function addSignal(collection, weight, title, detail, category) {
  collection.push({
    direction: "risk",
    weight: normalizeInteger(weight),
    title,
    detail,
    category
  });
}

function addSupport(collection, title, detail, category) {
  collection.push({
    direction: "support",
    weight: 0,
    title,
    detail,
    category
  });
}

function resolveThreatLevel(score) {
  return LEVEL_THRESHOLDS.find((item) => score <= item.max)?.level || "CRITICAL";
}

function resolveConfidence({ score, prediction, riskSignals, supportSignals }) {
  if (prediction === "BOT") {
    const riskBoost = Math.round(score * 0.35);
    const evidenceBoost = Math.min(18, riskSignals.length * 4);
    return clamp(55 + riskBoost + evidenceBoost, 55, 98);
  }

  const supportBoost = Math.min(24, supportSignals.length * 6);
  const lowRiskBoost = Math.max(0, 30 - score);
  return clamp(58 + supportBoost + Math.round(lowRiskBoost * 0.6), 58, 96);
}

function buildExplainability({ prediction, riskSignals, supportSignals }) {
  if (prediction === "BOT") {
    if (riskSignals.length === 0) {
      return [{
        direction: "risk",
        weight: 0,
        title: "Elevated risk",
        detail: "The session exceeded the low-risk threshold based on combined signals.",
        category: "summary"
      }];
    }

    return riskSignals
      .slice()
      .sort((left, right) => right.weight - left.weight)
      .slice(0, 5);
  }

  if (supportSignals.length === 0) {
    return [{
      direction: "support",
      weight: 0,
      title: "Low-risk interaction",
      detail: "The session stayed below the risk threshold with no dominant automation markers.",
      category: "summary"
    }];
  }

  return supportSignals.slice(0, 5);
}

function computeTypingCps(keystrokeCount, typingDurationMs) {
  const strokes = normalizeInteger(keystrokeCount);
  const duration = normalizeInteger(typingDurationMs);

  if (!strokes || duration <= 0) {
    return 0;
  }

  return Number((strokes / (duration / 1000)).toFixed(2));
}

function detectSuspiciousUserAgent(userAgent) {
  const value = String(userAgent || "");
  if (!value) {
    return true;
  }

  return /Headless|PhantomJS|SlimerJS|Electron|node-fetch|curl|wget|python-requests/i.test(value);
}

function normalizeInteger(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

function normalizeDecimal(value) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? Number(parsed.toFixed(2)) : 0;
}
