const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

async function generateThreatReport(input) {
  const normalizedInput = normalizeInput(input);

  if (!process.env.GEMINI_API_KEY) {
    return buildFallbackThreatReport(normalizedInput, "Gemini API key not configured. Generated a local analyst summary instead.");
  }

  const sdk = loadGeminiSdk();
  if (!sdk) {
    return buildFallbackThreatReport(normalizedInput, "Gemini SDK unavailable. Generated a local analyst summary instead.");
  }

  try {
    const client = new sdk.GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = client.getGenerativeModel({
      model: GEMINI_MODEL,
      systemInstruction: [
        "You are a Senior Cybersecurity Threat Analyst.",
        "Analyze login security events and generate professional threat intelligence reports.",
        "Use only the supplied evidence.",
        "Do not invent indicators.",
        "Provide:",
        "1. Executive Summary",
        "2. Threat Assessment",
        "3. Risk Assessment",
        "4. Recommended Action",
        "5. Analyst Notes",
        "Keep the response concise and professional.",
        "Maximum 200 words.",
        "Use enterprise cybersecurity language.",
        "Avoid hallucinations.",
        "Base conclusions strictly on supplied indicators.",
        "Return strict JSON with the keys executiveSummary, threatAssessment, riskAssessment, recommendedAction, analystNotes."
      ].join(" ")
    });

    const prompt = [
      "Generate a threat intelligence report for this login security event.",
      "Only use the supplied evidence.",
      "Return strict JSON.",
      "",
      JSON.stringify(normalizedInput, null, 2)
    ].join("\n");

    const result = await model.generateContent({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 500,
        responseMimeType: "application/json"
      }
    });

    const text = result?.response?.text?.() || "";
    const parsed = parseReportJson(text);
    return normalizeReport(parsed, {
      source: "gemini",
      provider: "google",
      model: GEMINI_MODEL,
      fallbackReason: ""
    });
  } catch (error) {
    console.error("Gemini threat report generation failed.", error);
    return buildFallbackThreatReport(normalizedInput, "Gemini request failed. Generated a local analyst summary instead.");
  }
}

module.exports = {
  generateThreatReport
};

function loadGeminiSdk() {
  try {
    return require("@google/generative-ai");
  } catch (error) {
    return null;
  }
}

function normalizeInput(input) {
  const reasons = Array.isArray(input?.reasons)
    ? input.reasons.map((item) => String(item || "").trim()).filter(Boolean).slice(0, 6)
    : [];

  return {
    score: toInteger(input?.score),
    classification: String(input?.classification || input?.prediction || "UNKNOWN").toUpperCase(),
    confidence: toInteger(input?.confidence),
    threatLevel: String(input?.threatLevel || input?.level || "SAFE").toUpperCase(),
    action: String(input?.action || "ALLOW_ACCESS").toUpperCase(),
    reasons,
    behaviorMetrics: {
      mouseMoveCount: toInteger(input?.behaviorMetrics?.mouseMoveCount),
      clickCount: toInteger(input?.behaviorMetrics?.clickCount),
      scrollCount: toInteger(input?.behaviorMetrics?.scrollCount),
      keystrokeCount: toInteger(input?.behaviorMetrics?.keystrokeCount),
      typingSpeed: toDecimal(input?.behaviorMetrics?.typingSpeed),
      timeToFirstClickMs: toInteger(input?.behaviorMetrics?.timeToFirstClickMs),
      timeToSubmitMs: toInteger(input?.behaviorMetrics?.timeToSubmitMs),
      captchaVerified: Boolean(input?.behaviorMetrics?.captchaVerified),
      otpVerified: Boolean(input?.behaviorMetrics?.otpVerified)
    }
  };
}

function buildFallbackThreatReport(input, fallbackReason) {
  const reasons = input.reasons.length
    ? input.reasons
    : ["The session exceeded the safe threshold based on observed security signals."];
  const actionLabel = formatAction(input.action);
  const classificationLabel = input.classification === "BOT" ? "automated activity" : "human activity";
  const reasonSummary = reasons.slice(0, 2).join(" ");

  return normalizeReport({
    executiveSummary: `${input.threatLevel} confidence ${classificationLabel} assessment generated from ${reasons.length} observed signal${reasons.length === 1 ? "" : "s"}.`,
    threatAssessment: `This login session shows ${reasonSummary || reasons[0]}`.trim(),
    riskAssessment: input.classification === "BOT"
      ? `The observed pattern is consistent with scripted or automated access behavior. Score ${input.score}/100 and confidence ${input.confidence}% support elevated defensive controls.`
      : `The session remained within a lower-risk profile. Score ${input.score}/100 and confidence ${input.confidence}% indicate limited evidence of automation.`,
    recommendedAction: actionLabel,
    analystNotes: input.classification === "BOT"
      ? `Primary indicators: ${reasons.join("; ")}`
      : `Supportive indicators outweighed automation concerns. ${reasonSummary || reasons[0]}`
  }, {
    source: "fallback",
    provider: "local-rule-engine",
    model: "fallback-analyst",
    fallbackReason
  });
}

function normalizeReport(report, metadata) {
  return {
    executiveSummary: normalizeSection(report?.executiveSummary, "Threat summary unavailable."),
    threatAssessment: normalizeSection(report?.threatAssessment, "Threat assessment unavailable."),
    riskAssessment: normalizeSection(report?.riskAssessment, "Risk assessment unavailable."),
    recommendedAction: normalizeSection(report?.recommendedAction, "Review session manually."),
    analystNotes: normalizeSection(report?.analystNotes, "No additional analyst notes were generated."),
    source: metadata.source,
    provider: metadata.provider,
    model: metadata.model,
    fallbackReason: metadata.fallbackReason,
    generatedAt: new Date().toISOString()
  };
}

function normalizeSection(value, fallback) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (!text) {
    return fallback;
  }
  return text.length > 320 ? `${text.slice(0, 317).trim()}...` : text;
}

function parseReportJson(text) {
  const raw = String(text || "").trim();
  if (!raw) {
    throw new Error("Empty Gemini response.");
  }

  const cleaned = raw
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/, "")
    .trim();

  return JSON.parse(cleaned);
}

function formatAction(value) {
  const mapping = {
    ALLOW_ACCESS: "Allow Access",
    SHOW_CAPTCHA: "Trigger CAPTCHA",
    REQUIRE_OTP: "Require OTP Verification",
    BLOCK_SESSION: "Block Session"
  };
  return mapping[value] || String(value || "Review Session");
}

function toInteger(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

function toDecimal(value) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? Number(parsed.toFixed(2)) : 0;
}
