const fs = require("fs");
const path = require("path");

const LOG_DIR = process.env.LOG_DIR
  || (process.env.VERCEL ? "/tmp" : path.join(__dirname, "..", "storage"));
const LOG_PATH = process.env.LOG_PATH || path.join(LOG_DIR, "access_log.csv");

const HEADERS = [
  "timestamp",
  "username",
  "decision",
  "label",
  "reason",
  "reasonSummary",
  "aiScore",
  "behaviorScore",
  "automationScore",
  "automationFlags",
  "botDetectDecision",
  "botSignalCount",
  "botDetectFlags",
  "webdriver",
  "headlessUA",
  "pluginsLength",
  "languagesLength",
  "captchaScore",
  "captchaChallengeType",
  "captchaTimeToSolveMs",
  "captchaAttempts",
  "captchaHoneypotTriggered",
  "captchaActivationDelayMs",
  "captchaVerifiedClient",
  "trapClicked",
  "timeToFirstClickMs",
  "timeToSubmitMs",
  "mouseMoveCount",
  "keystrokeCount",
  "typingDurationMs",
  "typingCps",
  "userAgent",
  "platform",
  "language",
  "timezone"
];

function ensureLogFile() {
  fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
  if (!fs.existsSync(LOG_PATH)) {
    fs.writeFileSync(LOG_PATH, `${HEADERS.join(",")}\n`, "utf8");
    return;
  }

  const content = fs.readFileSync(LOG_PATH, "utf8");
  if (!content.trim()) {
    fs.writeFileSync(LOG_PATH, `${HEADERS.join(",")}\n`, "utf8");
    return;
  }

  const [headerLine, ...lines] = content.split("\n");
  const existingHeaders = headerLine.split(",");
  const missing = HEADERS.filter((header) => !existingHeaders.includes(header));
  if (missing.length === 0) {
    return;
  }

  const entries = lines
    .filter((line) => line.trim() !== "")
    .map((line) => {
      const values = parseCsvLine(line);
      const entry = {};
      existingHeaders.forEach((header, index) => {
        entry[header] = values[index] ?? "";
      });
      return entry;
    });

  const rebuilt = [HEADERS.join(",")]
    .concat(entries.map((entry) => HEADERS.map((header) => escapeCsv(entry[header])).join(",")))
    .join("\n");

  fs.writeFileSync(LOG_PATH, `${rebuilt}\n`, "utf8");
}

function escapeCsv(value) {
  if (value === null || value === undefined) {
    return "";
  }
  const stringValue = String(value);
  if (stringValue.includes(",") || stringValue.includes("\n") || stringValue.includes('"')) {
    return `"${stringValue.replace(/"/g, '""')}"`;
  }
  return stringValue;
}

function appendLog(entry) {
  ensureLogFile();
  const row = HEADERS.map((header) => escapeCsv(entry[header]));
  fs.appendFileSync(LOG_PATH, `${row.join(",")}\n`, "utf8");
}

function readLogs() {
  ensureLogFile();
  const content = fs.readFileSync(LOG_PATH, "utf8").trim();
  if (!content) {
    return [];
  }
  const [headerLine, ...lines] = content.split("\n");
  const headers = headerLine.split(",");
  return lines.map((line) => {
    const values = parseCsvLine(line);
    const entry = {};
    headers.forEach((header, index) => {
      entry[header] = values[index] ?? "";
    });
    return entry;
  });
}

function parseCsvLine(line) {
  const values = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (inQuotes) {
      if (char === '"') {
        if (line[i + 1] === '"') {
          current += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        current += char;
      }
    } else if (char === '"') {
      inQuotes = true;
    } else if (char === ",") {
      values.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  values.push(current);
  return values;
}

module.exports = {
  appendLog,
  readLogs,
  LOG_PATH
};
