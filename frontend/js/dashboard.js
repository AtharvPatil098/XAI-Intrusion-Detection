// dashboard.js — XAI-IDS Full Dashboard (auto-polling, dual mode)
// FIXED: stable polling, log deduplication, minimal DOM re-renders

const API        = "http://127.0.0.1:8000";
const POLL_MS    = 3000;   // poll every 3 s
const EXPLAIN_MS = 15000;  // re-run SHAP at most every 15 s
const MAX_PTS    = 30;

// ── State ──────────────────────────────────────────────────────────────────
let _lastTs          = null;   // ts of the last prediction we acted on
let _lastExplainTs   = 0;      // wall-clock ms of last SHAP call
let _lastLogKey      = null;   // dedup key for the activity log
let _polling         = false;  // guard: only one poll() in-flight at a time
let _connected       = null;   // tri-state: null | true | false (avoid flicker)
let _lastSource      = null;   // track source changes without DOM thrash
let _lastSignature = null;

// ── State ──────────────────────────────────────────────────────────────────
// ... existing state ...
let logCount = parseInt(localStorage.getItem("xai_log_count")) || 0;
let persistedLogs = JSON.parse(localStorage.getItem("xai_logs")) || [];

// ── Initialize Log on Page Load ────────────────────────────────────────────
function loadPersistedLogs() {
  const container = document.getElementById("activityLog");
  const countEl = document.getElementById("logCount");
  
  if (countEl) countEl.textContent = logCount;
  
  // Render logs from storage (they are stored in order: newest to oldest)
  persistedLogs.forEach(logHtml => {
    const tempDiv = document.createElement("div");
    tempDiv.innerHTML = logHtml;
    const entry = tempDiv.firstElementChild;
    container.appendChild(entry); // Append because we store them in order
  });
}

// Call this immediately after the DOM is ready or at the end of dashboard.js
document.addEventListener("DOMContentLoaded", loadPersistedLogs);

// ── Clock ──────────────────────────────────────────────────────────────────
function startClock() {
  const el = document.getElementById("clock");
  setInterval(() => {
    el.textContent = new Date().toLocaleTimeString("en-GB", { hour12: false });
  }, 1000);
}

// ── Connection indicator ───────────────────────────────────────────────────
// FIX: only write to DOM when state actually changes (was updating every poll)
function setConnection(online) {
  if (_connected === online) return;   // ← no change, skip DOM write
  _connected = online;
  document.getElementById("connDot").className    = "dot " + (online ? "online" : "offline");
  document.getElementById("connLabel").textContent = online ? "LIVE · DEMO" : "OFFLINE";
}

// Called separately when we know the source
function setSourceLabel(source) {
  const label = source === "live" ? "LIVE TRAFFIC" : "LIVE · DEMO";
  if (_lastSource === label) return;   // ← no change, skip DOM write
  _lastSource = label;
  const el = document.getElementById("connLabel");
  if (el) el.textContent = label;
}

// ── API helpers ────────────────────────────────────────────────────────────
async function apiGet(path) {
  const res = await fetch(API + path);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function apiPost(path, body) {
  const res = await fetch(API + path, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ── Risk gauge ─────────────────────────────────────────────────────────────
let _lastGaugeScore = null;
let _lastGaugeLevel = null;

function updateGauge(score, level) {
  // FIX: skip re-render if nothing changed
  if (score === _lastGaugeScore && level === _lastGaugeLevel) return;
  _lastGaugeScore = score;
  _lastGaugeLevel = level;

  const pct   = Math.min(score / 100, 1);
  const total = 251.2;

  document.getElementById("gaugeFill").style.strokeDashoffset =
    total - pct * total;
  document.getElementById("gaugeNeedle").setAttribute(
    "transform", `rotate(${-90 + pct * 180} 100 100)`
  );

  const colors = { Low: "#22c55e", Medium: "#f59e0b", High: "#f97316", Critical: "#ef4444" };
  const color  = colors[level] || "#e2e8f0";

  const scoreEl = document.getElementById("gaugeScore");
  const levelEl = document.getElementById("gaugeLevel");
  scoreEl.textContent = score;
  scoreEl.style.color = color;
  levelEl.textContent = level?.toUpperCase() ?? "--";
  levelEl.style.color = color;
}

// ── Status cards ───────────────────────────────────────────────────────────
// FIX: track previous card state; only write DOM when values differ
const _cardState = {};

function setTextIfChanged(id, text, colorClass = "") {
  const key = id;
  const val = text + "|" + colorClass;
  if (_cardState[key] === val) return;
  _cardState[key] = val;
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.className   = "card-value" + (colorClass ? " " + colorClass : "");
}

function updateCards(dual) {
  const isAttack = dual.nslkdd_rf_prediction === 1 || dual.cicids_rf_prediction === 1;
  const status   = isAttack ? "ATTACK" : "NORMAL";

  // Status card
  setTextIfChanged("statusVal", status, isAttack ? "attack" : "normal");
  const wantBorder = isAttack ? "rgba(239,68,68,0.4)" : "rgba(34,197,94,0.3)";
  const cardStatus = document.getElementById("cardStatus");
  if (cardStatus && cardStatus.style.borderColor !== wantBorder)
    cardStatus.style.borderColor = wantBorder;

  // Risk level
  setTextIfChanged("riskVal", dual.risk_level ?? "--", `risk-${dual.risk_level}`);

  // Risk score
  setTextIfChanged("scoreVal", String(dual.risk_score ?? "--"), "mono");

  // Per-model cards
  setTextIfChanged("nslRfVal", formatPred(dual.nslkdd_rf_prediction),
    dual.nslkdd_rf_prediction === 1 ? "attack" : "normal");
  setTextIfChanged("nslIfVal", formatAnom(dual.nslkdd_if_prediction),
    dual.nslkdd_if_prediction === 1 ? "attack" : "normal");
  setTextIfChanged("cicRfVal", formatPred(dual.cicids_rf_prediction),
    dual.cicids_rf_prediction === 1 ? "attack" : "normal");
  setTextIfChanged("cicIfVal", formatAnom(dual.cicids_if_prediction),
    dual.cicids_if_prediction === 1 ? "attack" : "normal");

  updateAttackType(dual.attack_type);
}

function updateAttackType(attackType) {
  const el   = document.getElementById("attackTypeVal");
  const card = document.getElementById("cardAttackType");
  if (!el || !attackType) return;

  // FIX: only update DOM if the text actually changed
  if (el.textContent === attackType) return;

  el.textContent = attackType;

  const t = attackType.toLowerCase();
  let cls = "attack-unknown";
  if (t === "normal")                  cls = "attack-normal";
  else if (t.includes("dos"))          cls = "attack-dos";
  else if (t.includes("probe") || t.includes("scan")) cls = "attack-probe";
  else if (t.includes("brute"))        cls = "attack-brute";
  else if (t.includes("web"))          cls = "attack-web";
  else if (t.includes("zero-day") || t.includes("unknown")) cls = "attack-zeroday";

  el.className = `card-value sm ${cls}`;

  const borderColors = {
    "attack-dos":     "rgba(239,68,68,0.4)",
    "attack-probe":   "rgba(249,115,22,0.4)",
    "attack-brute":   "rgba(245,158,11,0.4)",
    "attack-web":     "rgba(167,139,250,0.4)",
    "attack-zeroday": "rgba(253,230,138,0.3)",
    "attack-normal":  "rgba(34,197,94,0.3)",
    "attack-unknown": "rgba(100,116,139,0.2)",
  };
  if (card) card.style.borderColor = borderColors[cls] || "";
}

function formatPred(v) { return v === 1 ? "ATTACK" : v === 0 ? "NORMAL" : "--"; }
function formatAnom(v) { return v === 1 ? "ANOMALY" : v === 0 ? "NORMAL" : "--"; }

// ── Contribution bars ──────────────────────────────────────────────────────
const _barState = {};

function updateContribs(dual) {
  setBar("barNslRf", "pctNslRf", dual.nslkdd_rf_contribution);
  setBar("barNslIf", "pctNslIf", dual.nslkdd_if_contribution);
  setBar("barCicRf", "pctCicRf", dual.cicids_rf_contribution);
  setBar("barCicIf", "pctCicIf", dual.cicids_if_contribution);
}

function setBar(barId, pctId, value) {
  const pct = value ?? 0;
  // FIX: only write DOM when value has changed
  if (_barState[barId] === pct) return;
  _barState[barId] = pct;

  const bar = document.getElementById(barId);
  const lbl = document.getElementById(pctId);
  if (bar) bar.style.width = Math.min(pct, 100) + "%";
  if (lbl) lbl.textContent = pct.toFixed(1) + "%";
}

// ── SHAP chart ─────────────────────────────────────────────────────────────
const shapChart = new Chart(document.getElementById("shapChart"), {
  type: "bar",
  data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 4 }] },
  options: {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 600 },
    scales: {
      x: {
        min: 0,
        ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 11 } },
        grid:  { color: "rgba(255,255,255,0.05)" },
      },
      y: {
        ticks: { color: "#e2e8f0", font: { family: "JetBrains Mono", size: 11 } },
        grid:  { display: false },
      }
    },
    plugins: { legend: { display: false } }
  }
});

function updateSHAP(features) {
  const top = (features || []).slice(0, 10);
  shapChart.data.labels                      = top.map(f => f.feature);
  shapChart.data.datasets[0].data            = top.map(f => Math.abs(f.shap_value));
  shapChart.data.datasets[0].backgroundColor = top.map(f => {
    const v = Math.abs(f.shap_value);
    return v > 0.2 ? "rgba(239,68,68,0.75)"
         : v > 0.1 ? "rgba(245,158,11,0.75)"
         : "rgba(56,189,248,0.75)";
  });
  shapChart.update();
}

// ── AI Explanation ─────────────────────────────────────────────────────────
function buildExplanation(dual, nslExp, cicExp) {
  const container = document.getElementById("expContainer");

  const rfAttack  = dual.nslkdd_rf_prediction === 1 || dual.cicids_rf_prediction === 1;
  const ifAnomaly = dual.nslkdd_if_prediction === 1 || dual.cicids_if_prediction === 1;
  const isZeroDay = ifAnomaly && !rfAttack;
  const confirmed = rfAttack && ifAnomaly;

  let banner = "";
  if (isZeroDay) {
    banner = `
      <div class="anomaly-banner zero-day">
        <span class="anomaly-icon">🛸</span>
        <div>
          <div class="anomaly-title">POSSIBLE ZERO-DAY / UNKNOWN ATTACK</div>
          <div class="anomaly-sub">
            ${dual.attack_type ? `<strong>Type: ${dual.attack_type}</strong> — ` : ""}
            Isolation Forest detected abnormal behaviour not matching known attack patterns.
            RF classifiers report normal — this may be a novel or unseen threat.
          </div>
        </div>
      </div>`;
  } else if (confirmed) {
    banner = `
      <div class="anomaly-banner confirmed">
        <span class="anomaly-icon">🚨</span>
        <div>
          <div class="anomaly-title">CONFIRMED ATTACK — RF + IF BOTH FLAGGED</div>
          <div class="anomaly-sub">
            ${dual.attack_type ? `<strong>Type: ${dual.attack_type}</strong> — ` : ""}
            Both the classifier (RF) and anomaly detector (IF) agree this is malicious traffic.
          </div>
        </div>
      </div>`;
  } else if (ifAnomaly) {
    banner = `
      <div class="anomaly-banner anomaly-only">
        <span class="anomaly-icon">⚠️</span>
        <div>
          <div class="anomaly-title">ANOMALY DETECTED</div>
          <div class="anomaly-sub">
            ${dual.attack_type ? `<strong>Type: ${dual.attack_type}</strong> — ` : ""}
            Isolation Forest flagged unusual traffic patterns. Monitor closely.
          </div>
        </div>
      </div>`;
  }

  const blocks = [
    buildExpBlock("NSL-KDD RF", dual.nslkdd_rf_prediction, nslExp?.top_features),
    buildExpBlock("CICIDS RF",  dual.cicids_rf_prediction,  cicExp?.top_features),
  ].filter(Boolean);

  const rfSection = blocks.length
    ? blocks.join("")
    : `<p class="exp-waiting">No SHAP data available yet.</p>`;

  container.innerHTML = banner + rfSection;
}

function buildExpBlock(source, prediction, topFeatures) {
  if (!topFeatures || topFeatures.length === 0) return null;

  const isAttack  = prediction === 1;
  const cls       = isAttack ? "attack" : "normal";
  const icon      = isAttack ? "⚠️" : "✅";
  const verdict   = isAttack ? "Attack detected" : "Normal traffic";

  const top3      = topFeatures.slice(0, 3);
  const featNames = top3.map(f => `<strong>${f.feature}</strong>`).join(", ");
  const sentence  = isAttack
    ? `Flagged due to high SHAP contribution from ${featNames}.`
    : `Classified as normal. Top contributing features: ${featNames}.`;

  const maxAbs = Math.max(...topFeatures.slice(0, 6).map(f => Math.abs(f.shap_value)));

  const rows = topFeatures.slice(0, 6).map(f => {
    const abs  = Math.abs(f.shap_value);
    const pct  = maxAbs > 0 ? (abs / maxAbs * 100).toFixed(1) : 0;
    const tier = abs > 0.2 ? "high" : abs > 0.1 ? "medium" : "low";
    return `
      <div class="exp-feat-row">
        <span class="exp-feat-name" title="${f.feature}">${f.feature}</span>
        <div class="exp-feat-bar-wrap">
          <div class="exp-feat-bar ${tier}" style="width:${pct}%"></div>
        </div>
        <span class="exp-feat-val">${f.shap_value.toFixed(3)}</span>
      </div>`;
  }).join("");

  return `
    <div class="exp-block ${cls}">
      <div class="exp-block-title">${source} · SHAP</div>
      <div class="exp-verdict"><span class="icon">${icon}</span>${verdict} — ${sentence}</div>
      <div class="exp-features">${rows}</div>
    </div>`;
}

// ── Risk timeline chart ────────────────────────────────────────────────────
const timelineData = { labels: [], values: [] };

const timelineChart = new Chart(document.getElementById("timelineChart"), {
  type: "line",
  data: {
    labels: timelineData.labels,
    datasets: [{
      label: "Risk Score",
      data:  timelineData.values,
      borderColor: "#38bdf8",
      backgroundColor: "rgba(56,189,248,0.07)",
      borderWidth: 2,
      pointRadius: 3,
      pointBackgroundColor: "#38bdf8",
      tension: 0.4,
      fill: true,
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 400 },
    scales: {
      x: { display: false },
      y: {
        min: 0, max: 100,
        ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 11 } },
        grid:  { color: "rgba(255,255,255,0.05)" },
      }
    },
    plugins: { legend: { display: false } }
  }
});

function pushTimeline(score) {
  const ts = new Date().toLocaleTimeString("en-GB", { hour12: false });
  timelineData.labels.push(ts);
  timelineData.values.push(score);
  if (timelineData.labels.length > MAX_PTS) {
    timelineData.labels.shift();
    timelineData.values.shift();
  }
  timelineChart.update();
}

// ── Activity log ───────────────────────────────────────────────────────────


// FIX: build a dedup key from prediction content, NOT from the timestamp.
// This prevents identical predictions from creating duplicate log entries.
function makeLogKey(dual) {
  return [
    dual.nslkdd_rf_prediction,
    dual.nslkdd_if_prediction,
    dual.cicids_rf_prediction,
    dual.cicids_if_prediction,
    dual.risk_level,
    dual.attack_type ?? "",
  ].join("|");
}

function addLog(dual, source = "random") {
  // FIX: skip if this exact prediction state was already logged
  const key = makeLogKey(dual);
  if (key === _lastLogKey) return;
  _lastLogKey = key;

  const container = document.getElementById("activityLog");
  const rfAttack  = dual.nslkdd_rf_prediction === 1 || dual.cicids_rf_prediction === 1;
  const ifAnomaly = dual.nslkdd_if_prediction === 1 || dual.cicids_if_prediction === 1;
  const ts        = new Date().toLocaleTimeString("en-GB", { hour12: false });
  const score     = dual.risk_score ?? "--";
  const level     = dual.risk_level ?? "--";
  const src       = source === "live" ? "LIVE" : "DEMO";

  let tag, cls;
  if (rfAttack && ifAnomaly) { tag = "ATTACK+ANOMALY"; cls = "log-attack";  }
  else if (rfAttack)         { tag = "ATTACK";          cls = "log-attack";  }
  else if (ifAnomaly)        { tag = "ZERO-DAY?";       cls = "log-zeroday"; }
  else                       { tag = "NORMAL";           cls = "log-normal";  }

  const atype = dual.attack_type && dual.attack_type !== "Normal"
    ? ` type=${dual.attack_type}` : "";

  const div = document.createElement("div");
  div.className   = `log-entry ${cls}`;
  div.textContent = `[${ts}] [${src}] [${tag}] risk=${level} score=${score}${atype}`;
  container.insertBefore(div, container.firstChild);

  while (container.children.length > 50) container.removeChild(container.lastChild);

  // --- PERSISTENCE CHANGES START HERE ---
  
  // 1. Update the counter
  logCount++;
  document.getElementById("logCount").textContent = logCount;
  localStorage.setItem("xai_log_count", logCount);

  // 2. Update the persistent log array
  // We store the 'outerHTML' so the CSS classes (colors) are preserved
  persistedLogs.unshift(div.outerHTML); 
  
  // Keep the persistent array capped at 50 to match the UI
  if (persistedLogs.length > 50) persistedLogs.pop();
  
  // 3. Save to localStorage
  localStorage.setItem("xai_logs", JSON.stringify(persistedLogs));
  
  // --- PERSISTENCE CHANGES END HERE ---
}

// ── Model health badges ────────────────────────────────────────────────────
async function checkHealth() {
  try {
    const data = await apiGet("/api/health");
    for (const [ds, status] of Object.entries(data.models)) {
      setModelBadge(`m-${ds}-rf`, status.rf_model);
      setModelBadge(`m-${ds}-if`, status.if_model);
    }
  } catch { /* ignore */ }
}

function setModelBadge(id, ready) {
  const el = document.getElementById(id);
  if (!el) return;
  const want    = ready ? "READY" : "MISSING";
  const wantCls = "mbadge " + want;
  // FIX: only write DOM when value changes
  if (el.textContent === want && el.className === wantCls) return;
  el.textContent = want;
  el.className   = wantCls;
}

// ── Main poll loop ─────────────────────────────────────────────────────────
//
// FIX summary:
//   1. _polling guard prevents overlapping executions (was already present,
//      kept and verified it covers the full async span including SHAP).
//   2. `isNew` now compares ts strings — but ts from the backend is now
//      stable (see app.py fix), so this correctly detects real changes.
//   3. Gauge / cards / contribs only write to DOM if values changed (see
//      per-function guards above) — eliminates visual flicker.
//   4. SHAP is decoupled from the poll guard: it fires as a detached async
//      call so the _polling flag is released immediately after the main
//      prediction update, preventing poll-skip cascades.
//   5. Log deduplication is content-based (makeLogKey), not timestamp-based.

async function poll() {
  if (_polling) return;   // previous poll still running — skip this tick
  _polling = true;

  try {
    const latest = await apiGet("/api/latest");
    const dual   = latest.prediction;
    const source = latest.source;
    const ts     = latest.ts ?? null;

    // Connection state — only writes DOM when it actually changes
    setConnection(true);
    setSourceLabel(source);

    // ── Always update cards/gauge/contribs (guarded internally) ───────────
    updateCards(dual);
    updateGauge(dual.risk_score, dual.risk_level);
    updateContribs(dual);

    // ── Timeline + log — only on genuinely new predictions ─────────────────
    const signature = JSON.stringify({
      n1: dual.nslkdd_rf_prediction,
      n2: dual.cicids_rf_prediction,
      i1: dual.nslkdd_if_prediction,
      i2: dual.cicids_if_prediction,
      r:  dual.risk_score,
      t:  dual.attack_type
    });

    // Always update timeline
pushTimeline(dual.risk_score ?? 0);

// Determine if this is a new entry
const isNewEntry = !_lastTs || ts !== _lastTs || signature !== _lastSignature;

if (isNewEntry) {
  // update the last seen markers
  _lastTs = ts;
  _lastSignature = signature;

  // Add log to dashboard
  addLog(dual, source);
}
    // ── SHAP — FIX: fire as a detached async call so it does NOT hold
    //   the _polling guard. This prevents poll-skip cascades when SHAP is slow.
    const now = Date.now();

    if (!_lastExplainTs || (isNewTs && now - _lastExplainTs >= EXPLAIN_MS)) {
      _lastExplainTs = now;

      const featuresSnapshot = latest.features;

      (async () => {
        try {
          const explainRes = await apiPost("/api/explain/dual", {
            features: featuresSnapshot
          });

          const nslExp = explainRes.nslkdd_explanation;
          const cicExp = explainRes.cicids_explanation;

          if (nslExp?.top_features) {
            updateSHAP(nslExp.top_features);
          }

          buildExplanation(dual, nslExp, cicExp);

        } catch (err) {
          console.warn("SHAP error:", err.message);
        }
      })();
    }

  } catch (err) {
    setConnection(false);
    console.warn("Poll error:", err.message);
  } finally {
    _polling = false;   // always release, even on error
  }
}

// ── Init ───────────────────────────────────────────────────────────────────
startClock();
checkHealth();

poll();
setInterval(poll, POLL_MS);
setInterval(checkHealth, 30000);