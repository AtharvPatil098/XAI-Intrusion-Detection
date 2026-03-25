// dashboard.js — XAI-IDS Full Dashboard (auto-polling, dual mode)

const API      = "http://127.0.0.1:8000";
const POLL_MS  = 2000;
const MAX_PTS  = 30;      // max data points on timeline
let isPolling = false;
let _lastTs = null;       // timestamp of last processed prediction — skip duplicates
let lastLogSignature = null;
// ── Clock ──────────────────────────────────────────────────────────────────
function startClock() {
  const el = document.getElementById("clock");
  setInterval(() => {
    el.textContent = new Date().toLocaleTimeString("en-GB", { hour12: false });
  }, 1000);
}

// ── Connection indicator ───────────────────────────────────────────────────
function setConnection(online) {
  document.getElementById("connDot").className    = "dot " + (online ? "online" : "offline");
  document.getElementById("connLabel").textContent = online ? "LIVE" : "OFFLINE";
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
function updateGauge(score, level) {
  const pct    = Math.min(score / 100, 1);
  const total  = 251.2;

  document.getElementById("gaugeFill").style.strokeDashoffset = total - pct * total;
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
function updateCards(dual) {
  const isAttack = dual.nslkdd_rf_prediction === 1 || dual.cicids_rf_prediction === 1;
  const status   = isAttack ? "ATTACK" : "NORMAL";

  const statusEl = document.getElementById("statusVal");
  statusEl.textContent = status;
  statusEl.className   = "card-value " + (isAttack ? "attack" : "normal");
  document.getElementById("cardStatus").style.borderColor =
    isAttack ? "rgba(239,68,68,0.4)" : "rgba(34,197,94,0.3)";

  const riskEl = document.getElementById("riskVal");
  riskEl.textContent = dual.risk_level ?? "--";
  riskEl.className   = `card-value risk-${dual.risk_level}`;

  document.getElementById("scoreVal").textContent = dual.risk_score ?? "--";

  setText("nslRfVal", formatPred(dual.nslkdd_rf_prediction),
          dual.nslkdd_rf_prediction === 1 ? "attack" : "normal");
  setText("nslIfVal", formatAnom(dual.nslkdd_if_prediction),
          dual.nslkdd_if_prediction === 1 ? "attack" : "normal");
  setText("cicRfVal", formatPred(dual.cicids_rf_prediction),
          dual.cicids_rf_prediction === 1 ? "attack" : "normal");
  setText("cicIfVal", formatAnom(dual.cicids_if_prediction),
          dual.cicids_if_prediction === 1 ? "attack" : "normal");

  // Attack type card
  updateAttackType(dual.attack_type);
}

function updateAttackType(attackType) {
  const el  = document.getElementById("attackTypeVal");
  const card = document.getElementById("cardAttackType");
  if (!el || !attackType) return;

  el.textContent = attackType;

  // Colour code by category
  const t = attackType.toLowerCase();
  let cls = "attack-unknown";
  if (t === "normal")                    cls = "attack-normal";
  else if (t.includes("dos"))            cls = "attack-dos";
  else if (t.includes("probe") ||
           t.includes("scan"))           cls = "attack-probe";
  else if (t.includes("brute"))         cls = "attack-brute";
  else if (t.includes("web"))           cls = "attack-web";
  else if (t.includes("zero-day") ||
           t.includes("unknown"))       cls = "attack-zeroday";

  el.className = `card-value sm ${cls}`;

  // Also highlight the card border
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

function setText(id, text, colorClass = "") {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.className   = "card-value" + (colorClass ? " " + colorClass : "");
}

function formatPred(v) { return v === 1 ? "ATTACK" : v === 0 ? "NORMAL" : "--"; }
function formatAnom(v) { return v === 1 ? "ANOMALY" : v === 0 ? "NORMAL" : "--"; }

// ── Contribution bars ──────────────────────────────────────────────────────
function updateContribs(dual) {
  setBar("barNslRf", "pctNslRf", dual.nslkdd_rf_contribution);
  setBar("barNslIf", "pctNslIf", dual.nslkdd_if_contribution);
  setBar("barCicRf", "pctCicRf", dual.cicids_rf_contribution);
  setBar("barCicIf", "pctCicIf", dual.cicids_if_contribution);
}

function setBar(barId, pctId, value) {
  const pct = value ?? 0;
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
  shapChart.data.labels                       = top.map(f => f.feature);
  shapChart.data.datasets[0].data             = top.map(f => Math.abs(f.shap_value));
  shapChart.data.datasets[0].backgroundColor  = top.map(f => {
    const v = Math.abs(f.shap_value);
    return v > 0.2  ? "rgba(239,68,68,0.75)"
         : v > 0.1  ? "rgba(245,158,11,0.75)"
         : "rgba(56,189,248,0.75)";
  });
  shapChart.update();
}

// ── AI Explanation ─────────────────────────────────────────────────────────

function buildExplanation(dual, nslExp, cicExp) {
  const container = document.getElementById("expContainer");

  // ── Determine detection scenario ──────────────────────────────────────────
  const rfAttack  = dual.nslkdd_rf_prediction === 1 || dual.cicids_rf_prediction  === 1;
  const ifAnomaly = dual.nslkdd_if_prediction === 1 || dual.cicids_if_prediction  === 1;

  // Zero-day: IF flags anomaly but RF sees nothing suspicious
  const isZeroDay = ifAnomaly && !rfAttack;
  // Confirmed: both RF and IF agree
  const confirmed = rfAttack && ifAnomaly;

  // Build anomaly banner (shown whenever IF fires)
  let banner = "";
  if (isZeroDay) {
    banner = `
      <div class="anomaly-banner zero-day">
        <span class="anomaly-icon">🛸</span>
        <div>
          <div class="anomaly-title">POSSIBLE ZERO-DAY / UNKNOWN ATTACK</div>
          <div class="anomaly-sub">
            ${dual.attack_type ? `<strong>Type: ${dual.attack_type}</strong> — ` : ""}
            Isolation Forest detected abnormal behaviour not matching known attack patterns. RF classifiers report normal — this may be a novel or unseen threat.
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

  // Build SHAP explanation blocks for RF models
  const blocks = [
    buildExpBlock("NSL-KDD RF", dual.nslkdd_rf_prediction, nslExp?.top_features),
    buildExpBlock("CICIDS RF",  dual.cicids_rf_prediction,  cicExp?.top_features),
  ].filter(Boolean);

  const rfSection = blocks.length
    ? blocks.join("")
    : `<p class="exp-waiting">No SHAP data available yet.</p>`;

 // Clear ONLY explanation section (safe)
 container.innerHTML = "";

 // Create wrapper (prevents full DOM reflow issues)
 const wrapper = document.createElement("div");
 wrapper.innerHTML = banner + rfSection;

 // Append safely
 container.appendChild(wrapper);
}

function buildExpBlock(source, prediction, topFeatures) {
  if (!topFeatures || topFeatures.length === 0) return null;

  const isAttack  = prediction === 1;
  const cls       = isAttack ? "attack" : "normal";
  const icon      = isAttack ? "⚠️" : "✅";
  const verdict   = isAttack ? "Attack detected" : "Normal traffic";

  // Human-readable sentence from top 3 features
  const top3      = topFeatures.slice(0, 3);
  const featNames = top3.map(f => `<strong>${f.feature}</strong>`).join(", ");
  const sentence  = isAttack
    ? `Flagged due to high SHAP contribution from ${featNames}.`
    : `Classified as normal. Top contributing features: ${featNames}.`;

  // Max absolute value for bar scaling
  const maxAbs = Math.max(...topFeatures.slice(0, 6).map(f => Math.abs(f.shap_value)));

  // Feature rows with mini bars
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
let logCount = 0;

function addLog(dual, source = "random") {
  const container = document.getElementById("activityLog");
  const rfAttack  = dual.nslkdd_rf_prediction === 1 || dual.cicids_rf_prediction === 1;
  const ifAnomaly = dual.nslkdd_if_prediction === 1 || dual.cicids_if_prediction === 1;
  const ts        = new Date().toLocaleTimeString("en-GB", { hour12: false });
  const score     = dual.risk_score ?? "--";
  const level     = dual.risk_level ?? "--";
  const src       = source === "live" ? "LIVE" : "DEMO";

  // Determine log tag and style
  let tag, cls;
  if (rfAttack && ifAnomaly)    { tag = "ATTACK+ANOMALY";  cls = "log-attack";   }
  else if (rfAttack)            { tag = "ATTACK";           cls = "log-attack";   }
  else if (ifAnomaly)           { tag = "ZERO-DAY?";        cls = "log-zeroday";  }
  else                          { tag = "NORMAL";            cls = "log-normal";   }

  const atype = dual.attack_type && dual.attack_type !== "Normal"
               ? ` type=${dual.attack_type}` : "";

  const div = document.createElement("div");
  div.className   = `log-entry ${cls}`;
  div.textContent = `[${ts}] [${src}] [${tag}] risk=${level} score=${score}${atype}`;
  container.appendChild(div);

  while (container.children.length > 100) 
    container.removeChild(container.lastChild);

  container.scrollTop = container.scrollHeight;
  logCount++;
  document.getElementById("logCount").textContent = logCount;
}

// ── Dataset stats ──────────────────────────────────────────────────────────
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
  el.textContent = ready ? "READY" : "MISSING";
  el.className   = "mbadge " + (ready ? "READY" : "MISSING");
}

// ── Main poll loop ─────────────────────────────────────────────────────────
async function poll() {
  if (isPolling) return;
  isPolling = true; 
  try {
    // /api/latest returns live traffic if flow_extractor is running,
    // otherwise falls back to a random sample automatically
    const latest = await apiGet("/api/latest");
    const dual   = latest.prediction;
    const source = latest.source;
    const ts     = latest.ts ?? null;

    setConnection(true);

    // Show source indicator in header
    const connLabel = document.getElementById("connLabel");
    if (connLabel) {
      connLabel.textContent = source === "live" ? "LIVE TRAFFIC" : "LIVE · DEMO";
    }

    // Always update the gauge and cards (smooth live feel)
    updateCards(dual);
    updateGauge(dual.risk_score, dual.risk_level);
    updateContribs(dual);
    pushTimeline(dual.risk_score ?? 0);

    // Only log + re-explain when the prediction is actually new
    // (avoids duplicate log entries when no new flow has arrived yet)
    
    const isNew = ts !== _lastTs;
    if (isNew || !_lastTs) {
      _lastTs = ts;
      const signature = JSON.stringify({
        n1: dual.nslkdd_rf_prediction,
        n2: dual.cicids_rf_prediction,
        r:  dual.risk_score,
        t:  dual.attack_type
      });

    if (signature !== lastLogSignature) {
      lastLogSignature = signature;
      addLog(dual, source);
    }

      // SHAP is expensive — only run when prediction changed
      const explainRes = await apiPost("/api/explain/dual", { features: latest.features });
      const nslExp = explainRes.nslkdd_explanation;
      const cicExp = explainRes.cicids_explanation;
      if (nslExp?.top_features) updateSHAP(nslExp.top_features);
      if (isNew) {
        buildExplanation(dual, nslExp, cicExp);
      }
    }

  } catch (err) {
    setConnection(false);
    console.warn("Poll error:", err.message);
  }finally {
    isPolling = false;   // ✅ RELEASE LOCK
  }
}

// ── Init ───────────────────────────────────────────────────────────────────
if (!window.__POLL_STARTED__) {
  window.__POLL_STARTED__ = true;

  startClock();
  checkHealth();

  setInterval(poll, POLL_MS);
  setInterval(checkHealth, 30000);
}