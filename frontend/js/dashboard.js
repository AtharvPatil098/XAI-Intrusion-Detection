// dashboard.js — XAI-IDS Security Operations Dashboard

const BASE_URL = "http://127.0.0.1:8000";
const POLL_MS  = 2000;

// ── Clock ──────────────────────────────────────────────────────────────────
function startClock() {
  const el = document.getElementById("clock");
  setInterval(() => {
    el.textContent = new Date().toLocaleTimeString("en-GB", { hour12: false });
  }, 1000);
}

// ── Connection indicator ───────────────────────────────────────────────────
function setConnection(online) {
  document.getElementById("connDot").className   = "dot " + (online ? "online" : "offline");
  document.getElementById("connLabel").textContent = online ? "LIVE" : "OFFLINE";
}

// ── API fetch helper ───────────────────────────────────────────────────────
async function api(path) {
  const res = await fetch(BASE_URL + path);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ── Traffic Chart (line) ───────────────────────────────────────────────────
const TRAFFIC_MAX = 30;
const trafficData = { labels: [], values: [] };

const trafficChart = new Chart(document.getElementById("trafficChart"), {
  type: "line",
  data: {
    labels: trafficData.labels,
    datasets: [{
      label: "Alerts",
      data: trafficData.values,
      borderColor: "#38bdf8",
      backgroundColor: "rgba(56,189,248,0.08)",
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
        min: 0,
        ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 11 } },
        grid:  { color: "rgba(255,255,255,0.05)" },
      }
    },
    plugins: { legend: { display: false } }
  }
});

function pushTraffic(alertCount) {
  const time = new Date().toLocaleTimeString("en-GB", { hour12: false });
  trafficData.labels.push(time);
  trafficData.values.push(alertCount);
  if (trafficData.labels.length > TRAFFIC_MAX) {
    trafficData.labels.shift();
    trafficData.values.shift();
  }
  trafficChart.update();
}

// ── Feature Chart (horizontal bar) ────────────────────────────────────────
const featureChart = new Chart(document.getElementById("featureChart"), {
  type: "bar",
  data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 4 }] },
  options: {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 500 },
    scales: {
      x: {
        min: 0, max: 1,
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

function updateFeatureChart(features) {
  const top = features.slice(0, 8);
  featureChart.data.labels = top.map(f => f.name);
  featureChart.data.datasets[0].data  = top.map(f => f.value);
  featureChart.data.datasets[0].backgroundColor = top.map(f =>
    f.value > 0.7 ? "rgba(239,68,68,0.7)"
    : f.value > 0.4 ? "rgba(245,158,11,0.7)"
    : "rgba(56,189,248,0.7)"
  );
  featureChart.update();
}

// ── Explanation panel ──────────────────────────────────────────────────────
function buildExplanation(features, prediction) {
  const isAttack = prediction?.prediction === "ATTACK";
  const top = features.slice(0, 3).map(f => `<strong>${f.name}</strong> (${f.value.toFixed(2)})`).join(", ");
  const icon = isAttack ? "⚠️" : "✅";
  const text = isAttack
    ? `Potential attack detected — high contribution from ${top}.`
    : `Traffic appears normal. Top contributing features: ${top}.`;

  const el  = document.getElementById("explanation");
  const cls = isAttack ? "attack-row" : "";
  el.innerHTML = `<div class="explain-row ${cls}"><span class="icon">${icon}</span><span>${text}</span></div>`;
}

// ── Logs panel ─────────────────────────────────────────────────────────────
function renderLogs(logs) {
  const container = document.getElementById("logs");
  const latest    = logs.slice(-20).reverse();
  container.innerHTML = latest.map(line => {
    const cls = /attack/i.test(line) ? "log-attack" : "log-normal";
    return `<div class="log-entry ${cls}">${line}</div>`;
  }).join("");
  document.getElementById("logCount").textContent = logs.length;
}

// ── Status card helpers ────────────────────────────────────────────────────
function setStatus(status) {
  const el  = document.getElementById("statusVal");
  el.textContent = status;
  el.className   = "card-value " + (status === "ATTACK" ? "attack" : "normal");
  document.getElementById("cardStatus").style.borderColor =
    status === "ATTACK" ? "rgba(239,68,68,0.5)" : "rgba(34,197,94,0.3)";
}

function setRisk(risk) {
  const el  = document.getElementById("riskVal");
  el.textContent = risk;
  el.className   = `card-value risk-${risk.toLowerCase()}`;
}

// ── Main poll loop ─────────────────────────────────────────────────────────
async function poll() {
  try {
    const [realtime, predict, explain, logs] = await Promise.all([
      api("/realtime"),
      api("/predict"),
      api("/explain"),
      api("/logs"),
    ]);

    setConnection(true);

    // Cards
    setStatus(realtime.status);
    setRisk(realtime.risk);
    document.getElementById("alertsVal").textContent = realtime.alerts;
    document.getElementById("modelVal").textContent  = predict.model  ?? "--";
    document.getElementById("confVal").textContent   =
      predict.confidence != null ? (predict.confidence * 100).toFixed(1) + "%" : "--";

    // Charts & panels
    pushTraffic(realtime.alerts);
    updateFeatureChart(explain.features ?? []);
    buildExplanation(explain.features ?? [], predict);
    renderLogs(logs.logs ?? []);

  } catch (err) {
    setConnection(false);
    console.warn("Poll error:", err.message);
  }
}

// ── Init ───────────────────────────────────────────────────────────────────
startClock();
poll();
setInterval(poll, POLL_MS);