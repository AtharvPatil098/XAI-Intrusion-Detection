// ==============================
// 🔹 API URL
// ==============================
const API_URL = "http://127.0.0.1:8000/predict_sample";

// ==============================
// 🔹 INIT AFTER DOM LOAD
// ==============================
let shapChart;

document.addEventListener("DOMContentLoaded", () => {

    const ctx = document.getElementById('shapChart').getContext('2d');

    shapChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Feature Influence',
                data: [],
                backgroundColor: 'rgba(0, 255, 102, 0.6)',
                borderColor: '#00ff66',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: '#ccc' } },
                y: { ticks: { color: '#fff' } }
            },
            plugins: { legend: { display: false } }
        }
    });

    fetchPrediction();
    setInterval(fetchPrediction, 3000);
});


// ==============================
// 🔹 FETCH
// ==============================
async function fetchPrediction() {
    try {
        const response = await fetch(API_URL);
        if (!response.ok) throw new Error("API error");

        const data = await response.json();
        updateDashboard(data);

    } catch (error) {
        console.error("🚨 API Error:", error);
    }
}


// ==============================
// 🔹 UPDATE UI
// ==============================
function updateDashboard(data) {

    if (!data) return;

    const scoreElement = document.getElementById('threat-score');
    const feedElement = document.getElementById('live-feed');
    const reasonList = document.getElementById('reason-list');
    const statusText = document.getElementById('status-text');

    const timeString = new Date().toLocaleTimeString();

    const risk = data.risk_score || 0;
    const prediction = data.prediction || "Unknown";
    const attackType = data.attack_type || "Normal";
    const explanation = data.explanation || [];

    // ==========================
    // 🔥 STATUS COLOR LOGIC (FIXED)
    // ==========================
    let color = "var(--neon-green)";
    let statusLabel = "Normal ✔";

    if (prediction === "Attack") {
        color = "var(--neon-red)";
        statusLabel = `Attack 🚨 (${attackType})`;
    }
    else if (prediction === "Unknown Attack") {
        color = "#ffaa00";
        statusLabel = "Unknown Attack ⚠️";
    }

    scoreElement.innerText = risk + "%";
    scoreElement.style.color = color;
    scoreElement.style.textShadow = `0 0 15px ${color}`;
    statusText.innerText = "Status: " + statusLabel;

    // ==========================
    // 🔥 LIVE FEED (COLOR FIX)
    // ==========================
    const item = document.createElement('div');
    item.className = 'feed-item';

    item.innerText = `[${timeString}] ${prediction} (${attackType}) | Risk: ${risk}`;

    item.style.color = color;
    item.style.borderLeftColor = color;

    feedElement.prepend(item);

    // limit to 15
    if (feedElement.children.length > 15) {
        feedElement.removeChild(feedElement.lastChild);
    }

    // ==========================
    // 🔥 EXPLANATION
    // ==========================
    reasonList.innerHTML = "";

    explanation.slice(0, 5).forEach(e => {
        const li = document.createElement("li");
        li.innerText = e.reason || e.feature || "Unknown factor";
        reasonList.appendChild(li);
    });

    // ==========================
    // 🔥 SHAP CHART (REAL VALUES)
    // ==========================
    shapChart.data.labels = explanation.map(e => e.feature || "Feature");

    shapChart.data.datasets[0].data = explanation.map(e =>
        Math.abs(e.value || 0.01)
    );

    shapChart.data.datasets[0].backgroundColor = color;
    shapChart.data.datasets[0].borderColor = color;

    shapChart.update();
}