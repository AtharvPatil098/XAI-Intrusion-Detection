# app.py
# FastAPI backend for the XAI Intrusion Detection System.
#
# Run: python app.py
#  OR: uvicorn app:app --host 0.0.0.0 --port 8000
#
# ⚠️  DO NOT use --reload when the log writer is active.
#     Uvicorn's file watcher sees every CSV write as a "file changed" event
#     and restarts the server every 3 seconds, causing the browser to
#     connect → disconnect → connect in an endless loop.

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import io
import pandas as pd
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from model.predict import Predictor, DualPredictor
from model.risk_score import compute_risk_score, compute_dual_risk_score
from explainability.explanation_engine import ExplanationEngine
from utils.helpers import (numpy_to_python, sample_random_record,
                           summarise_results, summarise_dual_results)
from config import DATA_PROCESSED, MODELS_NSLKDD, MODELS_CICIDS, API_HOST, API_PORT, LOGS_DIR

app = FastAPI(
    title="XAI Intrusion Detection System",
    description="Explainable AI intrusion detection using NSL-KDD and CICIDS datasets.",
    version="1.0.0",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
SOC_DIR      = os.path.join(FRONTEND_DIR, "soc")

if os.path.exists(SOC_DIR):
    app.mount("/soc",       StaticFiles(directory=SOC_DIR,      html=True), name="soc")
if os.path.exists(FRONTEND_DIR):
    app.mount("/dashboard", StaticFiles(directory=FRONTEND_DIR, html=True), name="dashboard")


# ── Model registry ────────────────────────────────────────────────────────────

class ModelRegistry:
    """Lazy-loads and caches all predictors and explainers."""

    def __init__(self):
        self._predictors:     Dict[str, Predictor]         = {}
        self._explainers:     Dict[str, ExplanationEngine] = {}
        self._dual_predictor: Optional[DualPredictor]      = None

    def predictor(self, dataset: str) -> Predictor:
        if dataset not in self._predictors:
            self._predictors[dataset] = Predictor(dataset)
        return self._predictors[dataset]

    def explainer(self, dataset: str) -> ExplanationEngine:
        if dataset not in self._explainers:
            self._explainers[dataset] = ExplanationEngine(dataset)
        return self._explainers[dataset]

    def dual_predictor(self) -> DualPredictor:
        if self._dual_predictor is None:
            self._dual_predictor = DualPredictor()
        return self._dual_predictor


registry = ModelRegistry()


# ── In-memory log buffer (used by GET /logs) ──────────────────────────────────
from collections import deque
from datetime import datetime

_log_buffer: deque = deque(maxlen=100)

def _write_log(status: str, risk: str, confidence: float, dataset: str = "dual"):
    ts   = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] [{status}] risk={risk} conf={confidence:.2f} src={dataset}"
    _log_buffer.appendleft(line)


# ── Request / response models ─────────────────────────────────────────────────

class PredictRequest(BaseModel):
    dataset:  str            = "nslkdd"
    features: Dict[str, Any]

class DualPredictRequest(BaseModel):
    features: Dict[str, Any]

class ExplainRequest(BaseModel):
    dataset:  str            = "nslkdd"
    features: Dict[str, Any]
    top_n:    int            = 10


# ── Helpers ───────────────────────────────────────────────────────────────────

def validate_dataset(dataset: str):
    if dataset.lower() not in ["nslkdd", "cicids"]:
        raise HTTPException(400, "dataset must be 'nslkdd' or 'cicids'")


def run_prediction(dataset: str, features: dict) -> dict:
    pred           = registry.predictor(dataset).predict(features)
    rf_prob_attack = pred["rf_probability"][1] if pred["rf_probability"] else 0.5
    anomaly_score  = pred["anomaly_score"]     if pred["anomaly_score"] is not None else -0.3
    risk           = compute_risk_score(rf_prob_attack, anomaly_score)
    return numpy_to_python({**pred, **risk})


def infer_attack_type(features: dict, rf_attack: bool, if_anomaly: bool) -> str:
    if not rf_attack and not if_anomaly:
        return "Normal"

    serr   = float(features.get("serror_rate", 0))
    rerr   = float(features.get("rerror_rate", 0))
    count  = float(features.get("count", 0))
    diff   = float(features.get("diff_srv_rate", 0))
    flag   = str(features.get("flag", ""))
    proto  = str(features.get("protocol_type", ""))
    port   = int(features.get("Destination Port", features.get("dst_port", 0)))
    syn    = float(features.get("SYN Flag Count", features.get("syn_count", 0)))
    dst_b  = float(features.get("dst_bytes", features.get("Total Length of Bwd Packets", 0)))
    src_b  = float(features.get("src_bytes", features.get("Total Length of Fwd Packets", 0)))
    pkts_s = float(features.get("Flow Packets/s", 0))

    if serr > 0.5 and count > 50:                return "DoS — SYN Flood (Neptune)"
    if syn > 200:                                 return "DoS — SYN Flood"
    if pkts_s > 10000:                            return "DoS — Flood Attack"
    if proto == "icmp" and count > 50:            return "DoS — ICMP Flood (Smurf)"
    if count > 200 and dst_b == 0:                return "DoS — UDP/Null Flood"
    if rerr > 0.5 and diff > 0.5 and count > 20:  return "Probe — Port Scan"
    if rerr > 0.3 and diff > 0.7:                 return "Probe — Port Sweep"
    if diff > 0.8 and count > 10:                 return "Probe — Network Scan"
    if flag in ("REJ", "S0") and diff > 0.3:      return "Probe — Stealth Scan"
    if port == 22 and src_b > 0 and dst_b == 0:   return "Brute Force — SSH"
    if port == 21 and src_b > 0 and dst_b == 0:   return "Brute Force — FTP"
    if port in (23, 3389) and count > 5:          return "Brute Force — Remote Login"
    if port in (80, 443, 8080) and src_b > 5000:  return "Web Attack"
    if if_anomaly and not rf_attack:              return "Unknown — Possible Zero-Day"
    return "Attack — Unclassified"


# ── Stable timestamp: only update _latest["ts"] when content changes ──────────
def _prediction_fingerprint(result: dict) -> str:
    return "|".join(str(result.get(k, "")) for k in [
        "nslkdd_rf_prediction",
        "nslkdd_if_prediction",
        "cicids_rf_prediction",
        "cicids_if_prediction",
        "risk_level",
        "attack_type",
    ])

_last_live_fingerprint = [None]


def run_dual_prediction(features: dict, store_as_latest: bool = True) -> dict:
    """
    Run all 4 models simultaneously and attach combined risk score + attack type.

    store_as_latest=True  — updates _latest only when content changes
    store_as_latest=False — pure computation, no side effects (random cache)
    """
    pred = registry.dual_predictor().predict(features)

    nslkdd_rf_prob = pred["nslkdd_rf_probability"][1] if pred["nslkdd_rf_probability"] else 0.5
    nslkdd_anom    = pred["nslkdd_anomaly_score"]     if pred["nslkdd_anomaly_score"] is not None else -0.3
    cicids_rf_prob = pred["cicids_rf_probability"][1]  if pred["cicids_rf_probability"]  else 0.5
    cicids_anom    = pred["cicids_anomaly_score"]      if pred["cicids_anomaly_score"]  is not None else -0.3

    risk   = compute_dual_risk_score(nslkdd_rf_prob, nslkdd_anom, cicids_rf_prob, cicids_anom)
    result = numpy_to_python({**pred, **risk})

    rf_attack  = (pred["nslkdd_rf_prediction"] == 1 or pred["cicids_rf_prediction"] == 1)
    if_anomaly = (pred["nslkdd_if_prediction"] == 1 or pred["cicids_if_prediction"] == 1)
    result["attack_type"] = infer_attack_type(features, rf_attack, if_anomaly)

    fingerprint = _prediction_fingerprint(result)  # ✅ ADD THIS LINE

    if store_as_latest:
        if fingerprint != _last_live_fingerprint[0]:
            _last_live_fingerprint[0] = fingerprint

            _latest["prediction"] = result
            _latest["features"]   = features
            _latest["source"]     = "live"
            _latest["ts"]         = datetime.now().isoformat()

            log_writer.write(result, features, "live")

    return result


# ── Latest prediction store ───────────────────────────────────────────────────
_latest: dict = {"prediction": None, "features": None, "source": "random", "ts": None}


# ── Log writer ────────────────────────────────────────────────────────────────

import csv
import threading

class LogWriter:
    """
    Appends one row per prediction to a daily CSV in LOGS_DIR.
    LOGS_DIR must be outside the Python source tree so uvicorn's watcher
    (if ever re-enabled) does not see CSV writes as code changes.
    Thread-safe.
    """

    COLUMNS = [
        "timestamp", "source",
        "src_ip", "dst_ip", "protocol",
        "risk_level", "risk_score", "attack_type",
        "nslkdd_rf", "nslkdd_if", "cicids_rf", "cicids_if",
        "nslkdd_anom_score", "cicids_anom_score",
    ]

    def __init__(self, logs_dir: str):
        self.logs_dir = logs_dir
        self.lock     = threading.Lock()
        os.makedirs(logs_dir, exist_ok=True)

    def _log_path(self) -> str:
        today = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.logs_dir, f"ids_log_{today}.csv")

    def write(self, result: dict, features: dict, source: str):
        path   = self._log_path()
        is_new = not os.path.exists(path)

        src_ip   = features.get("src_ip",        features.get("Source IP",      ""))
        dst_ip   = features.get("dst_ip",        features.get("Destination IP", ""))
        protocol = features.get("protocol_type", features.get("protocol",       ""))

        row = {
            "timestamp":         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source":            source,
            "src_ip":            src_ip,
            "dst_ip":            dst_ip,
            "protocol":          protocol,
            "risk_level":        result.get("risk_level",  ""),
            "risk_score":        result.get("risk_score",  ""),
            "attack_type":       result.get("attack_type", ""),
            "nslkdd_rf":         result.get("nslkdd_rf_prediction", ""),
            "nslkdd_if":         result.get("nslkdd_if_prediction", ""),
            "cicids_rf":         result.get("cicids_rf_prediction",  ""),
            "cicids_if":         result.get("cicids_if_prediction",  ""),
            "nslkdd_anom_score": result.get("nslkdd_anomaly_score",  ""),
            "cicids_anom_score": result.get("cicids_anomaly_score",  ""),
        }

        with self.lock:
            with open(path, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self.COLUMNS)
                if is_new:
                    writer.writeheader()
                writer.writerow(row)


log_writer    = LogWriter(LOGS_DIR)
_random_cache: dict = {"prediction": None, "features": None, "ts": None, "cache_ts": None}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/dashboard")


@app.get("/api/health")
def health():
    def model_status(model_dir, csv_name):
        return {
            "rf_model":  os.path.exists(os.path.join(model_dir, "rf_model.pkl")),
            "if_model":  os.path.exists(os.path.join(model_dir, "if_model.pkl")),
            "processed": os.path.exists(os.path.join(DATA_PROCESSED, csv_name)),
        }
    return {
        "status": "ok",
        "models": {
            "nslkdd": model_status(MODELS_NSLKDD, "nsl_kdd_processed.csv"),
            "cicids":  model_status(MODELS_CICIDS,  "cicids_processed.csv"),
        }
    }


@app.post("/api/predict")
def predict(req: PredictRequest):
    validate_dataset(req.dataset)
    return run_prediction(req.dataset.lower(), req.features)


@app.get("/api/latest")
def get_latest():
    """
    Returns the most recent dual prediction.
    - live mode : flow_extractor running → returns _latest
    - demo mode : no live traffic → random sample cached 10 s

    FIX: original code used (timedelta).seconds which wraps at 60 and caused
    the cache to never refresh. Now uses .total_seconds(). Also guards against
    _random_cache["ts"] being None on the very first call.
    """
    if _latest["prediction"] is not None:
        return _latest

    now = datetime.now()
    cache_age = (now - _random_cache["ts"]).total_seconds() \
                if _random_cache["ts"] is not None else float("inf")

    if _random_cache["prediction"] is None or cache_age >= 10:
        features   = sample_random_record("nslkdd")
        prediction = run_dual_prediction(features, store_as_latest=False)
        log_writer.write(prediction, features, "random")
        _random_cache["prediction"] = prediction
        _random_cache["features"]   = features
        _random_cache["ts"]         = now
        _random_cache["cache_ts"]   = now.isoformat()

    return {
        "prediction": _random_cache["prediction"],
        "features":   _random_cache["features"],
        "source":     "random",
        "ts":         _random_cache["cache_ts"],
    }


@app.post("/api/predict/dual")
def predict_dual(req: DualPredictRequest):
    return run_dual_prediction(req.features)


@app.post("/api/predict/csv")
async def predict_csv(file: UploadFile = File(...)):
    content = await file.read()
    df      = pd.read_csv(io.StringIO(content.decode("utf-8"))).head(500)
    results = []
    for _, row in df.iterrows():
        features = {k: v for k, v in row.items()
                    if k not in ["binary_label", "attack_category", "label_encoded"]}
        try:
            results.append(run_dual_prediction(features))
        except Exception as e:
            results.append({"error": str(e)})
    return {"summary": summarise_dual_results(results), "results": results}


@app.post("/api/explain")
def explain(req: ExplainRequest):
    validate_dataset(req.dataset)
    dataset     = req.dataset.lower()
    prediction  = run_prediction(dataset, req.features)
    explanation = registry.explainer(dataset).explain(req.features, top_n=req.top_n)
    return numpy_to_python({"prediction": prediction, "explanation": explanation})


@app.post("/api/explain/dual")
def explain_dual(req: DualPredictRequest):
    prediction  = run_dual_prediction(req.features)
    nslkdd_exp  = registry.explainer("nslkdd").explain(req.features, top_n=12)
    cicids_exp  = registry.explainer("cicids").explain(req.features,  top_n=12)
    return numpy_to_python({
        "prediction":         prediction,
        "nslkdd_explanation": nslkdd_exp,
        "cicids_explanation":  cicids_exp,
    })


@app.get("/api/sample/{dataset}")
def get_sample(dataset: str):
    validate_dataset(dataset)
    try:
        return numpy_to_python({"dataset": dataset,
                                "features": sample_random_record(dataset)})
    except Exception as e:
        raise HTTPException(404, f"Could not load sample: {e}")


_stats_cache: dict = {}

@app.get("/api/stats/{dataset}")
def dataset_stats(dataset: str):
    validate_dataset(dataset)
    if dataset in _stats_cache:
        return _stats_cache[dataset]

    filename = "nsl_kdd_processed.csv" if dataset == "nslkdd" else "cicids_processed.csv"
    path     = os.path.join(DATA_PROCESSED, filename)
    if not os.path.exists(path):
        raise HTTPException(404, f"No processed data for '{dataset}'. Run preprocess script first.")

    df     = pd.read_csv(path, usecols=["binary_label", "attack_category"])
    total  = len(df)
    normal = int((df["binary_label"] == 0).sum())
    attack = int((df["binary_label"] == 1).sum())

    result = {
        "dataset":               dataset,
        "total_records":         total,
        "normal":                normal,
        "attack":                attack,
        "attack_ratio":          round(attack / total * 100, 2),
        "category_distribution": df["attack_category"].value_counts().to_dict()
                                 if "attack_category" in df.columns else {},
        "num_features":          77 if dataset == "cicids" else 41,
    }
    _stats_cache[dataset] = result
    return result


@app.get("/realtime")
def realtime():
    features  = sample_random_record("nslkdd")
    result    = run_dual_prediction(features)
    is_attack = (result["nslkdd_rf_prediction"] == 1 or result["cicids_rf_prediction"] == 1)
    status    = "ATTACK" if is_attack else "NORMAL"
    risk      = result["risk_level"]
    conf      = result["nslkdd_rf_probability"][1] if result["nslkdd_rf_probability"] else 0.5
    _write_log(status, risk, conf)
    return {"status": status, "alerts": 1 if is_attack else 0, "risk": risk}


@app.get("/predict")
def predict_get():
    features = sample_random_record("nslkdd")
    result   = run_dual_prediction(features)
    rf_prob  = result["nslkdd_rf_probability"]
    conf     = rf_prob[1] if rf_prob else 0.5
    return {
        "prediction": "ATTACK" if result["nslkdd_rf_prediction"] == 1 else "NORMAL",
        "confidence": round(conf, 4),
        "model":      "NSL-KDD + CICIDS Dual RF/IF",
    }


@app.get("/explain")
def explain_get():
    features     = sample_random_record("nslkdd")
    explanation  = registry.explainer("nslkdd").explain(features, top_n=8)
    top_features = explanation.get("top_features", [])
    return {
        "features": [
            {"name": f["feature"], "value": round(abs(f["shap_value"]), 4)}
            for f in top_features
        ]
    }


@app.get("/logs")
def logs_get():
    return {"logs": list(_log_buffer)[:20]}


@app.get("/api/logs/today")
def logs_today():
    path = log_writer._log_path()
    if not os.path.exists(path):
        raise HTTPException(404, "No log file for today yet.")
    filename = os.path.basename(path)
    return FileResponse(path, media_type="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.get("/api/logs/list")
def logs_list():
    if not os.path.exists(LOGS_DIR):
        return {"logs": []}
    files = sorted(
        [f for f in os.listdir(LOGS_DIR) if f.endswith(".csv")],
        reverse=True
    )
    return {"logs": files}


# ── Entry point ───────────────────────────────────────────────────────────────
#
# ✅ THE PRIMARY FIX FOR CONNECT/DISCONNECT LOOP:
#
#    reload=True  (original) caused uvicorn to watch ALL files in the project.
#    LogWriter.write() appends to a CSV file every ~3 seconds (once per poll).
#    Uvicorn saw the CSV change → killed the server → restarted it.
#    Browser lost connection → showed OFFLINE → reconnected → repeated forever.
#
#    reload=False  stops all of that instantly.
#
# If you need auto-reload during development of Python code, run from terminal:
#   uvicorn app:app --host 0.0.0.0 --port 8000 --reload \
#     --reload-dir . --reload-exclude "logs" --reload-exclude "data"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=API_HOST,
        port=API_PORT,
        reload=False,   # ← CRITICAL FIX: was True
    )