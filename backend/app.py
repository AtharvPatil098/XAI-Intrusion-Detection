# app.py
# FastAPI backend for the XAI Intrusion Detection System.
#
# Run: python app.py
#  OR: uvicorn app:app --host 0.0.0.0 --port 8000 --reload

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
from config import DATA_PROCESSED, MODELS_NSLKDD, MODELS_CICIDS, API_HOST, API_PORT

app = FastAPI(
    title="XAI Intrusion Detection System",
    description="Explainable AI intrusion detection using NSL-KDD and CICIDS datasets.",
    version="1.0.0",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
SOC_DIR      = os.path.join(FRONTEND_DIR, "soc")

# /soc must be mounted BEFORE /dashboard (more specific path first)
if os.path.exists(SOC_DIR):
    app.mount("/soc",       StaticFiles(directory=SOC_DIR,      html=True), name="soc")
if os.path.exists(FRONTEND_DIR):
    app.mount("/dashboard", StaticFiles(directory=FRONTEND_DIR, html=True), name="dashboard")


# ── Model registry ────────────────────────────────────────────────────────────

class ModelRegistry:
    """Lazy-loads and caches all predictors and explainers."""

    def __init__(self):
        self._predictors:    Dict[str, Predictor]         = {}
        self._explainers:    Dict[str, ExplanationEngine] = {}
        self._dual_predictor: Optional[DualPredictor]     = None

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

_log_buffer: deque = deque(maxlen=100)   # keeps the last 100 log lines

def _write_log(status: str, risk: str, confidence: float, dataset: str = "dual"):
    """Append one formatted line to the log buffer after every prediction."""
    ts   = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] [{status}] risk={risk} conf={confidence:.2f} src={dataset}"
    _log_buffer.appendleft(line)


# ── Request / response models ─────────────────────────────────────────────────

class PredictRequest(BaseModel):
    dataset:  str            = "nslkdd"
    features: Dict[str, Any]

class DualPredictRequest(BaseModel):
    features: Dict[str, Any]    # unified dict — both adapters pick what they need

class ExplainRequest(BaseModel):
    dataset:  str            = "nslkdd"
    features: Dict[str, Any]
    top_n:    int            = 10


# ── Helpers ───────────────────────────────────────────────────────────────────

def validate_dataset(dataset: str):
    if dataset.lower() not in ["nslkdd", "cicids"]:
        raise HTTPException(400, "dataset must be 'nslkdd' or 'cicids'")


def run_prediction(dataset: str, features: dict) -> dict:
    """Run RF + IF for a single dataset and attach risk score."""
    pred           = registry.predictor(dataset).predict(features)
    rf_prob_attack = pred["rf_probability"][1] if pred["rf_probability"] else 0.5
    anomaly_score  = pred["anomaly_score"]     if pred["anomaly_score"] is not None else -0.3
    risk           = compute_risk_score(rf_prob_attack, anomaly_score)
    return numpy_to_python({**pred, **risk})


def run_dual_prediction(features: dict) -> dict:
    """Run all 4 models simultaneously and attach combined risk score."""
    pred = registry.dual_predictor().predict(features)

    # Extract signals — fall back to neutral values if a model isn't loaded
    nslkdd_rf_prob   = pred["nslkdd_rf_probability"][1] if pred["nslkdd_rf_probability"] else 0.5
    nslkdd_anom      = pred["nslkdd_anomaly_score"]     if pred["nslkdd_anomaly_score"] is not None else -0.3
    cicids_rf_prob   = pred["cicids_rf_probability"][1]  if pred["cicids_rf_probability"]  else 0.5
    cicids_anom      = pred["cicids_anomaly_score"]      if pred["cicids_anomaly_score"]  is not None else -0.3

    risk = compute_dual_risk_score(nslkdd_rf_prob, nslkdd_anom, cicids_rf_prob, cicids_anom)
    return numpy_to_python({**pred, **risk})


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    """Redirect to the full XAI dashboard."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/dashboard")


@app.get("/api/health")
def health():
    """Returns which models and processed datasets are available."""
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
    """Single-dataset prediction (RF + IF + risk score)."""
    validate_dataset(req.dataset)
    return run_prediction(req.dataset.lower(), req.features)


@app.post("/api/predict/dual")
def predict_dual(req: DualPredictRequest):
    """
    Dual-mode prediction — runs all 4 models simultaneously.
    Input: unified feature dict (superset of NSL-KDD + CICIDS fields).
    Output: all 4 model signals + one combined risk score.
    This is the main endpoint used by the dashboard and flow_extractor.
    """
    return run_dual_prediction(req.features)


@app.post("/api/predict/csv")
async def predict_csv(file: UploadFile = File(...)):
    """
    Upload a CSV and run dual-mode prediction on every row (max 500).
    CSV should contain a superset of NSL-KDD and/or CICIDS feature columns.
    Missing columns default to 0 automatically.
    """
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
    """SHAP explanation for a single dataset's RF model."""
    validate_dataset(req.dataset)
    dataset     = req.dataset.lower()
    prediction  = run_prediction(dataset, req.features)
    explanation = registry.explainer(dataset).explain(req.features, top_n=req.top_n)
    return numpy_to_python({"prediction": prediction, "explanation": explanation})


@app.post("/api/explain/dual")
def explain_dual(req: DualPredictRequest):
    """
    Runs SHAP on BOTH RF models simultaneously.
    Returns dual prediction + NSL-KDD and CICIDS feature importances
    in one response — one click, full picture.
    """
    prediction   = run_dual_prediction(req.features)
    nslkdd_exp   = registry.explainer("nslkdd").explain(req.features, top_n=12)
    cicids_exp   = registry.explainer("cicids").explain(req.features,  top_n=12)
    return numpy_to_python({
        "prediction":         prediction,
        "nslkdd_explanation": nslkdd_exp,
        "cicids_explanation":  cicids_exp,
    })


@app.get("/api/sample/{dataset}")
def get_sample(dataset: str):
    """Return a random sample record from a processed dataset."""
    validate_dataset(dataset)
    try:
        return numpy_to_python({"dataset": dataset,
                                "features": sample_random_record(dataset)})
    except Exception as e:
        raise HTTPException(404, f"Could not load sample: {e}")


# Cache stats results — reading 2.8M row CSVs on every request is slow
_stats_cache: dict = {}

@app.get("/api/stats/{dataset}")
def dataset_stats(dataset: str):
    """Basic statistics about a processed dataset. Result is cached after first load."""
    validate_dataset(dataset)

    # Return cached result if available
    if dataset in _stats_cache:
        return _stats_cache[dataset]

    filename = "nsl_kdd_processed.csv" if dataset == "nslkdd" else "cicids_processed.csv"
    path     = os.path.join(DATA_PROCESSED, filename)

    if not os.path.exists(path):
        raise HTTPException(404, f"No processed data for '{dataset}'. Run preprocess script first.")

    # Read only the columns we need — much faster than loading all 77 features
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

    _stats_cache[dataset] = result   # cache so future calls are instant
    return result


# ── Simple GET endpoints — used by the SOC dashboard (dashboard.js) ──────────
# These wrap the dual-prediction logic into GET requests so the simple
# dashboard can poll them without sending a JSON body.
# Each call picks a random NSL-KDD sample and runs all 4 models on it.

@app.get("/realtime")
def realtime():
    """Current system status — NORMAL or ATTACK, risk level, alert count."""
    features  = sample_random_record("nslkdd")
    result    = run_dual_prediction(features)
    is_attack = (result["nslkdd_rf_prediction"] == 1 or
                 result["cicids_rf_prediction"]  == 1)
    status    = "ATTACK" if is_attack else "NORMAL"
    risk      = result["risk_level"]
    conf      = result["nslkdd_rf_probability"][1] if result["nslkdd_rf_probability"] else 0.5

    _write_log(status, risk, conf)
    return {
        "status": status,
        "alerts": 1 if is_attack else 0,
        "risk":   risk,
    }


@app.get("/predict")
def predict_get():
    """Latest prediction with confidence score and model name."""
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
    """Top SHAP feature importances from the NSL-KDD RF model."""
    features    = sample_random_record("nslkdd")
    explanation = registry.explainer("nslkdd").explain(features, top_n=8)
    top_features = explanation.get("top_features", [])
    return {
        "features": [
            {"name": f["feature"], "value": round(abs(f["shap_value"]), 4)}
            for f in top_features
        ]
    }


@app.get("/logs")
def logs_get():
    """Last 20 prediction log lines."""
    return {"logs": list(_log_buffer)[:20]}


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=API_HOST, port=API_PORT, reload=True)