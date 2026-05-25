<<<<<<< HEAD
import pandas as pd
import joblib
import json
import numpy as np

print("🔥 XAI-IDS Predict System Starting...")

from config import (
    XGB_MODEL_PATH,
    IF_MODEL_PATH,
    FEATURE_COLUMNS_PATH,
    CICIDS_DATA,
    MULTI_CLASS_MODEL_PATH,
    LABEL_ENCODER_PATH,
    SCALER_PATH,
    calculate_risk_score,
    ATTACK_THRESHOLD,
    ANOMALY_LABEL
)

from explainability.shap_explainer import create_explainer
from explainability.explanation_engine import ExplanationEngine


# ==============================
# 🔹 LOAD FILES
# ==============================
def load_files():

    model = joblib.load(XGB_MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    if_model = joblib.load(IF_MODEL_PATH)

    with open(FEATURE_COLUMNS_PATH, "r") as f:
        feature_cols = json.load(f)

    multi_model = joblib.load(MULTI_CLASS_MODEL_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)

    # 🔥 SHAP background
    try:
        background = pd.read_csv(CICIDS_DATA)
        background.columns = background.columns.str.strip()
        background = background[feature_cols]
        background = background.sample(min(100, len(background)), random_state=42)
    except:
        background = pd.DataFrame(
            np.zeros((100, len(feature_cols))),
            columns=feature_cols
        )

    explainer = create_explainer(model, background)
    engine = ExplanationEngine(explainer, feature_cols)

    return model, if_model, feature_cols, engine, multi_model, label_encoder, scaler


# ==============================
# 🔹 PREDICT FUNCTION
# ==============================
def predict(
    sample_dict,
    model,
    if_model,
    feature_cols,
    engine,
    multi_model,
    label_encoder,
    scaler,
    is_raw_input=False
):

    # --------------------------
    # INPUT
    # --------------------------
    if is_raw_input:
        from preprocessing.feature_adapter import adapt_raw_input
        df = adapt_raw_input(sample_dict)
    else:
        df = pd.DataFrame([sample_dict])

        for col in feature_cols:
            if col not in df.columns:
                df[col] = 0

        df = df[feature_cols]

    # --------------------------
    # SCALE
    # --------------------------
    df_scaled = scaler.transform(df)

    # --------------------------
    # 🔹 BINARY MODEL
    # --------------------------
    probs = model.predict_proba(df_scaled)[0]
    attack_prob = float(probs[1])
    normal_prob = float(probs[0])

    label = "Attack" if attack_prob > ATTACK_THRESHOLD else "Normal"

    # --------------------------
    # 🔹 ANOMALY (USE SCALED ❗)
    # --------------------------
    anomaly_pred = int(if_model.predict(df_scaled)[0])
    anomaly_score = float(if_model.decision_function(df_scaled)[0])

    is_anomaly = anomaly_pred == ANOMALY_LABEL

    # --------------------------
    # 🔥 FINAL LABEL FIX
    # --------------------------
    if label == "Normal" and is_anomaly:
        final_label = "Unknown Attack"
    else:
        final_label = label

    # --------------------------
    # 🔥 MULTI-CLASS FIX
    # --------------------------
    if final_label == "Attack":

        attack_class = multi_model.predict(df_scaled)[0]
        attack_type = label_encoder.inverse_transform([attack_class])[0]

        # ❌ CRITICAL FIX: NEVER allow BENIGN here
        if attack_type == "BENIGN":
            attack_type = "Unknown Attack"

    else:
        attack_type = "Normal"

    # --------------------------
    # 🔹 RISK
    # --------------------------
    risk_score = calculate_risk_score(
        attack_prob,
        anomaly_score,
        is_anomaly
    )

    # --------------------------
    # 🔥 SHAP FIX (USE SAME INPUT AS MODEL)
    # --------------------------
    explanation = engine.generate(pd.DataFrame(df_scaled, columns=feature_cols))

    print(f"🚨 {final_label} | Type: {attack_type} | Risk: {risk_score}")

    return {
        "prediction": final_label,
        "attack_type": attack_type,
        "confidence": float(attack_prob if label == "Attack" else normal_prob),
        "attack_probability": attack_prob,
        "risk_score": risk_score,
        "is_anomaly": bool(is_anomaly),
        "anomaly_score": anomaly_score,
        "explanation": explanation
    }
=======
# model/predict.py
# Single-dataset Predictor and DualPredictor (runs all 4 models simultaneously).

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import joblib

from config import MODELS_NSLKDD, MODELS_CICIDS
from preprocessing.feature_adapter import FeatureAdapter, DualFeatureAdapter

# ── Register the wrapper class before any joblib.load() call ─────────────────
# This import is what makes joblib.load("rf_model.pkl") work correctly.
#
# When pickle deserialises rf_model.pkl it looks up the string
# "model.rf_wrapper.MultiClassRFWrapper" in sys.modules.  If the module has
# never been imported in this process, Python cannot find the class and raises:
#
#   AttributeError: module '__main__' has no attribute 'MultiClassRFWrapper'
#
# Importing here — before _load_models() is ever called — guarantees that
# model.rf_wrapper is in sys.modules and the class is resolvable, regardless
# of whether this process is a training script, FastAPI worker, or test runner.
#
# The name MultiClassRFWrapper is not used explicitly anywhere below; the
# import's side-effect (registering the module) is all that is needed.
from model.rf_wrapper import MultiClassRFWrapper  # noqa: F401


# ── Single dataset predictor ──────────────────────────────────────────────────

class Predictor:
    """
    Runs RF + IF for a single dataset (nslkdd or cicids).

    Usage:
        predictor = Predictor("nslkdd")
        result = predictor.predict({"duration": 0, "protocol_type": "tcp", ...})
    """

    def __init__(self, dataset: str):
        self.dataset  = dataset.lower()
        self.adapter  = FeatureAdapter(dataset)
        self.rf_model = None
        self.if_model = None
        self.scaler   = None
        self._load_models()

    def _load_models(self):
        model_dir = MODELS_NSLKDD if self.dataset == "nslkdd" else MODELS_CICIDS
        for attr, filename in [("rf_model", "rf_model.pkl"),
                                ("if_model", "if_model.pkl"),
                                ("scaler",   "scaler.pkl")]:
            path = os.path.join(model_dir, filename)
            if os.path.exists(path):
                setattr(self, attr, joblib.load(path))

    def predict(self, input_dict: dict) -> dict:
        # ── Step 1: convert raw input → scaled numpy array ────────────────
        X = self.adapter.adapt(input_dict)
        X_scaled = self.scaler.transform(X) if self.scaler else X

        result = {
            "dataset":        self.dataset,
            "rf_prediction":  None,     # 0 = normal,  1 = attack
            "rf_class":       None,     # multiclass label e.g. "DoS", "Port Scan"
            "rf_probability": None,     # [p_normal, p_attack]
            "if_prediction":  None,     # 0 = normal,  1 = anomaly
            "anomaly_score":  None,     # more negative = more anomalous
        }

        # ── Step 2: Random Forest — known attack classification ───────────
        if self.rf_model:
            result["rf_prediction"]  = int(self.rf_model.predict(X_scaled)[0])
            result["rf_probability"] = self.rf_model.predict_proba(X_scaled)[0].tolist()
            # Multiclass label — used by app.py to derive attack_type via ML
            if hasattr(self.rf_model, "predict_label"):
                result["rf_class"] = self.rf_model.predict_label(X_scaled)

        # ── Step 3: Isolation Forest — secondary anomaly signal ───────────
        if self.if_model:
            if_raw = int(self.if_model.predict(X_scaled)[0])   # IF: 1=normal, -1=anomaly
            result["if_prediction"] = 0 if if_raw == 1 else 1
            result["anomaly_score"] = float(self.if_model.score_samples(X_scaled)[0])

        return result

    def models_loaded(self) -> bool:
        return self.rf_model is not None and self.if_model is not None


# ── Dual predictor — runs all 4 models simultaneously ────────────────────────

class DualPredictor:
    """
    Runs all 4 models (NSL-KDD RF, NSL-KDD IF, CICIDS RF, CICIDS IF)
    on a single unified input dict.

    The input dict is a superset of both feature spaces. Each model only
    reads the features it was trained on — extra fields are ignored.

    Usage:
        predictor = DualPredictor()
        result = predictor.predict({"duration": 0, "Destination Port": 80, ...})
    """

    def __init__(self):
        self.adapter  = DualFeatureAdapter()
        self.nslkdd   = Predictor("nslkdd")
        self.cicids   = Predictor("cicids")

    def predict(self, input_dict: dict) -> dict:
        # ── Step 1: adapt input to both feature spaces ────────────────────
        X_nslkdd, X_cicids = self.adapter.adapt(input_dict)

        # ── Step 2: scale each array with its own scaler ─────────────────
        X_nslkdd_scaled = self.nslkdd.scaler.transform(X_nslkdd) if self.nslkdd.scaler else X_nslkdd
        X_cicids_scaled = self.cicids.scaler.transform(X_cicids)  if self.cicids.scaler else X_cicids

        # ── Step 3: run all 4 models ──────────────────────────────────────
        result = {
            # NSL-KDD signals
            "nslkdd_rf_prediction":  None,
            "nslkdd_rf_class":       None,   # multiclass label e.g. "DoS", "Port Scan"
            "nslkdd_rf_probability": None,
            "nslkdd_if_prediction":  None,
            "nslkdd_anomaly_score":  None,
            # CICIDS signals
            "cicids_rf_prediction":  None,
            "cicids_rf_class":       None,   # multiclass label e.g. "Brute Force"
            "cicids_rf_probability": None,
            "cicids_if_prediction":  None,
            "cicids_anomaly_score":  None,
        }

        if self.nslkdd.rf_model:
            result["nslkdd_rf_prediction"]  = int(self.nslkdd.rf_model.predict(X_nslkdd_scaled)[0])
            result["nslkdd_rf_probability"] = self.nslkdd.rf_model.predict_proba(X_nslkdd_scaled)[0].tolist()
            if hasattr(self.nslkdd.rf_model, "predict_label"):
                result["nslkdd_rf_class"] = self.nslkdd.rf_model.predict_label(X_nslkdd_scaled)

        if self.nslkdd.if_model:
            if_raw = int(self.nslkdd.if_model.predict(X_nslkdd_scaled)[0])
            result["nslkdd_if_prediction"] = 0 if if_raw == 1 else 1
            result["nslkdd_anomaly_score"] = float(self.nslkdd.if_model.score_samples(X_nslkdd_scaled)[0])

        if self.cicids.rf_model:
            result["cicids_rf_prediction"]  = int(self.cicids.rf_model.predict(X_cicids_scaled)[0])
            result["cicids_rf_probability"] = self.cicids.rf_model.predict_proba(X_cicids_scaled)[0].tolist()
            if hasattr(self.cicids.rf_model, "predict_label"):
                result["cicids_rf_class"] = self.cicids.rf_model.predict_label(X_cicids_scaled)

        if self.cicids.if_model:
            if_raw = int(self.cicids.if_model.predict(X_cicids_scaled)[0])
            result["cicids_if_prediction"] = 0 if if_raw == 1 else 1
            result["cicids_anomaly_score"] = float(self.cicids.if_model.score_samples(X_cicids_scaled)[0])

        return result

    def models_loaded(self) -> dict:
        """Returns which models are ready."""
        return {
            "nslkdd_rf": self.nslkdd.rf_model is not None,
            "nslkdd_if": self.nslkdd.if_model is not None,
            "cicids_rf":  self.cicids.rf_model  is not None,
            "cicids_if":  self.cicids.if_model  is not None,
        }
>>>>>>> b74af1039ca230811c9075534ea29f37bdc263f8
