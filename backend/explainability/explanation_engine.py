<<<<<<< HEAD
class ExplanationEngine:

    def __init__(self, explainer, feature_cols):
        self.explainer = explainer
        self.feature_cols = feature_cols

    def generate(self, df):

        # ==============================
        # 🔹 GET SHAP VALUES (SAFE)
        # ==============================
        shap_values = self.explainer(df)

        try:
            values = shap_values.values[0][:, 1]   # attack class
        except:
            values = shap_values.values[0]         # fallback

        # ==============================
        # 🔹 FEATURE IMPORTANCE
        # ==============================
        feature_importance = list(zip(self.feature_cols, values))
        feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)

        # ==============================
        # 🔹 REMOVE DUPLICATE MEANINGS
        # ==============================
        seen_meanings = set()
        top_features = []

        for feature, value in feature_importance:

            f = feature.lower()

            # 🔥 Map feature → meaning category
            if "flow packets/s" in f:
                meaning = "packet_rate"
            elif "flow bytes/s" in f:
                meaning = "data_rate"
            elif "flow duration" in f:
                meaning = "duration"
            elif "destination port" in f:
                meaning = "port"
            elif "total fwd packets" in f:
                meaning = "fwd_packets"
            elif "total backward packets" in f:
                meaning = "bwd_packets"
            elif "init_win_bytes" in f:
                meaning = "tcp_window"
            elif "packet length" in f:
                meaning = "packet_size"
            elif "header length" in f:
                meaning = "header"
            elif "idle" in f:
                meaning = "idle"
            elif "psh flag" in f:
                meaning = "psh_flag"
            else:
                meaning = "generic"

            # ✅ Remove duplicate meanings
            if meaning not in seen_meanings:
                seen_meanings.add(meaning)
                top_features.append((feature, value))

            if len(top_features) == 5:
                break

        # ==============================
        # 🔹 HUMAN READABLE EXPLANATION
        # ==============================
        explanation = []

        for feature, impact in top_features:

            f = feature.lower()

            if "flow packets/s" in f:
                reason = "High packet rate detected (possible flooding attack)"

            elif "flow bytes/s" in f:
                reason = "High data transfer rate detected"

            elif "flow duration" in f:
                reason = "Abnormal or very short connection duration"

            elif "destination port" in f:
                reason = "Traffic targeting specific or sensitive service port"

            elif "total fwd packets" in f:
                reason = "Large number of forward packets detected"

            elif "total backward packets" in f:
                reason = "High response traffic observed"

            elif "init_win_bytes" in f:
                reason = "Abnormal TCP window size detected"

            elif "packet length" in f:
                reason = "Unusual packet size behavior detected"

            elif "header length" in f:
                reason = "Abnormal packet structure detected"

            elif "idle" in f:
                reason = "Irregular idle time between packets"

            elif "psh flag" in f:
                reason = "Suspicious push flag activity detected"

            else:
                reason = "Unusual network activity deviating from normal patterns"

            explanation.append({
                "feature": feature,
                "reason": reason,
                "effect": "increases attack probability" if impact > 0 else "supports normal behavior"
            })

        return explanation
=======
# explainability/explanation_engine.py
# High-level wrapper: loads RF model and runs SHAP explanations.

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import joblib

from config import MODELS_NSLKDD, MODELS_CICIDS
from explainability.shap_explainer import SHAPExplainer
from preprocessing.feature_adapter import FeatureAdapter


class ExplanationEngine:
    """
    Generates SHAP feature explanations for a single prediction.

    Usage:
        engine = ExplanationEngine("nslkdd")
        result = engine.explain({"duration": 0, "protocol_type": "tcp", ...})
    """

    def __init__(self, dataset: str):
        self.dataset   = dataset.lower()
        self.adapter   = FeatureAdapter(dataset)
        self.explainer = None
        self.scaler    = None
        self._load()

    def _load(self):
        model_dir = MODELS_NSLKDD if self.dataset == "nslkdd" else MODELS_CICIDS
        rf_path   = os.path.join(model_dir, "rf_model.pkl")
        feat_path = os.path.join(model_dir, "feature_names.pkl")
        sc_path   = os.path.join(model_dir, "scaler.pkl")

        if not os.path.exists(rf_path):
            print(f"[ExplanationEngine] RF model not found for '{self.dataset}'. Train first.")
            return

        rf_loaded     = joblib.load(rf_path)
        feature_names = (joblib.load(feat_path) if os.path.exists(feat_path)
                         else self.adapter.get_feature_names())

        # shap.TreeExplainer only accepts a raw sklearn RandomForestClassifier.
        # rf_model.pkl contains a MultiClassRFWrapper — unwrap it so SHAP
        # receives the underlying .rf estimator directly.
        from model.rf_wrapper import MultiClassRFWrapper
        if isinstance(rf_loaded, MultiClassRFWrapper):
            raw_rf     = rf_loaded.rf           # raw sklearn RandomForestClassifier
            normal_idx = rf_loaded._normal_idx  # cached index of "Normal" class
        else:
            raw_rf     = rf_loaded
            normal_idx = 0

        self.explainer = SHAPExplainer(raw_rf, feature_names, normal_idx)
        self.scaler    = joblib.load(sc_path) if os.path.exists(sc_path) else None

    def explain(self, input_dict: dict, top_n: int = 10) -> dict:
        """Return SHAP explanation for the given feature dict."""
        if self.explainer is None:
            return {"error": "Model not trained yet. Run train_rf.py first."}

        X = self.adapter.adapt(input_dict)
        if self.scaler:
            X = self.scaler.transform(X)

        return self.explainer.explain(X, top_n=top_n)
>>>>>>> b74af1039ca230811c9075534ea29f37bdc263f8
