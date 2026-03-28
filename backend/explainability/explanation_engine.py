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