# explainability/shap_explainer.py
# SHAP TreeExplainer wrapper for the Random Forest model.

import numpy as np
import shap


class SHAPExplainer:
    """
    Computes SHAP values for a fitted RandomForest model.

    Usage:
        explainer = SHAPExplainer(rf_model, feature_names)
        result    = explainer.explain(X_scaled, top_n=10)
    """

    def __init__(self, rf_model, feature_names: list):
        self.explainer     = shap.TreeExplainer(rf_model)
        self.feature_names = feature_names

    def explain(self, X_scaled: np.ndarray, top_n: int = 10) -> dict:
        """
        Returns the top_n features with the largest impact on the prediction.

        X_scaled : (1, n_features) scaled numpy array
        Returns  : {"top_features": [...], "base_value": float}
        """
        shap_values = self.explainer.shap_values(X_scaled)

        # For binary classification shap_values is [class0_vals, class1_vals]
        # We want class 1 (attack) SHAP values
        sv = shap_values[1][0] if isinstance(shap_values, list) else shap_values[0]

        # Build list sorted by absolute impact
        feature_impacts = [
            {"feature": name, "shap_value": float(sv[i])}
            for i, name in enumerate(self.feature_names)
        ]
        feature_impacts.sort(key=lambda x: abs(x["shap_value"]), reverse=True)

        # Base value = expected model output before seeing any features
        base = self.explainer.expected_value
        base_value = float(base[1] if isinstance(base, (list, np.ndarray)) else base)

        return {
            "top_features": feature_impacts[:top_n],
            "base_value":   base_value,
        }