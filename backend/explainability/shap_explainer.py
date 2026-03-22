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

        # ── Extract the 1-D SHAP value array for class 1 (attack) ────────────
        # SHAP output shape varies by version:
        #   Old: list of 2 arrays, each shape (n_samples, n_features)
        #   New: single array shape (n_samples, n_features, n_classes)
        #        OR (n_classes, n_samples, n_features)
        # We flatten everything down to a simple 1-D array of length n_features.

        if isinstance(shap_values, list):
            # Old format: [class0_array, class1_array]
            sv = np.array(shap_values[1]).flatten()
        elif isinstance(shap_values, np.ndarray):
            if shap_values.ndim == 3:
                # Shape: (n_samples, n_features, n_classes) — take class 1
                sv = shap_values[0, :, 1].flatten()
            elif shap_values.ndim == 2:
                # Shape: (n_samples, n_features)
                sv = shap_values[0].flatten()
            else:
                sv = shap_values.flatten()
        else:
            # Fallback: try to convert to array
            sv = np.array(shap_values).flatten()

        # Ensure sv has the right length
        n = len(self.feature_names)
        if len(sv) != n:
            # Last resort: just zero-pad or truncate
            sv = np.resize(sv, n)

        # Build list sorted by absolute impact, all values as plain float
        feature_impacts = [
            {"feature": name, "shap_value": float(sv[i])}
            for i, name in enumerate(self.feature_names)
        ]
        feature_impacts.sort(key=lambda x: abs(x["shap_value"]), reverse=True)

        # Base value — expected model output before seeing any features
        base = self.explainer.expected_value
        if isinstance(base, (list, np.ndarray)):
            base_value = float(np.array(base).flat[1])  # class 1
        else:
            base_value = float(base)

        return {
            "top_features": feature_impacts[:top_n],
            "base_value":   base_value,
        }