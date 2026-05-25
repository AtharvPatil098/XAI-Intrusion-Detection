<<<<<<< HEAD
import shap

# ==============================
# 🔹 CREATE EXPLAINER
# ==============================

def create_explainer(model, background_data):
    """
    Create SHAP explainer using model.predict_proba
    Compatible with XGBoost >= 3.x
    """
    return shap.Explainer(model.predict_proba, background_data)


# ==============================
# 🔹 GET SHAP VALUES
# ==============================

def get_shap_values(explainer, df):
    """
    Generate SHAP values for given input
    """
    return explainer(df)


# ==============================
# 🔹 EXTRACT TOP FEATURES
# ==============================

def get_top_features(shap_values, feature_names, top_n=5):
    """
    Extract top contributing features
    """

    # ==============================
    # 🔹 HANDLE SHAPE SAFELY
    # ==============================
    try:
        # Multi-class / classification
        values = shap_values.values[0][:, 1]   # attack class
    except:
        # Binary fallback
        values = shap_values.values[0]

    # ==============================
    # 🔹 FEATURE IMPORTANCE
    # ==============================
    feature_importance = list(zip(feature_names, values))
    feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)

    top_features = feature_importance[:top_n]

    results = []

    for feature, value in top_features:

        impact = (
            "increases attack probability"
            if value > 0
            else "supports normal behavior"
        )

        results.append({
            "feature": feature,
            "impact": impact,
            "shap_value": float(value)
        })

    return results


# ==============================
# 🔹 OPTIONAL: HUMAN MAPPING
# ==============================

def convert_to_human_readable(shap_output):
    """
    Convert technical features to human explanations
    """

    explanations = []

    for item in shap_output:
        feature = item["feature"]
        impact = item["impact"]

        f = feature.lower()

        # -----------------------------
        # 🔥 HUMAN MAPPING
        # -----------------------------

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
            reason = "Suspicious network behavior pattern"

        explanations.append({
            "feature": feature,
            "reason": reason,
            "effect": impact
        })

    return explanations
=======
# explainability/shap_explainer.py
# SHAP TreeExplainer wrapper for the Random Forest model.

import numpy as np
import shap


class SHAPExplainer:
    """
    Computes SHAP values for a fitted RandomForest model.

    Usage:
        explainer = SHAPExplainer(rf_model, feature_names, normal_idx)
        result    = explainer.explain(X_scaled, top_n=10)

    rf_model   : raw sklearn RandomForestClassifier (NOT MultiClassRFWrapper)
    normal_idx : index of the "Normal" class in rf_model.classes_
                 Used to pick the right SHAP slice for multi-class models.
    """

    def __init__(self, rf_model, feature_names: list, normal_idx: int = 0):
        self.explainer     = shap.TreeExplainer(rf_model)
        self.feature_names = feature_names
        self.normal_idx    = normal_idx
        self.n_classes     = getattr(rf_model, "n_classes_", 2)

    def explain(self, X_scaled: np.ndarray, top_n: int = 10) -> dict:
        """
        Returns the top_n features with the largest impact on the prediction.

        X_scaled : (1, n_features) scaled numpy array
        Returns  : {"top_features": [...], "base_value": float}
        """
        shap_values = self.explainer.shap_values(X_scaled)

        # ── Normalise shap_values to a list of per-class 1-D arrays ──────────
        # SHAP output shape varies by version and model type:
        #   A) list of K arrays, each (n_samples, n_features)   — old SHAP
        #   B) ndarray (n_samples, n_features, n_classes)        — new SHAP
        #   C) ndarray (n_classes, n_samples, n_features)        — rare variant
        #   D) ndarray (n_samples, n_features)                   — binary

        n_feat = len(self.feature_names)

        if isinstance(shap_values, list):
            # Format A
            sv_list = [np.array(sv).reshape(-1, n_feat)[0] for sv in shap_values]
        elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
            if shap_values.shape[0] == 1:
                # Format B: (1, n_features, n_classes)
                sv_list = [shap_values[0, :, k] for k in range(shap_values.shape[2])]
            else:
                # Format C: (n_classes, n_samples, n_features)
                sv_list = [shap_values[k, 0, :] for k in range(shap_values.shape[0])]
        elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 2:
            # Format D: binary (n_samples, n_features) — wrap as two-class list
            sv_list = [shap_values[0], shap_values[0]]
        else:
            sv = np.array(shap_values).flatten()
            sv_list = [sv, sv]

        # ── Pick the SHAP values to display ───────────────────────────────────
        # Binary (2 classes): use class-1 (attack) values — original behaviour.
        # Multi-class (>2):   aggregate all non-Normal classes.
        #   importance = sum of |shap| across attack classes  (for ranking)
        #   sign       = from the attack class with highest mean |shap|  (for direction)

        if len(sv_list) == 2:
            sv = sv_list[1][:n_feat]

        elif len(sv_list) > 2:
            attack_idxs = [i for i in range(len(sv_list)) if i != self.normal_idx]

            importance = np.zeros(n_feat)
            for i in attack_idxs:
                importance += np.abs(sv_list[i][:n_feat])

            # Direction from the dominant attack class
            dominant = max(attack_idxs,
                           key=lambda i: float(np.abs(sv_list[i][:n_feat]).mean()))
            sign = np.sign(sv_list[dominant][:n_feat])
            sv = sign * importance

        else:
            sv = sv_list[0][:n_feat]

        # Safety: pad/truncate to exactly n_features
        if len(sv) != n_feat:
            sv = np.resize(sv, n_feat)

        # ── Build sorted feature impact list ──────────────────────────────────
        feature_impacts = [
            {"feature": name, "shap_value": float(sv[i])}
            for i, name in enumerate(self.feature_names)
        ]
        feature_impacts.sort(key=lambda x: abs(x["shap_value"]), reverse=True)

        # ── Base value ────────────────────────────────────────────────────────
        base = self.explainer.expected_value
        if isinstance(base, (list, np.ndarray)):
            base_arr    = np.array(base).flatten()
            if len(base_arr) > 2:
                attack_idxs = [i for i in range(len(base_arr)) if i != self.normal_idx]
                base_value  = float(sum(base_arr[i] for i in attack_idxs))
            else:
                base_value = float(base_arr[min(1, len(base_arr) - 1)])
        else:
            base_value = float(base)

        return {
            "top_features": feature_impacts[:top_n],
            "base_value":   base_value,
        }
>>>>>>> b74af1039ca230811c9075534ea29f37bdc263f8
