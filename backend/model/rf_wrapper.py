# model/rf_wrapper.py
#
# WHY THIS FILE EXISTS — pickle module-path resolution
# ─────────────────────────────────────────────────────
# When joblib/pickle serialises an object it does NOT store the object's data
# and class definition together.  It stores only:
#   1. The fully-qualified dotted path of the class  (e.g. "model.rf_wrapper.MultiClassRFWrapper")
#   2. The instance's __dict__
#
# On deserialisation pickle imports that dotted path and calls the class to
# reconstruct the object.  If the class was defined in __main__ (i.e. inside
# a script run directly), pickle records "__main__.MultiClassRFWrapper".
# When FastAPI later calls joblib.load(), the process has no __main__ that
# contains MultiClassRFWrapper, so Python raises:
#
#   AttributeError: module '__main__' has no attribute 'MultiClassRFWrapper'
#
# The fix is simple and permanent: define the class in a named module
# (this file) so pickle records "model.rf_wrapper.MultiClassRFWrapper".
# That path is importable identically in both the training script and the
# FastAPI process, so deserialisation always succeeds after a server restart.
#
# USAGE
# ─────
# Training  (train_rf.py):
#   from model.rf_wrapper import MultiClassRFWrapper
#   wrapper = MultiClassRFWrapper(rf, le)
#   joblib.dump(wrapper, "rf_model.pkl")
#
# Inference (predict.py):
#   from model.rf_wrapper import MultiClassRFWrapper   # registers the class
#   rf_model = joblib.load("rf_model.pkl")             # resolves correctly

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder


class MultiClassRFWrapper:
    """
    Wraps a multi-class RandomForestClassifier behind a binary-compatible API.

    The underlying RF predicts one of N classes (e.g. Normal / DoS / Port Scan /
    Brute Force).  The existing inference pipeline (predict.py, app.py,
    risk_score.py) was written for a binary model and expects:

        rf_model.predict(X)       →  np.ndarray of 0 (Normal) or 1 (Attack)
        rf_model.predict_proba(X) →  np.ndarray shape (n_samples, 2)
                                      col-0 = p(Normal), col-1 = p(Attack)

    This wrapper satisfies that contract exactly while the underlying RF is
    multi-class.  Additional multi-class methods are available for SHAP and
    future endpoints without touching the existing pipeline.

    Parameters
    ----------
    rf : RandomForestClassifier
        A fitted multi-class RandomForest.
    le : LabelEncoder
        The encoder used to transform attack_category → integer during training.
        Its .classes_ attribute maps integer indices back to string labels.
    normal_label : str
        The string label that represents normal/benign traffic.
        Default "Normal" matches the unified label map in both datasets.
    """

    def __init__(self, rf: RandomForestClassifier, le: LabelEncoder,
                 normal_label: str = "Normal"):
        self.rf           = rf
        self.le           = le
        self.normal_label = normal_label
        # Cache the column index of "Normal" in the probability matrix so
        # predict_proba() does not recompute list(le.classes_).index() on
        # every single inference call.
        self._normal_idx  = list(le.classes_).index(normal_label)

    # ── Binary API — backward-compatible with the existing pipeline ───────────

    def predict(self, X) -> np.ndarray:
        """
        Binary prediction: 0 = Normal, 1 = Attack.

        Internally the RF predicts the full multi-class label; we collapse
        everything that is not normal_label to 1.
        """
        encoded = self.rf.predict(X)
        labels  = self.le.inverse_transform(encoded)
        return (labels != self.normal_label).astype(int)

    def predict_proba(self, X) -> np.ndarray:
        """
        Binary probability matrix: shape (n_samples, 2).
            col-0  p(Normal)  = probability mass on the Normal class
            col-1  p(Attack)  = 1 - p(Normal)  (sum of all attack classes)

        This preserves the two-element structure that risk_score.py and
        app.py index into with [0] and [1].
        """
        proba    = self.rf.predict_proba(X)        # (n_samples, n_classes)
        p_normal = proba[:, self._normal_idx]       # scalar per sample
        p_attack = 1.0 - p_normal
        return np.column_stack([p_normal, p_attack])

    # ── Multi-class API — for SHAP / logging / future endpoints ──────────────

    def predict_multiclass(self, X) -> np.ndarray:
        """Returns full string class labels: 'Normal', 'DoS', 'Port Scan', etc."""
        encoded = self.rf.predict(X)
        return self.le.inverse_transform(encoded)

    def predict_label(self, X) -> str:
        """
        Convenience method: returns the single string class label for the
        first (and typically only) sample in X.

        Used by Predictor.predict() and DualPredictor.predict() to expose
        the multiclass RF decision as 'rf_class' in the API response, so
        app.py can derive attack_type from ML output instead of rule-based logic.

        Returns "Unknown" if inverse_transform fails for any reason.
        """
        try:
            encoded = self.rf.predict(X)
            return str(self.le.inverse_transform(encoded)[0])
        except Exception:
            return "Unknown"

    def predict_proba_multiclass(self, X) -> np.ndarray:
        """Full (n_samples, n_classes) probability matrix, one column per class."""
        return self.rf.predict_proba(X)

    # ── Properties passthrough — needed by shap.TreeExplainer ────────────────
    # shap.TreeExplainer inspects these attributes on whatever object you pass.
    # Delegating to self.rf lets callers pass the wrapper directly to SHAP
    # without unwrapping it.

    @property
    def classes_(self) -> np.ndarray:
        """String class labels in the order the RF uses internally."""
        return self.le.classes_

    @property
    def estimators_(self):
        """Individual decision trees — required by shap.TreeExplainer."""
        return self.rf.estimators_

    @property
    def n_features_in_(self) -> int:
        """Number of features the RF was trained on."""
        return self.rf.n_features_in_

    @property
    def n_classes_(self) -> int:
        """Number of classes in the multi-class RF."""
        return self.rf.n_classes_

    @property
    def feature_importances_(self) -> np.ndarray:
        """Mean impurity decrease per feature across all trees."""
        return self.rf.feature_importances_

    # ── repr — useful when debugging loaded models ────────────────────────────

    def __repr__(self) -> str:
        return (
            f"MultiClassRFWrapper("
            f"classes={list(self.le.classes_)}, "
            f"normal_label='{self.normal_label}', "
            f"n_estimators={self.rf.n_estimators})"
        )