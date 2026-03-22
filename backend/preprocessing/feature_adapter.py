# preprocessing/feature_adapter.py
# Converts a raw feature dict → numpy array ready for model inference.
# Handles NSL-KDD (41 features), CICIDS (77 features), and DUAL mode (both).

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import joblib

from config import MODELS_NSLKDD, MODELS_CICIDS

# NSL-KDD feature order — must match the order used during training
NSL_KDD_FEATURES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

# These three NSL-KDD columns are text and need label encoding
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


# ── Small helpers ─────────────────────────────────────────────────────────────

def encode_categorical(value, encoder):
    """Encode a single categorical value. Returns 0 for unseen values."""
    if encoder is None:
        return 0
    try:
        return int(encoder.transform([str(value)])[0])
    except Exception:
        return 0


def to_float(value):
    """Safely cast any value to float. Returns 0.0 on failure."""
    try:
        return float(value)
    except Exception:
        return 0.0


# ── Single dataset adapter ────────────────────────────────────────────────────

class FeatureAdapter:
    """
    Converts a raw feature dict → (1, n_features) numpy array
    for a single dataset (nslkdd or cicids).

    Usage:
        adapter = FeatureAdapter("nslkdd")
        X = adapter.adapt({"duration": 0, "protocol_type": "tcp", ...})
    """

    def __init__(self, dataset: str):
        self.dataset = dataset.lower()
        self.encoders = None        # NSL-KDD only
        self.feature_names = None
        self._load_artifacts()

    def _load_artifacts(self):
        if self.dataset == "nslkdd":
            enc_path = os.path.join(MODELS_NSLKDD, "label_encoders.pkl")
            if os.path.exists(enc_path):
                self.encoders = joblib.load(enc_path)
            self.feature_names = NSL_KDD_FEATURES

        elif self.dataset == "cicids":
            feat_path = os.path.join(MODELS_CICIDS, "feature_names.pkl")
            if os.path.exists(feat_path):
                self.feature_names = joblib.load(feat_path)
            else:
                # Fallback before first preprocessing run
                from preprocessing.preprocess_cicids import CICIDS_FEATURES
                self.feature_names = CICIDS_FEATURES

    def adapt(self, input_dict: dict) -> np.ndarray:
        """Convert raw feature dict → (1, n_features) float32 array."""
        if self.dataset == "nslkdd":
            return self._adapt_nslkdd(input_dict)
        elif self.dataset == "cicids":
            return self._adapt_cicids(input_dict)
        else:
            raise ValueError(f"Unknown dataset '{self.dataset}'. Use 'nslkdd' or 'cicids'.")

    def _adapt_nslkdd(self, d: dict) -> np.ndarray:
        row = []
        for feat in NSL_KDD_FEATURES:
            if feat in CATEGORICAL_COLS:
                encoder = self.encoders.get(feat) if self.encoders else None
                val = encode_categorical(d.get(feat, ""), encoder)
            else:
                val = to_float(d.get(feat, 0))
            row.append(val)
        return np.array(row, dtype=np.float32).reshape(1, -1)

    def _adapt_cicids(self, d: dict) -> np.ndarray:
        if self.feature_names is None:
            raise RuntimeError("CICIDS feature names not loaded. Run preprocess_cicids.py first.")
        row = [to_float(d.get(feat, 0.0)) for feat in self.feature_names]
        return np.array(row, dtype=np.float32).reshape(1, -1)

    def get_feature_names(self):
        return self.feature_names or []


# ── Dual dataset adapter ──────────────────────────────────────────────────────

class DualFeatureAdapter:
    """
    Takes one unified input dict and produces feature arrays for BOTH datasets.

    The input dict is a superset of both feature spaces. Each adapter picks
    only the fields it needs and ignores the rest. Missing fields default to 0.

    Usage:
        adapter = DualFeatureAdapter()
        X_nslkdd, X_cicids = adapter.adapt(input_dict)
    """

    def __init__(self):
        self.nslkdd = FeatureAdapter("nslkdd")
        self.cicids  = FeatureAdapter("cicids")

    def adapt(self, input_dict: dict):
        """
        Returns (X_nslkdd, X_cicids) — two numpy arrays from one input dict.
        Each adapter silently ignores fields it doesn't recognise.
        """
        X_nslkdd = self.nslkdd.adapt(input_dict)
        X_cicids  = self.cicids.adapt(input_dict)
        return X_nslkdd, X_cicids