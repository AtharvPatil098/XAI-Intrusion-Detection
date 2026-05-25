# model/train_rf.py
# Trains a multi-class Random Forest classifier for NSL-KDD and/or CICIDS.
#
# Classes: Normal | DoS | Port Scan | Brute Force
#
# COMPATIBILITY: The saved rf_model.pkl wraps multi-class prediction in a shim
# so existing predict.py code — which calls rf_model.predict() and expects
# 0 or 1 — continues to work without modification.
#
# Run: python train_rf.py --dataset nslkdd
#      python train_rf.py --dataset cicids
#      python train_rf.py --dataset all

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import argparse
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder, StandardScaler

from config import DATA_PROCESSED, MODELS_NSLKDD, MODELS_CICIDS

# ── Import wrapper from its permanent module location ─────────────────────────
# MultiClassRFWrapper MUST be imported from model.rf_wrapper — NOT defined
# here.  When joblib serialises the wrapper object, pickle records the class
# path as "model.rf_wrapper.MultiClassRFWrapper".  That same dotted path is
# importable in FastAPI's process, so joblib.load() in predict.py always
# resolves correctly regardless of how many times the server is restarted.
#
# If the class were defined here (inside __main__), pickle would record
# "__main__.MultiClassRFWrapper" — a path that only exists while this script
# is running, causing AttributeError on every subsequent load.
from model.rf_wrapper import MultiClassRFWrapper


# ── Shared helpers ────────────────────────────────────────────────────────────

def load_dataset(dataset: str):
    """
    Load processed CSV and return (X, y_encoded, y_binary, feature_cols, le, model_dir).
    For CICIDS, also loads the pre-fitted scaler from preprocessing.
    """
    if dataset == "nslkdd":
        path      = os.path.join(DATA_PROCESSED, "nsl_kdd_processed.csv")
        model_dir = MODELS_NSLKDD
    else:
        path      = os.path.join(DATA_PROCESSED, "cicids_processed.csv")
        model_dir = MODELS_CICIDS

    if not os.path.exists(path):
        print(f"[SKIP] {path} not found. Run the matching preprocess script first.")
        return None

    df = pd.read_csv(path)

    # Validate required label columns
    for col in ["attack_category", "label_encoded", "binary_label"]:
        if col not in df.columns:
            print(f"[ERROR] '{col}' column missing. Re-run the preprocess script.")
            return None

    # Determine feature columns
    label_cols   = ["binary_label", "attack_category", "label_encoded"]
    feature_cols = [c for c in df.columns if c not in label_cols]

    if dataset == "cicids":
        feat_path = os.path.join(model_dir, "feature_names.pkl")
        if not os.path.exists(feat_path):
            print(f"[ERROR] feature_names.pkl missing in {model_dir}. "
                  "Run preprocess_cicids.py first.")
            return None
        feature_cols = joblib.load(feat_path)

    missing = [f for f in feature_cols if f not in df.columns]
    if missing:
        print(f"[ERROR] {len(missing)} expected features missing: {missing[:5]}")
        return None

    # Load or rebuild label encoder
    le_path = os.path.join(model_dir, "label_encoder.pkl")
    if os.path.exists(le_path):
        le = joblib.load(le_path)
    else:
        # Fallback: fit from data (should not normally happen)
        le = LabelEncoder()
        le.fit(df["attack_category"])
        joblib.dump(le, le_path)

    X         = df[feature_cols].values
    y_encoded = df["label_encoded"].values
    y_binary  = df["binary_label"].values

    return X, y_encoded, y_binary, feature_cols, le, model_dir


def get_scaler(dataset: str, model_dir: str, X_train: np.ndarray):
    """
    NSL-KDD: fit a new StandardScaler on training data.
    CICIDS:  load the scaler already fitted on Normal-only data by preprocessing.
    """
    if dataset == "nslkdd":
        scaler = StandardScaler()
        scaler.fit(X_train)
        joblib.dump(scaler, os.path.join(model_dir, "scaler.pkl"))
        return scaler
    else:
        scaler_path = os.path.join(model_dir, "scaler.pkl")
        if not os.path.exists(scaler_path):
            print("[ERROR] scaler.pkl missing. Run preprocess_cicids.py first.")
            return None
        return joblib.load(scaler_path)


# ── Training ──────────────────────────────────────────────────────────────────

def train(dataset: str):
    print(f"\n=== Training Multi-Class Random Forest — {dataset.upper()} ===")

    result = load_dataset(dataset)
    if result is None:
        return

    X, y_encoded, y_binary, feature_cols, le, model_dir = result

    print(f"  Dataset size : {len(X):,} samples")
    print(f"  Features     : {len(feature_cols)}")
    print(f"  Classes      : {list(le.classes_)}")

    # Print per-class counts for diagnostics
    unique, counts = np.unique(y_encoded, return_counts=True)
    for u, c in zip(unique, counts):
        print(f"    {le.classes_[u]:15s}: {c:>8,}")

    X_train, X_test, y_train, y_test, yb_train, yb_test = train_test_split(
        X, y_encoded, y_binary,
        test_size=0.2, random_state=42, stratify=y_encoded
    )

    scaler = get_scaler(dataset, model_dir, X_train)
    if scaler is None:
        return

    X_train = scaler.transform(X_train)
    X_test  = scaler.transform(X_test)

    # Multi-class RF with class_weight="balanced" to handle imbalance
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=None,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_train, y_train)

    # ── Evaluate multi-class performance ──────────────────────────────────
    y_pred_encoded = rf.predict(X_test)
    y_pred_labels  = le.inverse_transform(y_pred_encoded)
    y_true_labels  = le.inverse_transform(y_test)

    print(f"\nMulti-class accuracy: {accuracy_score(y_test, y_pred_encoded):.4f}")
    print(classification_report(y_true_labels, y_pred_labels))

    # ── Evaluate binary compatibility (what predict.py / app.py will see) ─
    wrapper    = MultiClassRFWrapper(rf, le)
    y_pred_bin = wrapper.predict(X_test)
    print("Binary (backward-compat) classification report:")
    print(classification_report(yb_test, y_pred_bin, target_names=["Normal", "Attack"]))

    # ── Save wrapped model and feature list ───────────────────────────────
    # joblib serialises wrapper as "model.rf_wrapper.MultiClassRFWrapper"
    # — a stable, importable path that works in any process.
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(wrapper,      os.path.join(model_dir, "rf_model.pkl"))
    joblib.dump(feature_cols, os.path.join(model_dir, "feature_names.pkl"))
    print(f"Saved → {model_dir}/rf_model.pkl  ({wrapper!r})")
    print(f"Saved → {model_dir}/feature_names.pkl")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=["nslkdd", "cicids", "all"], default="all")
    args = parser.parse_args()

    datasets = ["nslkdd", "cicids"] if args.dataset == "all" else [args.dataset]
    for ds in datasets:
        train(ds)