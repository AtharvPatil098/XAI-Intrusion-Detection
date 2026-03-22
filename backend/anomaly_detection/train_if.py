# anomaly_detection/train_if.py
# Trains an Isolation Forest on NORMAL (benign) traffic only.
# The model learns what "normal" looks like and flags deviations as anomalies.
# This enables zero-day / unknown attack detection.
#
# Run: python train_if.py --dataset nslkdd
#      python train_if.py --dataset cicids
#      python train_if.py --dataset all

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import argparse
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report

from config import DATA_PROCESSED, MODELS_NSLKDD, MODELS_CICIDS, IF_CONTAMINATION


# ── Shared helper ─────────────────────────────────────────────────────────────

def load_dataset(dataset: str):
    """Load processed CSV, scaler, and feature list. Returns None on any error."""
    model_dir = MODELS_NSLKDD if dataset == "nslkdd" else MODELS_CICIDS
    csv_path  = os.path.join(DATA_PROCESSED,
                             "nsl_kdd_processed.csv" if dataset == "nslkdd" else "cicids_processed.csv")

    if not os.path.exists(csv_path):
        print(f"[SKIP] {csv_path} not found. Run the matching preprocess script first.")
        return None

    feat_path   = os.path.join(model_dir, "feature_names.pkl")
    scaler_path = os.path.join(model_dir, "scaler.pkl")

    for p in [feat_path, scaler_path]:
        if not os.path.exists(p):
            print(f"[ERROR] {p} not found. Run train_rf.py first (or preprocess_cicids.py for CICIDS).")
            return None

    df           = pd.read_csv(csv_path)
    feature_cols = joblib.load(feat_path)
    scaler       = joblib.load(scaler_path)

    missing = [f for f in feature_cols if f not in df.columns]
    if missing:
        print(f"[ERROR] {len(missing)} features missing from CSV: {missing[:5]}")
        return None

    return df, feature_cols, scaler, model_dir


# ── Training ──────────────────────────────────────────────────────────────────

def train(dataset: str):
    print(f"\n=== Training Isolation Forest — {dataset.upper()} (normal traffic only) ===")

    result = load_dataset(dataset)
    if result is None:
        return

    df, feature_cols, scaler, model_dir = result

    # Train ONLY on normal/benign traffic — IF learns what "normal" looks like
    normal_df = df[df["binary_label"] == 0]
    print(f"  Normal samples: {len(normal_df):,}")

    X_normal = scaler.transform(normal_df[feature_cols].values)

    clf = IsolationForest(
        n_estimators=100,
        contamination=IF_CONTAMINATION,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_normal)

    # Evaluate on the full dataset (normal + attack)
    all_X    = scaler.transform(df[feature_cols].values)
    preds    = clf.predict(all_X)           # IF returns 1=normal, -1=anomaly
    preds_b  = (preds == -1).astype(int)    # convert to 0=normal, 1=anomaly
    true_lab = df["binary_label"].values
    print(classification_report(true_lab, preds_b, target_names=["Normal", "Anomaly"]))

    joblib.dump(clf, os.path.join(model_dir, "if_model.pkl"))
    print(f"Saved → {model_dir}/if_model.pkl")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=["nslkdd", "cicids", "all"], default="all")
    args = parser.parse_args()

    datasets = ["nslkdd", "cicids"] if args.dataset == "all" else [args.dataset]
    for ds in datasets:
        train(ds)