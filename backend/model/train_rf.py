# model/train_rf.py
# Trains a Random Forest classifier for NSL-KDD and/or CICIDS.
#
# Run: python train_rf.py --dataset nslkdd
#      python train_rf.py --dataset cicids
#      python train_rf.py --dataset all

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import argparse
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler

from config import DATA_PROCESSED, MODELS_NSLKDD, MODELS_CICIDS


# ── Shared helpers ────────────────────────────────────────────────────────────

def load_dataset(dataset: str):
    """Load processed CSV and return (X, y, feature_cols, model_dir).
    For CICIDS, also loads the pre-fitted scaler from preprocessing.
    """
    if dataset == "nslkdd":
        path = os.path.join(DATA_PROCESSED, "nsl_kdd_processed.csv")
        model_dir = MODELS_NSLKDD
    else:
        path = os.path.join(DATA_PROCESSED, "cicids_processed.csv")
        model_dir = MODELS_CICIDS

    if not os.path.exists(path):
        print(f"[SKIP] {path} not found. Run the matching preprocess script first.")
        return None

    df = pd.read_csv(path)
    label_cols = ["binary_label", "attack_category", "label_encoded"]
    feature_cols = [c for c in df.columns if c not in label_cols]

    # For CICIDS, validate features against the saved list from preprocessing
    if dataset == "cicids":
        feat_path = os.path.join(model_dir, "feature_names.pkl")
        if not os.path.exists(feat_path):
            print(f"[ERROR] feature_names.pkl missing in {model_dir}. Run preprocess_cicids.py first.")
            return None
        feature_cols = joblib.load(feat_path)

    missing = [f for f in feature_cols if f not in df.columns]
    if missing:
        print(f"[ERROR] {len(missing)} expected features missing from CSV: {missing[:5]}")
        return None

    X = df[feature_cols].values
    y = df["binary_label"].values
    return X, y, feature_cols, model_dir


def get_scaler(dataset: str, model_dir: str, X_train):
    """Return a fitted scaler.
    NSL-KDD: fit a new scaler on training data.
    CICIDS: load the scaler already fitted on benign-only data by preprocessing.
    """
    if dataset == "nslkdd":
        scaler = StandardScaler()
        scaler.fit(X_train)
        joblib.dump(scaler, os.path.join(model_dir, "scaler.pkl"))
        return scaler
    else:
        scaler_path = os.path.join(model_dir, "scaler.pkl")
        if not os.path.exists(scaler_path):
            print(f"[ERROR] scaler.pkl missing. Run preprocess_cicids.py first.")
            return None
        return joblib.load(scaler_path)


# ── Training ──────────────────────────────────────────────────────────────────

def train(dataset: str):
    print(f"\n=== Training Random Forest — {dataset.upper()} ===")

    result = load_dataset(dataset)
    if result is None:
        return

    X, y, feature_cols, model_dir = result
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = get_scaler(dataset, model_dir, X_train)
    if scaler is None:
        return

    X_train = scaler.transform(X_train)
    X_test  = scaler.transform(X_test)

    clf = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

    # Save model and feature list
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(clf, os.path.join(model_dir, "rf_model.pkl"))
    joblib.dump(feature_cols, os.path.join(model_dir, "feature_names.pkl"))
    print(f"Saved → {model_dir}/rf_model.pkl")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=["nslkdd", "cicids", "all"], default="all")
    args = parser.parse_args()

    datasets = ["nslkdd", "cicids"] if args.dataset == "all" else [args.dataset]
    for ds in datasets:
        train(ds)