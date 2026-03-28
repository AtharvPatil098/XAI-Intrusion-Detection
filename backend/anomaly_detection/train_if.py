# anomaly_detection/train_if.py
# Trains an Isolation Forest using semi-supervised mixed training.
#
# Training strategy:
#   ALL Normal samples  +  a small fraction (ATTACK_FRAC) of real attack samples
#
# Why mixed training improves subtle-attack detection:
#   Pure Normal-only training draws the anomaly boundary tightly around the
#   Normal manifold but has no information about where attacks actually sit in
#   feature space.  Brute Force and Port Scan have feature distributions that
#   partially overlap with Normal (slow, low-volume, plausible-looking flows),
#   so the Normal-only boundary does not push far enough into attack territory.
#
#   Adding a small fraction of real attack samples forces the isolation trees
#   to build shorter paths for those attack points — they become "easier to
#   isolate" — which shifts the anomaly score threshold so that the full
#   attack population (not just the 5% seen in training) scores as anomalous.
#   This is still unsupervised: labels are NEVER passed to IsolationForest.fit().
#   The attack fraction acts purely as a geometric hint about where non-normal
#   data lives, not as a supervised signal.
#
# Dataset routing:
#   NSL-KDD : nsl_kdd_processed.csv  (real data, unchanged)
#   CICIDS   : cicids_clean.csv       (real data, no SMOTE — same as before)
#
# Run: python train_if.py --dataset nslkdd
#      python train_if.py --dataset cicids
#      python train_if.py --dataset all

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import argparse
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report

from config import DATA_PROCESSED, MODELS_NSLKDD, MODELS_CICIDS

# ── Hyper-parameters ──────────────────────────────────────────────────────────

# Fraction of the ATTACK pool to include in the IF training set.
# 0.05 = 5 % of all attack rows.  Small enough to keep the model
# unsupervised in character; large enough to shift the boundary.
ATTACK_FRAC = 0.05

# contamination: expected fraction of outliers in the data the model
# will score at inference time.  0.10 = "we expect ~10 % of live traffic
# to be anomalous."  Not the same as ATTACK_FRAC (training-data fraction).
IF_CONTAMINATION = 0.10


# ── Dataset routing ───────────────────────────────────────────────────────────

DATASET_CONFIG = {
    "nslkdd": {
        "csv":       "nsl_kdd_processed.csv",
        "model_dir": MODELS_NSLKDD,
        "tag":       "NSL-KDD",
    },
    "cicids": {
        "csv":       "cicids_clean.csv",   # real data only — no SMOTE contamination
        "model_dir": MODELS_CICIDS,
        "tag":       "CICIDS",
    },
}


# ── Loader ────────────────────────────────────────────────────────────────────

def load_dataset(dataset: str):
    """
    Load the correct CSV, scaler, and feature list for IF training.
    Returns (df, feature_cols, scaler, model_dir) or None on any error.
    """
    cfg       = DATASET_CONFIG[dataset]
    model_dir = cfg["model_dir"]
    csv_path  = os.path.join(DATA_PROCESSED, cfg["csv"])
    tag       = cfg["tag"]

    if not os.path.exists(csv_path):
        print(f"[{tag}] CSV not found: {csv_path}")
        hint = ("Run preprocess_cicids.py — produces both cicids_clean.csv "
                "and cicids_processed.csv." if dataset == "cicids"
                else "Run preprocess_nslkdd.py first.")
        print(f"[{tag}] {hint}")
        return None

    for label, path in [("scaler.pkl",        os.path.join(model_dir, "scaler.pkl")),
                        ("feature_names.pkl",  os.path.join(model_dir, "feature_names.pkl"))]:
        if not os.path.exists(path):
            print(f"[{tag}] {label} not found at {path}. "
                  "Run the matching preprocess script first.")
            return None

    df           = pd.read_csv(csv_path)
    feature_cols = joblib.load(os.path.join(model_dir, "feature_names.pkl"))
    scaler       = joblib.load(os.path.join(model_dir, "scaler.pkl"))

    if "binary_label" not in df.columns:
        print(f"[{tag}] 'binary_label' column missing in {csv_path}. "
              "Re-run the preprocess script.")
        return None

    missing = [f for f in feature_cols if f not in df.columns]
    if missing:
        print(f"[{tag}] {len(missing)} feature columns missing: {missing[:5]}")
        return None

    return df, feature_cols, scaler, model_dir


# ── Training set construction ─────────────────────────────────────────────────

def build_train_set(df: pd.DataFrame, feature_cols: list,
                    scaler, tag: str):
    """
    Build and scale the mixed training matrix:
        ALL Normal rows  +  ATTACK_FRAC of all Attack rows (random sample)

    Labels are NOT passed to IsolationForest — the attack rows are used
    purely as geometric information about where non-normal data lives.

    Returns
    -------
    X_train   : np.ndarray, shape (n_train, n_features), scaled
    normal_df : pd.DataFrame — Normal rows used
    attack_sample : pd.DataFrame — Attack rows sampled in
    """
    normal_df = df[df["binary_label"] == 0].copy()
    attack_df = df[df["binary_label"] == 1].copy()

    if len(attack_df) == 0:
        # No attack rows available — fall back to Normal-only training
        print(f"[{tag}] WARNING: No attack rows found. "
              "Falling back to Normal-only training.")
        attack_sample = attack_df  # empty DataFrame, same columns
    else:
        # Sample a fixed fraction of the full attack pool.
        # min(1.0, ATTACK_FRAC) guards against edge cases.
        attack_sample = attack_df.sample(
            frac=min(1.0, ATTACK_FRAC),
            random_state=42,
        )

    # ── Debug logging — training distribution ─────────────────────────────
    n_normal  = len(normal_df)
    n_attack  = len(attack_sample)
    n_total   = n_normal + n_attack
    pct_n     = 100.0 * n_normal  / n_total if n_total > 0 else 0.0
    pct_a     = 100.0 * n_attack  / n_total if n_total > 0 else 0.0

    print(f"\n[{tag}] ── Training set composition ──────────────────────")
    print(f"  Normal  samples : {n_normal:>8,}  ({pct_n:5.1f}% of training set)")
    print(f"  Attack  samples : {n_attack:>8,}  ({pct_a:5.1f}% of training set)"
          f"  [frac={ATTACK_FRAC:.0%} of {len(attack_df):,} total attack rows]")
    print(f"  Total   samples : {n_total:>8,}")

    # Per-class breakdown of the attack fraction
    if "attack_category" in attack_sample.columns and n_attack > 0:
        print(f"  Attack breakdown in training sample:")
        for cls, grp in attack_sample.groupby("attack_category"):
            pool_cls = (attack_df["attack_category"] == cls).sum()
            print(f"    {cls:15s}: {len(grp):>6,}  "
                  f"(from pool of {pool_cls:,})")

    print(f"[{tag}] ───────────────────────────────────────────────────")

    # ── Assemble and scale ────────────────────────────────────────────────
    train_df = pd.concat([normal_df, attack_sample], ignore_index=True)
    X_train  = scaler.transform(train_df[feature_cols].values)

    return X_train, normal_df, attack_sample


# ── Training ──────────────────────────────────────────────────────────────────

def train(dataset: str):
    tag      = DATASET_CONFIG[dataset]["tag"]
    csv_name = DATASET_CONFIG[dataset]["csv"]

    print(f"\n=== Training Isolation Forest — {tag} ===")
    print(f"    Data source  : {csv_name}")
    print(f"    Train mode   : Normal (100%) + Attack ({ATTACK_FRAC:.0%} sample) — semi-supervised")
    print(f"    Eval set     : Full dataset (Normal + all attack classes)")
    print(f"    Contamination: {IF_CONTAMINATION}")

    result = load_dataset(dataset)
    if result is None:
        return

    df, feature_cols, scaler, model_dir = result

    # ── Full dataset summary ──────────────────────────────────────────────
    n_normal_total = int((df["binary_label"] == 0).sum())
    n_attack_total = int((df["binary_label"] == 1).sum())
    print(f"\n[{tag}] Full dataset: {len(df):,} rows total")
    print(f"  Normal  : {n_normal_total:>8,}")
    print(f"  Attack  : {n_attack_total:>8,}")

    if n_normal_total == 0:
        print(f"[{tag}] ERROR: No Normal samples found. "
              "Check preprocessing labels.")
        return

    if "attack_category" in df.columns:
        print(f"\n[{tag}] Attack class pool (full clean dataset):")
        for cls, cnt in df[df["binary_label"] == 1]["attack_category"].value_counts().items():
            print(f"  {cls:15s}: {cnt:>8,}")

    # ── Build mixed training set ──────────────────────────────────────────
    # Labels are NEVER passed to IsolationForest — purely geometric hint.
    X_train, normal_df, attack_sample = build_train_set(
        df, feature_cols, scaler, tag
    )

    # ── Fit Isolation Forest ──────────────────────────────────────────────
    clf = IsolationForest(
        n_estimators=100,
        contamination=IF_CONTAMINATION,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train)   # ← X_train only; no y passed — model stays unsupervised

    # ── Evaluate on the FULL dataset ──────────────────────────────────────
    all_X   = scaler.transform(df[feature_cols].values)
    preds   = clf.predict(all_X)          # IF: 1=normal, -1=anomaly
    preds_b = (preds == -1).astype(int)   # convert → 0=normal, 1=anomaly
    true_b  = df["binary_label"].values

    print(f"\n[{tag}] Full-dataset evaluation (binary: Normal vs Anomaly):")
    print(classification_report(
        true_b, preds_b,
        target_names=["Normal", "Anomaly"],
        digits=3,
    ))

    # Per-class detection rate — primary diagnostic for attack class coverage
    if "attack_category" in df.columns:
        df_eval            = df.copy()
        df_eval["if_flag"] = preds_b

        print(f"[{tag}] Per-class anomaly detection rate:")
        for cls, grp in df_eval.groupby("attack_category"):
            n_flagged = int(grp["if_flag"].sum())
            n_cls     = len(grp)
            rate      = n_flagged / n_cls if n_cls > 0 else 0.0
            # ✓ = ≥50 % detected, △ = 20–49 %, ✗ = <20 %
            symbol    = "✓" if rate >= 0.50 else ("△" if rate >= 0.20 else "✗")
            print(f"  {symbol} {cls:15s}: {rate:6.1%} flagged  "
                  f"({n_flagged:,}/{n_cls:,})")

    # ── Save ──────────────────────────────────────────────────────────────
    # Path unchanged — predict.py and app.py expect this exact location.
    out_path = os.path.join(model_dir, "if_model.pkl")
    joblib.dump(clf, out_path)
    print(f"\n[{tag}] Saved → {out_path}")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train Isolation Forest for NSL-KDD and/or CICIDS."
    )
    parser.add_argument(
        "--dataset",
        choices=["nslkdd", "cicids", "all"],
        default="all",
        help="Which dataset to train on (default: all)",
    )
    parser.add_argument(
        "--attack-frac",
        type=float,
        default=ATTACK_FRAC,
        dest="attack_frac",
        help=f"Fraction of attack pool to include in training (default: {ATTACK_FRAC}). "
             "Range 0.0–1.0. Lower = more unsupervised; higher = stronger boundary hint.",
    )
    args = parser.parse_args()

    # Allow runtime override without editing the file
    if args.attack_frac != ATTACK_FRAC:
        ATTACK_FRAC = args.attack_frac
        print(f"[config] ATTACK_FRAC overridden to {ATTACK_FRAC:.2%}")

    datasets = ["nslkdd", "cicids"] if args.dataset == "all" else [args.dataset]
    for ds in datasets:
        train(ds)