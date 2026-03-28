# preprocessing/preprocess_cicids.py
# Combines all 8 CICIDS-2017 CSVs into one clean processed dataset.
# Produces TWO output files:
#
#   cicids_clean.csv     ← real data only, no SMOTE  → used by Isolation Forest
#   cicids_processed.csv ← SMOTE-balanced            → used by Random Forest
#
# Place all 8 CSVs in: backend/data/raw/CICIDS/
# Run: python preprocess_cicids.py

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import glob
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib

from config import (DATA_RAW_CICIDS, DATA_PROCESSED,
                    CICIDS_DROP_COLS, CICIDS_LABEL_COL, MODELS_CICIDS)

# ── Output file paths ─────────────────────────────────────────────────────────
# cicids_processed.csv  — SMOTE-balanced, used by RF training
# cicids_clean.csv      — real data only (no SMOTE), used by IF training
OUT_RF_FILE = os.path.join(DATA_PROCESSED, "cicids_processed.csv")
OUT_IF_FILE = os.path.join(DATA_PROCESSED, "cicids_clean.csv")

# ── All 77 CICIDS-2017 feature names ─────────────────────────────────────────
CICIDS_FEATURES = [
    "Destination Port", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]  # 77 features

# ── Unified multi-class label map ─────────────────────────────────────────────
# Final classes: Normal | DoS | Port Scan | Brute Force
# Rows with labels NOT in this map are DROPPED (infiltration, bot, etc.).
LABEL_MAP = {
    # Normal
    "benign":                          "Normal",

    # DoS
    "dos hulk":                        "DoS",
    "dos goldeneye":                   "DoS",
    "dos slowloris":                   "DoS",
    "dos slowhttptest":                "DoS",
    "heartbleed":                      "DoS",
    "ddos":                            "DoS",

    # Port Scan
    "portscan":                        "Port Scan",

    # Brute Force
    "ftp-patator":                     "Brute Force",
    "ssh-patator":                     "Brute Force",

    # Web attacks → Brute Force (closest semantic match in shared schema)
    "web attack \x96 brute force":     "Brute Force",
    "web attack \x96 xss":             "Brute Force",
    "web attack \x96 sql injection":   "Brute Force",
    "web attack \u2013 brute force":   "Brute Force",
    "web attack \u2013 xss":           "Brute Force",
    "web attack \u2013 sql injection": "Brute Force",
    "web attack brute force":          "Brute Force",
    "web attack xss":                  "Brute Force",
    "web attack sql injection":        "Brute Force",
}

FINAL_CLASSES = {"Normal", "DoS", "Port Scan", "Brute Force"}

# Columns with values that must never be negative (CICFlowMeter artefact)
NON_NEGATIVE_KEYWORDS = [
    "Length", "Bytes", "Packets", "Size", "Count",
    "Rate", "Duration", "Bulk", "Segment", "bytes", "packets", "pkt",
]

# ── Normal-class cap for SMOTE path only ──────────────────────────────────────
# CICIDS has ~2.3 M Normal rows. Capping before SMOTE keeps RAM and runtime
# manageable. Attack classes are NEVER capped — we want all real attack data.
# This cap is applied ONLY to the RF (SMOTE) path, NOT to the clean IF path,
# so the IF evaluates against the full real Normal population.
# Set to None to disable (requires ~16 GB RAM).
NORMAL_CAP_FOR_RF = 200_000


# ── Step functions ────────────────────────────────────────────────────────────

def load_raw_files():
    """Find all CSVs in the CICIDS folder, load and combine them."""
    csv_files = sorted(glob.glob(os.path.join(DATA_RAW_CICIDS, "*.csv")))
    if not csv_files:
        print(f"[CICIDS] No CSV files found in {DATA_RAW_CICIDS}")
        print("[CICIDS] Download from: https://www.unb.ca/cic/datasets/ids-2017.html")
        return None

    print(f"[CICIDS] Found {len(csv_files)} CSV files:")
    frames = []
    for path in csv_files:
        print(f"  Loading {os.path.basename(path)} ...", end=" ", flush=True)
        try:
            df = pd.read_csv(path, low_memory=False)
            df.columns = df.columns.str.strip()
            print(f"{len(df):,} rows")
            frames.append(df)
        except Exception as e:
            print(f"SKIP — {e}")

    if not frames:
        return None

    combined = pd.concat(frames, ignore_index=True)
    print(f"[CICIDS] Combined: {len(combined):,} rows × {len(combined.columns)} cols")
    return combined


def drop_metadata(df):
    """Remove metadata columns that are not network features."""
    to_drop = [c for c in CICIDS_DROP_COLS if c in df.columns]
    df.drop(columns=to_drop, inplace=True)
    return df


def find_label_column(df):
    """Locate the Label column regardless of spacing or casing."""
    for candidate in ["Label", "label", " Label", "LABEL"]:
        if candidate in df.columns:
            return candidate
    return next((c for c in df.columns if c.strip().lower() == "label"), None)


def build_multiclass_labels(df):
    """
    Map raw CICIDS labels → unified multi-class labels using LABEL_MAP.
    Drops rows whose labels are not in LABEL_MAP.
    Adds attack_category and binary_label.

    NOTE: label_encoded is NOT added here — it is added separately for the
    clean path and the SMOTE path so each encoder fits its own data.
    """
    label_col = find_label_column(df)
    if label_col is None:
        raise ValueError(f"Cannot find Label column. Columns: {list(df.columns)}")

    df.rename(columns={label_col: "Label"}, inplace=True)
    print("[CICIDS] Raw label value counts (top 20):")
    print(df["Label"].value_counts().head(20).to_string())

    normalised            = df["Label"].astype(str).str.strip().str.lower()
    df["attack_category"] = normalised.map(LABEL_MAP)

    before = len(df)
    df     = df[df["attack_category"].isin(FINAL_CLASSES)].copy()
    if len(df) < before:
        print(f"[CICIDS] Dropped {before - len(df):,} rows with unmapped labels "
              "(infiltration, bot, etc.)")

    # binary_label: 0=Normal, 1=Attack — existing predict.py / app.py unchanged
    df["binary_label"] = (df["attack_category"] != "Normal").astype(int)

    df.drop(columns=["Label"], inplace=True)
    return df


def select_features(df):
    """Keep only the 77 known CICIDS features + label columns."""
    if "Fwd Header Length.1" in df.columns:
        df.drop(columns=["Fwd Header Length.1"], inplace=True)
        print("[CICIDS] Dropped duplicate 'Fwd Header Length.1'")

    available = [f for f in CICIDS_FEATURES if f in df.columns]
    missing   = [f for f in CICIDS_FEATURES if f not in df.columns]
    if missing:
        print(f"[CICIDS] {len(missing)} features missing from CSVs: {missing}")
    print(f"[CICIDS] Using {len(available)}/77 features")

    label_cols = ["binary_label", "attack_category"]
    return df[available + label_cols].copy(), available


def clean(df, feature_cols):
    """Replace inf, drop NaN rows, clip illegal negatives."""
    n_inf = np.isinf(df[feature_cols].values).sum()
    if n_inf:
        print(f"[CICIDS] Replacing {n_inf:,} inf values with NaN")
        df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)

    before = len(df)
    df.dropna(subset=feature_cols, inplace=True)
    print(f"[CICIDS] Dropped {before - len(df):,} NaN rows → {len(df):,} remain")

    for col in feature_cols:
        if any(kw in col for kw in NON_NEGATIVE_KEYWORDS):
            n_neg = (df[col] < 0).sum()
            if n_neg:
                df[col] = df[col].clip(lower=0)

    return df


def fit_and_save_scaler(df, feature_cols):
    """
    Fit StandardScaler on REAL Normal rows ONLY and save it.
    Called once on clean (pre-SMOTE) data so neither synthetic Normal samples
    nor the SMOTE normal-cap affect the scaler statistics.
    The same scaler is shared by both RF and IF — they operate in the same
    feature space and must use identical scaling.
    """
    normal_X = df.loc[df["binary_label"] == 0, feature_cols].values
    scaler   = StandardScaler()
    scaler.fit(normal_X)
    joblib.dump(scaler, os.path.join(MODELS_CICIDS, "scaler.pkl"))
    print(f"[CICIDS] Scaler fitted on {len(normal_X):,} real Normal samples (pre-SMOTE/pre-cap)")
    return scaler


def add_label_encoded(df, save_encoder=True):
    """
    Fit a LabelEncoder on df["attack_category"] and add label_encoded column.
    save_encoder=True  → saves to label_encoder.pkl (used for the final/balanced file)
    save_encoder=False → encoder is local only (used for clean file and SMOTE internals)
    """
    le = LabelEncoder()
    df = df.copy()
    df["label_encoded"] = le.fit_transform(df["attack_category"])
    if save_encoder:
        joblib.dump(le, os.path.join(MODELS_CICIDS, "label_encoder.pkl"))
        print(f"[CICIDS] Label encoder saved. Classes: {list(le.classes_)}")
    return df


# ── IF path — save clean (pre-SMOTE) file ────────────────────────────────────

def save_clean(df, feature_cols):
    """
    Save the real-data-only CSV for Isolation Forest training.
    This is a snapshot taken AFTER cleaning but BEFORE the Normal cap
    and BEFORE SMOTE, so it contains the full real distribution of all classes.
    label_encoded is added with a local encoder (not saved — IF doesn't need it,
    but train_if.py checks for the column's presence is optional; we include it
    for consistency with the processed file schema).
    """
    df_clean = add_label_encoded(df, save_encoder=False)
    df_clean.to_csv(OUT_IF_FILE, index=False)
    print(f"\n[CICIDS] Clean (IF) dataset saved → {OUT_IF_FILE}")
    print(f"[CICIDS] Clean shape  : {df_clean.shape}")
    print(f"[CICIDS] Clean label distribution:")
    print(df_clean["attack_category"].value_counts().to_string())
    print(f"[CICIDS] Clean binary: Normal={int((df_clean['binary_label']==0).sum()):,}  "
          f"Attack={int((df_clean['binary_label']==1).sum()):,}")


# ── RF path — Normal cap + SMOTE + save balanced file ────────────────────────

def cap_normal_class(df):
    """
    Randomly subsample the Normal class to NORMAL_CAP_FOR_RF rows.
    Attack classes are NEVER touched — we keep all real attack samples.
    Applied only in the RF (SMOTE) pipeline path, never in the clean/IF path.
    """
    if NORMAL_CAP_FOR_RF is None:
        return df

    normal_mask    = df["attack_category"] == "Normal"
    normal_df      = df[normal_mask]
    attack_df      = df[~normal_mask]

    if len(normal_df) <= NORMAL_CAP_FOR_RF:
        return df  # already small enough

    normal_sampled = normal_df.sample(n=NORMAL_CAP_FOR_RF, random_state=42)
    df_capped      = pd.concat([normal_sampled, attack_df], ignore_index=True)

    print(f"[CICIDS] Normal class capped for RF path: "
          f"{len(normal_df):,} → {NORMAL_CAP_FOR_RF:,} rows "
          f"(attack rows unchanged: {len(attack_df):,})")
    return df_capped


def balance_with_smote(df, feature_cols):
    """
    Balance the four classes using SMOTE for the RF training dataset.

    Strategy: upsample every class that falls below the MEDIAN class size
    up to that median. Classes already at or above the median are untouched.

    Rules respected:
    - SMOTE operates on numeric feature columns only.
    - attack_category strings are reconstructed from y after resampling.
    - binary_label is reconstructed from attack_category after resampling.
    - label_encoded is NOT present yet — added after this step.
    - The scaler has already been fitted on real Normal data before this call.
    """
    try:
        from imblearn.over_sampling import SMOTE
    except ImportError:
        print("[CICIDS] WARNING: imbalanced-learn not installed.")
        print("         Run: pip install imbalanced-learn")
        print("         Skipping SMOTE — RF dataset will remain imbalanced.")
        return df

    # Temporary integer encoding for SMOTE (needs numeric y)
    le_temp = LabelEncoder()
    y       = le_temp.fit_transform(df["attack_category"])
    X       = df[feature_cols].values

    unique, counts = np.unique(y, return_counts=True)

    print("\n[CICIDS] RF dataset class distribution BEFORE SMOTE:")
    for u, c in zip(unique, counts):
        print(f"  {le_temp.classes_[u]:15s}: {c:>8,}")

    # Target = median class size; upsample minorities, leave majorities alone
    target_n = int(np.median(counts))
    print(f"[CICIDS] SMOTE target per class: {target_n:,} (median of class sizes)")

    sampling_strategy = {
        int(cls_idx): max(int(cnt), target_n)
        for cls_idx, cnt in zip(unique, counts)
    }

    # k_neighbors must be < smallest minority class count
    min_count   = int(counts.min())
    k_neighbors = min(5, min_count - 1)

    if k_neighbors < 1:
        print(f"[CICIDS] WARNING: smallest class has only {min_count} sample(s). "
              "SMOTE requires ≥2 neighbors. Skipping balancing.")
        return df

    smote = SMOTE(
        sampling_strategy=sampling_strategy,
        k_neighbors=k_neighbors,
        random_state=42,
    )

    X_res, y_res = smote.fit_resample(X, y)

    # Reconstruct DataFrame
    df_res = pd.DataFrame(X_res, columns=feature_cols)
    df_res["attack_category"] = le_temp.inverse_transform(y_res)
    df_res["binary_label"]    = (df_res["attack_category"] != "Normal").astype(int)

    print("[CICIDS] RF dataset class distribution AFTER SMOTE:")
    for cls_name in sorted(df_res["attack_category"].unique()):
        n = int((df_res["attack_category"] == cls_name).sum())
        print(f"  {cls_name:15s}: {n:>8,}")

    return df_res


def save_balanced(df, feature_cols):
    """
    Save the SMOTE-balanced CSV for Random Forest training.
    Also persists the label encoder (fitted on the balanced dataset)
    and the feature names.
    """
    # label_encoded fitted on balanced data and encoder saved here
    df = add_label_encoded(df, save_encoder=True)

    joblib.dump(feature_cols, os.path.join(MODELS_CICIDS, "feature_names.pkl"))
    df.to_csv(OUT_RF_FILE, index=False)

    print(f"\n[CICIDS] Balanced (RF) dataset saved → {OUT_RF_FILE}")
    print(f"[CICIDS] Balanced shape  : {df.shape}")
    print(f"[CICIDS] Balanced label distribution:")
    print(df["attack_category"].value_counts().to_string())
    print(f"[CICIDS] Balanced binary: Normal={int((df['binary_label']==0).sum()):,}  "
          f"Attack={int((df['binary_label']==1).sum()):,}")


# ── Main ──────────────────────────────────────────────────────────────────────

def preprocess_cicids():
    os.makedirs(DATA_PROCESSED, exist_ok=True)
    os.makedirs(MODELS_CICIDS,  exist_ok=True)

    # ── Phase 1: load and shared cleaning ─────────────────────────────────
    df = load_raw_files()
    if df is None:
        return None

    # 1. Remove metadata columns (IPs, ports, timestamps)
    df = drop_metadata(df)

    # 2. Map labels → unified classes; drop unmapped rows
    df = build_multiclass_labels(df)

    # 3. Keep only the 77 CICIDS features + label columns
    df, feature_cols = select_features(df)

    # 4. Clean inf/NaN and clip illegal negatives
    df = clean(df, feature_cols)

    # 5. Fit and save scaler on ALL real Normal rows BEFORE any cap or SMOTE.
    #    This gives the scaler the most representative Normal distribution.
    #    Shared by both RF and IF — they operate in the same feature space.
    fit_and_save_scaler(df, feature_cols)

    # 6. Save feature names — fixed at this point, same for RF and IF
    joblib.dump(feature_cols, os.path.join(MODELS_CICIDS, "feature_names.pkl"))

    # ── Phase 2: save clean file for Isolation Forest ─────────────────────
    # Snapshot taken HERE — after cleaning, before any cap or SMOTE.
    # IF must train and evaluate on real data distributions only.
    print("\n── Saving clean dataset for Isolation Forest ──")
    save_clean(df, feature_cols)

    # ── Phase 3: SMOTE-balanced file for Random Forest ────────────────────
    print("\n── Preparing SMOTE-balanced dataset for Random Forest ──")

    # 7. Cap Normal class to keep SMOTE tractable (attack classes untouched)
    df_rf = cap_normal_class(df)

    # 8. Balance with SMOTE
    df_rf = balance_with_smote(df_rf, feature_cols)

    # 9. Save balanced file (also saves label encoder fitted on balanced data)
    save_balanced(df_rf, feature_cols)

    return df_rf


if __name__ == "__main__":
    preprocess_cicids()