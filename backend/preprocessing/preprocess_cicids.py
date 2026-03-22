# preprocessing/preprocess_cicids.py
# Combines all 8 CICIDS-2017 CSVs into one clean processed dataset.
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

from config import DATA_RAW_CICIDS, DATA_PROCESSED, CICIDS_DROP_COLS, CICIDS_LABEL_COL, MODELS_CICIDS

OUT_FILE = os.path.join(DATA_PROCESSED, "cicids_processed.csv")

# ── All 77 CICIDS-2017 feature names ─────────────────────────────────────────
# 78 raw features minus 1 duplicate "Fwd Header Length" = 77 usable features.
# Source: CICFlowMeter output as published with CICIDS-2017.
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
    "Fwd Header Length",    # keep only the first occurrence (duplicate dropped below)
    "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    # "Fwd Header Length.1" intentionally excluded (duplicate)
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]  # 77 features

# ── Attack label → category mapping ──────────────────────────────────────────
ATTACK_CATEGORIES = {
    "benign": "benign",
    # DoS
    "dos hulk": "dos", "dos goldeneye": "dos",
    "dos slowloris": "dos", "dos slowhttptest": "dos", "heartbleed": "dos",
    # DDoS
    "ddos": "ddos",
    # Probe
    "portscan": "probe",
    # Brute force
    "ftp-patator": "brute_force", "ssh-patator": "brute_force",
    # Web attacks (two encoding variants of the dash character)
    "web attack \x96 brute force": "web_attack",
    "web attack \x96 xss": "web_attack",
    "web attack \x96 sql injection": "web_attack",
    "web attack – brute force": "web_attack",
    "web attack – xss": "web_attack",
    "web attack – sql injection": "web_attack",
    "web attack brute force": "web_attack",
    "web attack xss": "web_attack",
    "web attack sql injection": "web_attack",
    # Other
    "infiltration": "infiltration",
    "bot": "botnet",
}

# Columns with values that must never be negative (CICFlowMeter artefact)
NON_NEGATIVE_KEYWORDS = [
    "Length", "Bytes", "Packets", "Size", "Count",
    "Rate", "Duration", "Bulk", "Segment", "bytes", "packets", "pkt",
]


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
            df.columns = df.columns.str.strip()     # strip spaces from column names
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


def build_labels(df):
    """Add attack_category, binary_label, label_encoded. Drop raw Label."""
    label_col = find_label_column(df)
    if label_col is None:
        raise ValueError(f"Cannot find Label column. Columns: {list(df.columns)}")

    df.rename(columns={label_col: "Label"}, inplace=True)
    print(f"[CICIDS] Raw label counts:\n{df['Label'].value_counts().to_string()}")

    normalised = df["Label"].astype(str).str.strip().str.lower()
    df["attack_category"] = normalised.map(lambda x: ATTACK_CATEGORIES.get(x, "other"))

    unmapped = df.loc[df["attack_category"] == "other", "Label"].unique()
    if len(unmapped):
        print(f"[CICIDS] Unmapped labels → 'other': {unmapped[:5]}")

    df["binary_label"] = (df["attack_category"] != "benign").astype(int)

    le = LabelEncoder()
    df["label_encoded"] = le.fit_transform(df["attack_category"])
    joblib.dump(le, os.path.join(MODELS_CICIDS, "label_encoder.pkl"))

    df.drop(columns=["Label"], inplace=True)
    return df


def select_features(df):
    """Keep only the 77 known CICIDS features + label columns."""
    # Drop the duplicate Fwd Header Length column if present
    if "Fwd Header Length.1" in df.columns:
        df.drop(columns=["Fwd Header Length.1"], inplace=True)
        print("[CICIDS] Dropped duplicate 'Fwd Header Length.1'")

    available = [f for f in CICIDS_FEATURES if f in df.columns]
    missing   = [f for f in CICIDS_FEATURES if f not in df.columns]
    if missing:
        print(f"[CICIDS] {len(missing)} features missing from CSVs: {missing}")
    print(f"[CICIDS] Using {len(available)}/77 features")

    label_cols = ["binary_label", "attack_category", "label_encoded"]
    return df[available + label_cols], available


def clean(df, feature_cols):
    """Replace inf, drop NaN rows, clip illegal negatives."""
    # Replace inf/-inf with NaN
    n_inf = np.isinf(df[feature_cols].values).sum()
    if n_inf:
        print(f"[CICIDS] Replacing {n_inf:,} inf values with NaN")
        df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)

    # Drop rows with NaN in any feature
    before = len(df)
    df.dropna(subset=feature_cols, inplace=True)
    print(f"[CICIDS] Dropped {before - len(df):,} NaN rows → {len(df):,} remain")

    # Clip negative values in byte/packet/size columns (CICFlowMeter bug)
    for col in feature_cols:
        if any(kw in col for kw in NON_NEGATIVE_KEYWORDS):
            n_neg = (df[col] < 0).sum()
            if n_neg:
                df[col] = df[col].clip(lower=0)

    return df


def fit_and_save_scaler(df, feature_cols):
    """Fit StandardScaler on benign traffic only and save it."""
    benign_X = df.loc[df["binary_label"] == 0, feature_cols].values
    scaler = StandardScaler()
    scaler.fit(benign_X)
    joblib.dump(scaler, os.path.join(MODELS_CICIDS, "scaler.pkl"))
    print(f"[CICIDS] Scaler fitted on {len(benign_X):,} benign samples")
    return scaler


def save(df, feature_cols):
    """Save feature list and processed CSV."""
    joblib.dump(feature_cols, os.path.join(MODELS_CICIDS, "feature_names.pkl"))
    df.to_csv(OUT_FILE, index=False)
    print(f"[CICIDS] Saved → {OUT_FILE}")
    print(f"[CICIDS] Shape  : {df.shape}")
    print(f"[CICIDS] Benign : {(df['binary_label']==0).sum():,}")
    print(f"[CICIDS] Attack : {(df['binary_label']==1).sum():,}")
    print(f"[CICIDS] Categories:\n{df['attack_category'].value_counts().to_string()}")


# ── Main ──────────────────────────────────────────────────────────────────────

def preprocess_cicids():
    os.makedirs(DATA_PROCESSED, exist_ok=True)
    os.makedirs(MODELS_CICIDS,  exist_ok=True)

    df = load_raw_files()
    if df is None:
        return None

    df = drop_metadata(df)
    df = build_labels(df)
    df, feature_cols = select_features(df)
    df = clean(df, feature_cols)
    fit_and_save_scaler(df, feature_cols)
    save(df, feature_cols)
    return df


if __name__ == "__main__":
    preprocess_cicids()