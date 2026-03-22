# preprocessing/preprocess_nslkdd.py
# Merges KDDTrain_ + KDDTest_, encodes categoricals, saves processed CSV.
#
# Run: python preprocess_nslkdd.py

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib

from config import DATA_RAW_NSLKDD, DATA_PROCESSED, NSL_KDD_COLUMNS, MODELS_NSLKDD

# ── File paths ────────────────────────────────────────────────────────────────
TRAIN_FILE = os.path.join(DATA_RAW_NSLKDD, "KDDTrain+.txt")
TEST_FILE  = os.path.join(DATA_RAW_NSLKDD, "KDDTest+.txt")
OUT_FILE   = os.path.join(DATA_PROCESSED,  "nsl_kdd_processed.csv")

# ── Attack label → category mapping ──────────────────────────────────────────
# Moved here from config.py — only used during preprocessing
ATTACK_CATEGORIES = {
    "normal": "normal",
    # DoS
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos",
    "smurf": "dos", "teardrop": "dos", "apache2": "dos", "udpstorm": "dos",
    "processtable": "dos", "worm": "dos", "mailbomb": "dos",
    # Probe
    "ipsweep": "probe", "nmap": "probe", "portsweep": "probe",
    "satan": "probe", "mscan": "probe", "saint": "probe",
    # R2L (remote to local)
    "ftp_write": "r2l", "guess_passwd": "r2l", "imap": "r2l",
    "multihop": "r2l", "phf": "r2l", "spy": "r2l",
    "warezclient": "r2l", "warezmaster": "r2l", "sendmail": "r2l",
    "named": "r2l", "snmpattack": "r2l", "snmpguess": "r2l",
    "xlock": "r2l", "xsnoop": "r2l", "httptunnel": "r2l",
    # U2R (user to root)
    "buffer_overflow": "u2r", "loadmodule": "u2r", "perl": "u2r",
    "rootkit": "u2r", "ps": "u2r", "sqlattack": "u2r", "xterm": "u2r",
}

# Categorical features that need label encoding (text → integer)
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


# ── Step functions ────────────────────────────────────────────────────────────

def load_raw_files():
    """Load train and test txt files and combine into one DataFrame."""
    print("[NSL-KDD] Loading train and test files...")
    train = pd.read_csv(TRAIN_FILE, header=None, names=NSL_KDD_COLUMNS)
    test  = pd.read_csv(TEST_FILE,  header=None, names=NSL_KDD_COLUMNS)
    df = pd.concat([train, test], ignore_index=True)
    print(f"[NSL-KDD] Total records: {len(df):,}")
    return df


def build_labels(df):
    """Add attack_category and binary_label columns, drop raw label."""
    df["attack_category"] = df["label"].str.strip().str.lower().map(
        lambda x: ATTACK_CATEGORIES.get(x, "other")
    )
    df["binary_label"] = (df["attack_category"] != "normal").astype(int)
    df.drop(columns=["label", "difficulty"], inplace=True)
    return df


def encode_categoricals(df):
    """Label-encode protocol_type, service, flag. Save encoders for inference."""
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le

    joblib.dump(encoders, os.path.join(MODELS_NSLKDD, "label_encoders.pkl"))
    print(f"[NSL-KDD] Saved label encoders for: {CATEGORICAL_COLS}")
    return df


def save(df):
    """Save processed DataFrame to CSV."""
    df.to_csv(OUT_FILE, index=False)
    print(f"[NSL-KDD] Saved → {OUT_FILE}")
    print(f"[NSL-KDD] Shape : {df.shape}")
    print(f"[NSL-KDD] Labels:\n{df['binary_label'].value_counts().to_string()}")


# ── Main ──────────────────────────────────────────────────────────────────────

def preprocess_nslkdd():
    os.makedirs(DATA_PROCESSED, exist_ok=True)
    os.makedirs(MODELS_NSLKDD,  exist_ok=True)

    df = load_raw_files()
    df = build_labels(df)
    df = encode_categoricals(df)
    save(df)
    return df


if __name__ == "__main__":
    preprocess_nslkdd()