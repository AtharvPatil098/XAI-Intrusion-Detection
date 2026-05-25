<<<<<<< HEAD
import pandas as pd
import json
from sklearn.model_selection import train_test_split

# Step 1: Define column names
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins',
    'logged_in','num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'label','difficulty'
]

# Step 2: Load dataset
train_path = "../data/raw/NSL_KDD/KDDTrain+.txt"
df = pd.read_csv(train_path, names=columns)

# Step 3: Basic checks
print("✅ Dataset shape:", df.shape)

print("\n🔹 First 5 rows:")
print(df.head())

print("\n🔹 Dataset Info:")
print(df.info())

print("\n🔹 Label distribution (original):")
print(df['label'].value_counts())

# ==============================
# 🚀 STEP 2: DATA CLEANING FLOW
# ==============================

# ✅ 1. Drop column
df = df.drop(columns=['difficulty'])

# ✅ 2. Convert label (binary classification)
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

# ✅ 3. One-hot encoding
categorical_cols = ['protocol_type', 'service', 'flag']
df = pd.get_dummies(df, columns=categorical_cols)

# ✅ 4. Split features & target
X = df.drop('label', axis=1)
y = df['label']

# ✅ 5. Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ✅ 6. Save feature columns
feature_columns = X.columns.tolist()

with open("../artifacts/feature_columns.json", "w") as f:
    json.dump(feature_columns, f)

# ✅ 7. Save processed data
X_train.to_csv("../data/processed/X_train.csv", index=False)
X_test.to_csv("../data/processed/X_test.csv", index=False)
y_train.to_csv("../data/processed/y_train.csv", index=False)
y_test.to_csv("../data/processed/y_test.csv", index=False)

# ✅ 8. Print shapes
print("\n✅ Final Shapes:")
print("X_train:", X_train.shape)
print("X_test:", X_test.shape)
=======
# preprocessing/preprocess_nslkdd.py
# Merges KDDTrain_ + KDDTest_, encodes categoricals, maps labels to unified
# multi-class scheme, balances classes with SMOTE, and saves processed CSV.
#
# Run: python preprocess_nslkdd.py

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib

from config import DATA_RAW_NSLKDD, DATA_PROCESSED, NSL_KDD_COLUMNS, MODELS_NSLKDD

# ── File paths ────────────────────────────────────────────────────────────────
TRAIN_FILE = os.path.join(DATA_RAW_NSLKDD, "KDDTrain+.txt")
TEST_FILE  = os.path.join(DATA_RAW_NSLKDD, "KDDTest+.txt")
OUT_FILE   = os.path.join(DATA_PROCESSED,  "nsl_kdd_processed.csv")

# ── Unified multi-class label map ─────────────────────────────────────────────
# Final classes: Normal | DoS | Port Scan | Brute Force
# Rows with labels NOT in this map are DROPPED.
LABEL_MAP = {
    # Normal
    "normal":          "Normal",

    # DoS
    "neptune":         "DoS",
    "smurf":           "DoS",
    "back":            "DoS",
    "teardrop":        "DoS",
    "land":            "DoS",
    "pod":             "DoS",
    "apache2":         "DoS",
    "udpstorm":        "DoS",
    "processtable":    "DoS",
    "worm":            "DoS",
    "mailbomb":        "DoS",

    # Port Scan / Probe
    "ipsweep":         "Port Scan",
    "nmap":            "Port Scan",
    "portsweep":       "Port Scan",
    "satan":           "Port Scan",
    "mscan":           "Port Scan",
    "saint":           "Port Scan",

    # Brute Force / R2L / U2R (credential-based, low sample count)
    "guess_passwd":    "Brute Force",
    "ftp_write":       "Brute Force",
    "imap":            "Brute Force",
    "multihop":        "Brute Force",
    "phf":             "Brute Force",
    "spy":             "Brute Force",
    "warezclient":     "Brute Force",
    "warezmaster":     "Brute Force",
    "sendmail":        "Brute Force",
    "named":           "Brute Force",
    "snmpattack":      "Brute Force",
    "snmpguess":       "Brute Force",
    "xlock":           "Brute Force",
    "xsnoop":          "Brute Force",
    "httptunnel":      "Brute Force",
    "buffer_overflow": "Brute Force",
    "loadmodule":      "Brute Force",
    "perl":            "Brute Force",
    "rootkit":         "Brute Force",
    "ps":              "Brute Force",
    "sqlattack":       "Brute Force",
    "xterm":           "Brute Force",
}

FINAL_CLASSES    = {"Normal", "DoS", "Port Scan", "Brute Force"}
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


# ── Step functions ────────────────────────────────────────────────────────────

def load_raw_files():
    missing = [p for p in [TRAIN_FILE, TEST_FILE] if not os.path.exists(p)]
    if missing:
        print(f"[NSL-KDD] Missing files: {missing}")
        print("[NSL-KDD] Download from: https://www.unb.ca/cic/datasets/nsl.html")
        return None

    print("[NSL-KDD] Loading train and test files...")
    train = pd.read_csv(TRAIN_FILE, header=None, names=NSL_KDD_COLUMNS)
    test  = pd.read_csv(TEST_FILE,  header=None, names=NSL_KDD_COLUMNS)
    df    = pd.concat([train, test], ignore_index=True)
    print(f"[NSL-KDD] Total records loaded: {len(df):,}")
    return df


def build_multiclass_labels(df):
    """
    Map raw attack labels → unified multi-class labels.
    Drops rows with unmapped labels.
    Adds attack_category and binary_label.

    NOTE: label_encoded is intentionally NOT added here.
    It is added after SMOTE so the encoder fits the final balanced dataset.
    """
    normalised            = df["label"].astype(str).str.strip().str.lower()
    df["attack_category"] = normalised.map(LABEL_MAP)

    before = len(df)
    df     = df[df["attack_category"].isin(FINAL_CLASSES)].copy()
    if len(df) < before:
        print(f"[NSL-KDD] Dropped {before - len(df):,} rows with unmapped labels")

    # binary_label: 0=Normal, 1=Attack — existing predict.py / app.py unchanged
    df["binary_label"] = (df["attack_category"] != "Normal").astype(int)

    df.drop(columns=["label", "difficulty"], inplace=True)
    return df


def encode_categoricals(df):
    """Label-encode protocol_type, service, flag. Save encoders for inference."""
    encoders = {}
    for col in CATEGORICAL_COLS:
        le         = LabelEncoder()
        df[col]    = le.fit_transform(df[col].astype(str))
        encoders[col] = le
    joblib.dump(encoders, os.path.join(MODELS_NSLKDD, "label_encoders.pkl"))
    print(f"[NSL-KDD] Saved label encoders for: {CATEGORICAL_COLS}")
    return df


def clean(df):
    """Replace inf/NaN in numeric feature columns."""
    exclude   = {"binary_label", "attack_category"}
    feat_cols = [c for c in df.select_dtypes(include=[float, int]).columns
                 if c not in exclude]

    n_inf = np.isinf(df[feat_cols].values).sum()
    if n_inf:
        print(f"[NSL-KDD] Replacing {n_inf:,} inf values with NaN")
        df[feat_cols] = df[feat_cols].replace([np.inf, -np.inf], np.nan)

    before = len(df)
    df.dropna(subset=feat_cols, inplace=True)
    if len(df) < before:
        print(f"[NSL-KDD] Dropped {before - len(df):,} NaN rows → {len(df):,} remain")

    return df


def get_feature_cols(df):
    """Return ordered list of numeric feature columns, excluding label columns."""
    exclude = {"binary_label", "attack_category"}
    return [c for c in df.columns if c not in exclude]


def fit_and_save_scaler(df, feature_cols):
    """
    Fit StandardScaler on REAL Normal rows ONLY and save it.
    Must be called BEFORE SMOTE so synthetic samples don't skew the scaler.
    """
    normal_X = df.loc[df["binary_label"] == 0, feature_cols].values
    scaler   = StandardScaler()
    scaler.fit(normal_X)
    joblib.dump(scaler, os.path.join(MODELS_NSLKDD, "scaler.pkl"))
    print(f"[NSL-KDD] Scaler fitted on {len(normal_X):,} real Normal samples (pre-SMOTE)")
    return scaler


def balance_with_smote(df, feature_cols):
    """
    Balance the four classes using SMOTE.

    Strategy: upsample every class that falls below the MEDIAN class size
    up to that median. Classes already at or above the median are untouched.
    This avoids exploding the dataset to the majority size and keeps runtime
    reasonable.

    Rules respected:
    - SMOTE operates on numeric feature columns only (no label cols).
    - attack_category strings are reconstructed from y after resampling.
    - label_encoded is NOT present yet — it is added after this step.
    - The scaler has already been fitted on real data before this call.
    """
    try:
        from imblearn.over_sampling import SMOTE
    except ImportError:
        print("[NSL-KDD] WARNING: imbalanced-learn not installed.")
        print("          Run: pip install imbalanced-learn")
        print("          Skipping SMOTE — dataset will remain imbalanced.")
        return df

    # Temporary integer encoding for SMOTE (SMOTE requires numeric y)
    le_temp = LabelEncoder()
    y       = le_temp.fit_transform(df["attack_category"])
    X       = df[feature_cols].values

    unique, counts = np.unique(y, return_counts=True)

    print("[NSL-KDD] Class distribution BEFORE balancing:")
    for u, c in zip(unique, counts):
        print(f"  {le_temp.classes_[u]:15s}: {c:>8,}")

    # Target = median class size — upsample minorities, leave majorities alone
    target_n = int(np.median(counts))
    print(f"[NSL-KDD] SMOTE target per class: {target_n:,} (median of class sizes)")

    # Only upsample classes that are BELOW the target
    sampling_strategy = {
        int(cls_idx): max(int(cnt), target_n)
        for cls_idx, cnt in zip(unique, counts)
    }

    # k_neighbors must be strictly less than the smallest minority class size
    min_count   = int(counts.min())
    k_neighbors = min(5, min_count - 1)

    if k_neighbors < 1:
        print(f"[NSL-KDD] WARNING: smallest class has only {min_count} sample(s). "
              "SMOTE requires ≥2 neighbors. Skipping balancing.")
        return df

    smote = SMOTE(
        sampling_strategy=sampling_strategy,
        k_neighbors=k_neighbors,
        random_state=42,
    )

    X_res, y_res = smote.fit_resample(X, y)

    # Reconstruct DataFrame with original column names
    df_res = pd.DataFrame(X_res, columns=feature_cols)
    df_res["attack_category"] = le_temp.inverse_transform(y_res)
    df_res["binary_label"]    = (df_res["attack_category"] != "Normal").astype(int)

    print("[NSL-KDD] Class distribution AFTER balancing:")
    for cls_name in sorted(df_res["attack_category"].unique()):
        n = int((df_res["attack_category"] == cls_name).sum())
        print(f"  {cls_name:15s}: {n:>8,}")

    return df_res


def add_label_encoded(df):
    """
    Fit LabelEncoder on the FINAL balanced dataset and add label_encoded column.
    Must be called AFTER SMOTE so the encoder reflects all rows.
    """
    le = LabelEncoder()
    df = df.copy()
    df["label_encoded"] = le.fit_transform(df["attack_category"])
    joblib.dump(le, os.path.join(MODELS_NSLKDD, "label_encoder.pkl"))
    print(f"[NSL-KDD] Final classes: {list(le.classes_)}")
    return df


def save(df):
    df.to_csv(OUT_FILE, index=False)
    print(f"[NSL-KDD] Saved → {OUT_FILE}")
    print(f"[NSL-KDD] Final shape : {df.shape}")
    print(f"[NSL-KDD] Final label distribution:")
    print(df["attack_category"].value_counts().to_string())
    print(f"[NSL-KDD] Binary: Normal={int((df['binary_label']==0).sum()):,}  "
          f"Attack={int((df['binary_label']==1).sum()):,}")


# ── Main ──────────────────────────────────────────────────────────────────────

def preprocess_nslkdd():
    os.makedirs(DATA_PROCESSED, exist_ok=True)
    os.makedirs(MODELS_NSLKDD,  exist_ok=True)

    df = load_raw_files()
    if df is None:
        return None

    # 1. Map labels
    df = build_multiclass_labels(df)

    # 2. Encode categoricals (must be numeric before SMOTE)
    df = encode_categoricals(df)

    # 3. Clean inf/NaN
    df = clean(df)

    # 4. Determine feature columns
    feature_cols = get_feature_cols(df)

    # 5. Fit scaler on real Normal rows BEFORE any synthetic data is created
    fit_and_save_scaler(df, feature_cols)

    # 6. Save feature names (list does not change after SMOTE)
    joblib.dump(feature_cols, os.path.join(MODELS_NSLKDD, "feature_names.pkl"))

    # 7. Balance with SMOTE (upsamples minority classes to median class size)
    df = balance_with_smote(df, feature_cols)

    # 8. Add label_encoded on the final balanced dataset
    df = add_label_encoded(df)

    # 9. Save
    save(df)
    return df


if __name__ == "__main__":
    preprocess_nslkdd()
>>>>>>> b74af1039ca230811c9075534ea29f37bdc263f8
