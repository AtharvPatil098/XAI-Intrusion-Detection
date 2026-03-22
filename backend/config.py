# config.py
# Central configuration — paths and settings only.
# Feature definitions live in the preprocessing scripts.

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Data paths ────────────────────────────────────────────────────────────────
DATA_RAW_NSLKDD = os.path.join(BASE_DIR, "data", "raw", "NSL_KDD")
DATA_RAW_CICIDS  = os.path.join(BASE_DIR, "data", "raw", "CICIDS")
DATA_PROCESSED   = os.path.join(BASE_DIR, "data", "processed")

# ── Saved model paths ─────────────────────────────────────────────────────────
MODELS_NSLKDD = os.path.join(BASE_DIR, "saved_models", "NSL_KDD")
MODELS_CICIDS  = os.path.join(BASE_DIR, "saved_models", "CICIDS")

# ── NSL-KDD raw column names (41 features + label + difficulty) ───────────────
NSL_KDD_COLUMNS = [
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
    "dst_host_srv_rerror_rate", "label", "difficulty"
]

# ── CICIDS metadata columns to drop (not features) ────────────────────────────
CICIDS_DROP_COLS = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp"]
CICIDS_LABEL_COL = "Label"

# ── Model settings ────────────────────────────────────────────────────────────
IF_CONTAMINATION = 0.05     # Isolation Forest: expected fraction of anomalies

# ── API settings ──────────────────────────────────────────────────────────────
API_HOST = "0.0.0.0"
API_PORT = 8000