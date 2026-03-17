# Central configuration file for the XAI Intrusion Detection System
import os

# DATASET SELECTION

# Change this to switch datasets:
# Options: "nsl_kdd" or "cicids"
DATASET = "nsl_kdd"

# BASE DIRECTORIES
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.path.join(BASE_DIR, "backend", "data")
RAW_DATA_DIR = os.path.join(DATA_DIR, "raw", DATASET)
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")

MODEL_DIR = os.path.join(BASE_DIR, "backend", "saved_models", DATASET)


# PROCESSED FILE PATH
PROCESSED_DATA_PATH = os.path.join(
    PROCESSED_DATA_DIR, f"{DATASET}_processed.csv"
)

# MODEL PATHS
RF_MODEL_PATH = os.path.join(MODEL_DIR, "rf_model.pkl")
IF_MODEL_PATH = os.path.join(MODEL_DIR, "if_model.pkl")


# CLASS LABELS
ATTACK_CLASS_LABEL = 1
NORMAL_CLASS_LABEL = 0



# RISK SCORE THRESHOLDS
LOW_RISK_MAX = 30
MEDIUM_RISK_MAX = 70
HIGH_RISK_MAX = 100

# ISOLATION FOREST SETTINGS
ANOMALY_SCORE_THRESHOLD = -0.2
# Scores lower than this are considered anomalous



# FEATURE CONFIGURATION (DATASET SPECIFIC)
if DATASET == "nsl_kdd":

    FEATURE_COLUMNS = [
        "duration", "protocol_type", "service", "flag",
        "src_bytes", "dst_bytes", "land", "wrong_fragment",
        "urgent", "hot", "num_failed_logins", "logged_in",
        "num_compromised", "root_shell", "su_attempted",
        "num_root", "num_file_creations", "num_shells",
        "num_access_files", "num_outbound_cmds",
        "is_host_login", "is_guest_login", "count",
        "srv_count", "serror_rate", "srv_serror_rate",
        "rerror_rate", "srv_rerror_rate", "same_srv_rate",
        "diff_srv_rate", "srv_diff_host_rate",
        "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
    ]

elif DATASET == "cicids":

    FEATURE_COLUMNS = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Fwd Packet Length Mean",
        "Bwd Packet Length Mean",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "URG Flag Count",
        "Average Packet Size",
        "Subflow Fwd Bytes",
        "Subflow Bwd Bytes",
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward"
    ]

else:
    raise ValueError("Invalid DATASET selected. Choose 'nsl_kdd' or 'cicids'.")



# ==============================
# ==============================


# SYSTEM MODE CONFIGURATION


# Enable real-time IDS (VM traffic monitoring)
REALTIME_MODE = True


# DATASET CONFIGURATION


# Supported datasets (used for training + real-time mapping)
DATASETS = ["nsl_kdd", "cicids"]

# MODEL PATHS
# Paths to trained models
MODEL_PATHS = {
    "nsl_kdd": {
        "rf": "backend/saved_models/NSL_KDD/rf_model.pkl",
        "if": "backend/saved_models/NSL_KDD/if_model.pkl"
    },
    "cicids": {
        "rf": "backend/saved_models/CICIDS/rf_model.pkl",
        "if": "backend/saved_models/CICIDS/if_model.pkl"
    }
}



# NETWORK CONFIGURATION

# Interface for packet capture 
# Common VMware interfaces:
# Windows: "vmnet1" (Host-only), "vmnet8" (NAT)
# Linux: "vmnet1", "vmnet8"
NETWORK_INTERFACE = "vmnet1"

# FLOW CONFIGURATION
# Flow timeout (in seconds)
FLOW_TIMEOUT = 30

# Minimum packets required before processing a flow
MIN_PACKETS_PER_FLOW = 5

# RISK THRESHOLDS
# Used for alert classification
RISK_THRESHOLDS = {
    "normal": 0.3,
    "suspicious": 0.6,
    "attack": 0.8
}

# LOGGING CONFIG
ENABLE_LOGGING = True
LOG_FILE = "backend/logs/ids.log"


# DEBUG MODE
DEBUG = True