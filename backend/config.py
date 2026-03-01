# Central configuration file for the XAI Intrusion Detection System
import os

# DATASET SELECTION

# Change this to switch datasets:
# Options: "nsl_kdd" or "cicids"
DATASET = "cicids"

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