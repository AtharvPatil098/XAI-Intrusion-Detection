import pandas as pd
import json
import os

# ==============================
# 🔹 LOAD FEATURE COLUMNS
# ==============================
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
FEATURE_PATH = os.path.join(BASE_DIR, "artifacts", "cicids_feature_columns.json")

with open(FEATURE_PATH, "r") as f:
    feature_columns = json.load(f)


# ==============================
# 🔹 ADAPTER FUNCTION (FINAL)
# ==============================
def adapt_raw_input(raw_input):

    # --------------------------
    # 🔹 INPUT VALUES (SAFE DEFAULTS)
    # --------------------------
    packets = max(raw_input.get("packets", 10), 1)
    bytes_ = max(raw_input.get("bytes", 1000), 1)
    duration = max(raw_input.get("duration", 1), 1e-6)
    port = raw_input.get("port", 80)

    adapted = {}

    # --------------------------
    # 🔹 CORE FLOW FEATURES
    # --------------------------
    adapted["Flow Duration"] = duration

    adapted["Total Fwd Packets"] = packets
    adapted["Total Backward Packets"] = int(packets * 0.4)

    adapted["Total Length of Fwd Packets"] = bytes_
    adapted["Total Length of Bwd Packets"] = int(bytes_ * 0.4)

    # --------------------------
    # 🔹 RATE FEATURES (IMPORTANT)
    # --------------------------
    adapted["Flow Bytes/s"] = bytes_ / duration
    adapted["Flow Packets/s"] = packets / duration

    # --------------------------
    # 🔹 PACKET SIZE FEATURES
    # --------------------------
    pkt_mean = bytes_ / packets

    adapted["Packet Length Mean"] = pkt_mean
    adapted["Packet Length Variance"] = pkt_mean * 10

    adapted["Max Packet Length"] = pkt_mean * 1.5
    adapted["Min Packet Length"] = pkt_mean * 0.5

    # --------------------------
    # 🔹 TCP / NETWORK BEHAVIOR
    # --------------------------
    adapted["Destination Port"] = port

    # Simulate realistic TCP window behavior
    adapted["Init_Win_bytes_forward"] = bytes_ % 65535
    adapted["Init_Win_bytes_backward"] = int((bytes_ * 0.5) % 65535)

    # Flags (simple heuristic)
    adapted["PSH Flag Count"] = 1 if packets > 500 else 0

    # Idle time
    adapted["Idle Max"] = duration * 0.3

    # Header length (approximation)
    adapted["Fwd Header Length"] = packets * 20
    adapted["Bwd Header Length"] = int(packets * 0.4) * 20

    # --------------------------
    # 🔹 FILL REMAINING FEATURES
    # --------------------------
    for col in feature_columns:
        if col not in adapted:
            adapted[col] = 0

    # --------------------------
    # 🔹 FINAL DATAFRAME
    # --------------------------
    df = pd.DataFrame([adapted])
    df = df[feature_columns]

    return df