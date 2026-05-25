<<<<<<< HEAD
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
=======
# preprocessing/feature_adapter.py
# Converts a raw feature dict → numpy array ready for model inference.
# Handles NSL-KDD (41 features), CICIDS (77 features), and DUAL mode (both).

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import joblib

from config import MODELS_NSLKDD, MODELS_CICIDS

# NSL-KDD feature order — must match the order used during training
NSL_KDD_FEATURES = [
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
    "dst_host_srv_rerror_rate"
]

# These three NSL-KDD columns are text and need label encoding
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


# ── Small helpers ─────────────────────────────────────────────────────────────

def encode_categorical(value, encoder):
    """Encode a single categorical value. Returns 0 for unseen values."""
    if encoder is None:
        return 0
    try:
        return int(encoder.transform([str(value)])[0])
    except Exception:
        return 0


def to_float(value):
    """Safely cast any value to float. Returns 0.0 on failure."""
    try:
        return float(value)
    except Exception:
        return 0.0


# ── Single dataset adapter ────────────────────────────────────────────────────

class FeatureAdapter:
    """
    Converts a raw feature dict → (1, n_features) numpy array
    for a single dataset (nslkdd or cicids).

    Usage:
        adapter = FeatureAdapter("nslkdd")
        X = adapter.adapt({"duration": 0, "protocol_type": "tcp", ...})
    """

    def __init__(self, dataset: str):
        self.dataset = dataset.lower()
        self.encoders = None        # NSL-KDD only
        self.feature_names = None
        self._load_artifacts()

    def _load_artifacts(self):
        if self.dataset == "nslkdd":
            enc_path = os.path.join(MODELS_NSLKDD, "label_encoders.pkl")
            if os.path.exists(enc_path):
                self.encoders = joblib.load(enc_path)
            self.feature_names = NSL_KDD_FEATURES

        elif self.dataset == "cicids":
            feat_path = os.path.join(MODELS_CICIDS, "feature_names.pkl")
            if os.path.exists(feat_path):
                self.feature_names = joblib.load(feat_path)
            else:
                # Fallback before first preprocessing run
                from preprocessing.preprocess_cicids import CICIDS_FEATURES
                self.feature_names = CICIDS_FEATURES

    def adapt(self, input_dict: dict) -> np.ndarray:
        """Convert raw feature dict → (1, n_features) float32 array."""
        if self.dataset == "nslkdd":
            return self._adapt_nslkdd(input_dict)
        elif self.dataset == "cicids":
            return self._adapt_cicids(input_dict)
        else:
            raise ValueError(f"Unknown dataset '{self.dataset}'. Use 'nslkdd' or 'cicids'.")

    def _adapt_nslkdd(self, d: dict) -> np.ndarray:
        row = []
        for feat in NSL_KDD_FEATURES:
            if feat in CATEGORICAL_COLS:
                encoder = self.encoders.get(feat) if self.encoders else None
                val = encode_categorical(d.get(feat, ""), encoder)
            else:
                val = to_float(d.get(feat, 0))
            row.append(val)
        return np.array(row, dtype=np.float32).reshape(1, -1)

    def _adapt_cicids(self, d: dict) -> np.ndarray:
        if self.feature_names is None:
            raise RuntimeError("CICIDS feature names not loaded. Run preprocess_cicids.py first.")
        row = [to_float(d.get(feat, 0.0)) for feat in self.feature_names]
        return np.array(row, dtype=np.float32).reshape(1, -1)

    def get_feature_names(self):
        return self.feature_names or []


# ── Dual dataset adapter ──────────────────────────────────────────────────────

class DualFeatureAdapter:
    """
    Takes one unified input dict and produces feature arrays for BOTH datasets.

    The input dict is a superset of both feature spaces. Each adapter picks
    only the fields it needs and ignores the rest. Missing fields default to 0.

    Usage:
        adapter = DualFeatureAdapter()
        X_nslkdd, X_cicids = adapter.adapt(input_dict)
    """

    def __init__(self):
        self.nslkdd = FeatureAdapter("nslkdd")
        self.cicids  = FeatureAdapter("cicids")

    def adapt(self, input_dict: dict):
        """
        Returns (X_nslkdd, X_cicids) — two numpy arrays from one input dict.
        Each adapter silently ignores fields it doesn't recognise.
        """
        X_nslkdd = self.nslkdd.adapt(input_dict)
        X_cicids  = self.cicids.adapt(input_dict)
        return X_nslkdd, X_cicids

# ── Additions to feature_adapter.py ──────────────────────────────────────────
#
# Add these two functions to preprocessing/feature_adapter.py.
# They are called inside aggregate_features() in flow_extractor.py
# to inject derived features that help the classifier distinguish
# nmap scans from SYN floods.
#
# USAGE in flow_extractor.py → aggregate_features():
#
#   features = aggregate_features(flows)
#   features.update(compute_derived_features(flows, features))
#   post_prediction(features, ...)
#
# ─────────────────────────────────────────────────────────────────────────────

from collections import Counter


def compute_derived_features(flows: list, base_features: dict) -> dict:
    """
    Compute additional discriminative features from a burst of flows.

    These are NOT trained features — they are passed in the unified feature
    dict and used ONLY by infer_attack_type() for rule-based classification.
    The ML models ignore keys they were not trained on.

    Derived features added:
      unique_dst_ports    — number of distinct destination ports contacted
      unique_src_ports    — number of distinct source ports used
      port_entropy        — Shannon entropy of destination port distribution
                            (high = scan, low = flood targeting one port)
      syn_ack_ratio       — SYN count / ACK count
                            (>10 = SYN flood or unanswered SYN scan)
      bytes_per_flow      — average total bytes per flow
                            (very low = empty probe packets)
      response_ratio      — fraction of flows that received ANY reply bytes
                            (low = most connections unanswered → scan/flood)
      single_port_frac    — fraction of flows to the most-common dst port
                            (high = flood; low = scan across many ports)
    """
    import math

    n = len(flows) or 1

    dst_ports = [f.dst_port for f in flows]
    src_ports = [f.src_port for f in flows]
    port_counts = Counter(dst_ports)

    unique_dst = len(set(dst_ports))
    unique_src = len(set(src_ports))

    # Shannon entropy of destination port distribution
    total_conns = sum(port_counts.values())
    entropy = 0.0
    for cnt in port_counts.values():
        p = cnt / total_conns
        entropy -= p * math.log2(p) if p > 0 else 0

    # SYN/ACK ratio — unanswered SYNs dominate in scans and SYN floods
    total_syn = sum(f.syn_count for f in flows)
    total_ack = sum(f.ack_count for f in flows) or 1
    syn_ack_ratio = total_syn / total_ack

    # Average bytes per flow
    bytes_per_flow = (
        (base_features.get("src_bytes", 0) + base_features.get("dst_bytes", 0)) / n
    )

    # Fraction of flows with non-zero reply (dst_bytes > 0 per flow)
    flows_with_reply = sum(
        1 for f in flows if sum(p[1] for p in f.bwd_packets) > 0
    )
    response_ratio = flows_with_reply / n

    # Fraction of flows going to the single most-common port
    most_common_count = port_counts.most_common(1)[0][1] if port_counts else 0
    single_port_frac = most_common_count / n

    return {
        "unique_dst_ports":  unique_dst,
        "unique_src_ports":  unique_src,
        "port_entropy":      round(entropy, 4),
        "syn_ack_ratio":     round(syn_ack_ratio, 4),
        "bytes_per_flow":    round(bytes_per_flow, 2),
        "response_ratio":    round(response_ratio, 4),
        "single_port_frac":  round(single_port_frac, 4),
    }


# ── Extended infer_attack_type using derived features ────────────────────────
# Replace the existing infer_attack_type() in app.py with this version.
# It consumes the derived features above in addition to the raw flow features.

def infer_attack_type_v2(features: dict, rf_attack: bool, if_anomaly: bool) -> str:
    """
    Hybrid classifier v2 — uses both raw flow features AND derived features
    from compute_derived_features() for higher accuracy on real VM traffic.

    Probe vs DoS disambiguation:
      Port Scan (nmap):  high port_entropy + high unique_dst_ports + low single_port_frac
      SYN Flood (hping): low port_entropy + high single_port_frac + very high syn_ack_ratio
    """
    if not rf_attack and not if_anomaly:
        return "Normal"

    def f(key, default=0.0):
        return float(features.get(key, default) or default)

    # Raw flow features
    count        = f("count")
    serr         = f("serror_rate")
    rerr         = f("rerror_rate")
    diff_srv     = f("diff_srv_rate")
    same_srv     = f("same_srv_rate")
    src_bytes    = f("src_bytes")
    dst_bytes    = f("dst_bytes")
    duration     = f("duration")
    flag         = str(features.get("flag", ""))
    proto        = str(features.get("protocol_type", "")).lower()
    logged_in    = int(f("logged_in"))

    port         = int(f("Destination Port"))
    syn_cnt      = f("SYN Flag Count")
    fin_cnt      = f("FIN Flag Count")
    ack_cnt      = f("ACK Flag Count")
    pkts_s       = f("Flow Packets/s")
    fwd_bytes    = f("Total Length of Fwd Packets")
    bwd_bytes    = f("Total Length of Bwd Packets")

    src_b = fwd_bytes if fwd_bytes > 0 else src_bytes
    dst_b = bwd_bytes if bwd_bytes > 0 else dst_bytes
    total_bytes  = src_b + dst_b
    reply_ratio  = dst_b / total_bytes if total_bytes > 0 else 0.0

    # Derived features (may be 0 if compute_derived_features wasn't called)
    port_entropy     = f("port_entropy")
    unique_dst       = f("unique_dst_ports")
    syn_ack_ratio    = f("syn_ack_ratio")
    bytes_per_flow   = f("bytes_per_flow")
    response_ratio   = f("response_ratio")
    single_port_frac = f("single_port_frac")

    # Fall back to raw indicators when derived features are missing
    if port_entropy == 0 and diff_srv > 0:
        port_entropy = diff_srv * 3        # rough approximation

    if not rf_attack and not if_anomaly:
        return "Normal"

    # ── 1. PROBE / SCAN (TOP PRIORITY) ─────────────────────────────

    # HARD scan detection (override everything)
    if (
        unique_dst > 20
        and port_entropy > 2.0
        and single_port_frac < 0.2
    ):
        if proto == "icmp":
            return "Probe — Host Discovery (nmap)"
        return "Probe — Port Scan (nmap SYN)"


    # softer scan pattern (optional refinement)
    is_scan_pattern = (
        (unique_dst > 3 or diff_srv > 0.3 or port_entropy > 1.0)
        and single_port_frac < 0.5
        and bytes_per_flow < 800
    )

    if is_scan_pattern and response_ratio > 0.2:
        return "Probe — Service Scan (nmap -sV)"

    # ── 2. BRUTE FORCE ────────────────────────────────────────────────────────
    #
    # Hydra: single port, bidirectional, many attempts, low port_entropy
    is_brute_port = port in (22, 21, 23, 3306, 3389, 5900, 80, 443, 8080)
    is_repeated = same_srv > 0.6 and count > 5
    has_exchange = src_b > 0 or dst_b > 0

    if is_brute_port and single_port_frac > 0.8 and src_b > 0 and count > 3:
        svc_map = {22: "SSH", 21: "FTP", 23: "Telnet", 3306: "MySQL",
                   3389: "RDP", 5900: "VNC", 80: "HTTP", 443: "HTTPS", 8080: "HTTP"}
        svc = svc_map.get(port, str(port))
        return f"Brute Force — {svc} (Hydra)"

    # Hydra on non-standard port
    if is_repeated and has_exchange and not is_scan_pattern and count > 20:
        return "Brute Force — Credential Attack"

    # ── 3. WEB ATTACK ─────────────────────────────────────────────────────────
    if port in (80, 443, 8080, 8443) and src_b > 10_000 and not is_scan_pattern:
        return "Web Attack — Payload Injection"

    # ── 4. DoS / DDoS ─────────────────────────────────────────────────────────
    #
    # DoS targeting one port: single_port_frac high, high rate, low reply
    is_single_target = (single_port_frac > 0.7) and not is_scan_pattern

    # SYN Flood: high syn_ack_ratio, single port, mostly unanswered
    if (is_single_target and (syn_ack_ratio > 5 or serr > 0.5)
            and count > 50 and fin_cnt < count * 0.05):
        return "DoS — SYN Flood (hping3)"

    # ICMP flood
    if proto == "icmp" and count > 100:
        return "DoS — ICMP Flood"

    # UDP flood
    if is_single_target and count > 150 and dst_b == 0:
        return "DoS — UDP/Null Flood"

    # High packet rate flood
    if pkts_s > 50_000 and is_single_target:
        return "DoS — Packet Flood"

    # Volumetric
    if is_single_target and src_b > 500_000 and reply_ratio < 0.1:
        return "DoS — Volumetric Flood"

    # Slow DoS
    if is_single_target and count > 50 and duration > 30 and total_bytes < 1000:
        return "DoS — Slow Attack (Slowloris)"
    
    if if_anomaly and not rf_attack:
        if count > 100 or single_port_frac > 0.8:
            return "DoS — Likely Flood Attack"
        return "Unknown — Possible Zero-Day"

    # ── 5. ZERO-DAY ───────────────────────────────────────────────────────────
    if if_anomaly and not rf_attack:
        return "Unknown — Possible Zero-Day"

    return "Attack — Unclassified"

>>>>>>> b74af1039ca230811c9075534ea29f37bdc263f8
