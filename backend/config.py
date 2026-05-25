import os

# ==============================
# 🔹 BASE PATH
# ==============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ==============================
# 🔹 DATA PATHS
# ==============================
DATA_DIR = os.path.join(BASE_DIR, "data")

# 🔥 FULL DATASET (used for BOTH SHAP + prediction sampling)
CICIDS_DATA = os.path.join(
    DATA_DIR,
    "processed",
    "CICIDS",
    "cicids_full.csv"
)

# ❌ REMOVE THIS (not needed anymore)
# CICIDS_PROCESSED = ...

# ==============================
# 🔹 MODEL PATHS
# ==============================
MODEL_DIR = os.path.join(BASE_DIR, "saved_models", "CICIDS")

XGB_MODEL_PATH = os.path.join(MODEL_DIR, "xgb_model.pkl")
IF_MODEL_PATH = os.path.join(MODEL_DIR, "cicids_if_model.pkl")
MULTI_CLASS_MODEL_PATH = os.path.join(MODEL_DIR, "cicids_multiclass.pkl")

# 🔥 SCALER (CRITICAL)
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

# ==============================
# 🔹 ARTIFACTS
# ==============================
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")

FEATURE_COLUMNS_PATH = os.path.join(
    ARTIFACTS_DIR,
    "cicids_feature_columns.json"
)

LABEL_ENCODER_PATH = os.path.join(
    ARTIFACTS_DIR,
    "cicids_label_encoder.pkl"
)

# ==============================
# 🔹 MODEL SETTINGS
# ==============================
ATTACK_THRESHOLD = 0.5
ANOMALY_LABEL = -1

# ==============================
# 🔹 RISK SCORE ENGINE (FINAL 🔥)
# ==============================
def calculate_risk_score(attack_prob, anomaly_score, is_anomaly):
    """
    Balanced risk scoring for realistic dashboard
    """

    # 🔴 CONFIRMED ATTACK
    if attack_prob >= ATTACK_THRESHOLD:
        risk = attack_prob * 100

    # 🟠 UNKNOWN / ANOMALY
    elif is_anomaly:
        anomaly_strength = abs(anomaly_score)
        risk = 60 + (anomaly_strength * 40)

    # 🟢 NORMAL
    else:
        risk = attack_prob * 40

    return round(min(risk, 100), 2)

# ==============================
# 🔹 API SETTINGS
# ==============================
API_HOST = "127.0.0.1"
API_PORT = 8000

# ==============================
# 🔹 CORS
# ==============================
ALLOWED_ORIGINS = [
    "http://127.0.0.1:5500",
    "http://localhost:5500"
]

# ==============================
# 🔹 DEBUG CHECK
# ==============================
def check_paths():
    paths = {
        "XGB_MODEL": XGB_MODEL_PATH,
        "IF_MODEL": IF_MODEL_PATH,
        "MULTI_MODEL": MULTI_CLASS_MODEL_PATH,
        "SCALER": SCALER_PATH,
        "FEATURE_COLUMNS": FEATURE_COLUMNS_PATH,
        "DATASET": CICIDS_DATA
    }

    print("\n🔍 Checking file paths...\n")

    for name, path in paths.items():
        if os.path.exists(path):
            print(f"✅ {name} OK")
        else:
            print(f"❌ {name} NOT FOUND → {path}")

    print("\n")


if __name__ == "__main__":
    check_paths()