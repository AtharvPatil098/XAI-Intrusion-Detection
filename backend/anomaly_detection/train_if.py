import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

print("🔥 Training Isolation Forest...")

# ==============================
# 🔹 PATHS (MATCH YOUR PROJECT)
# ==============================

DATA_PATH = "../data/processed/cicids_X_train.csv"
SAVE_PATH = "../saved_models/CICIDS/cicids_if_model.pkl"

# ==============================
# 🔹 LOAD DATA
# ==============================

if not os.path.exists(DATA_PATH):
    print("❌ Data file not found:", DATA_PATH)
    exit()

df = pd.read_csv(DATA_PATH)

print("✅ Data Loaded:", df.shape)

# ==============================
# 🔹 TRAIN MODEL
# ==============================

model = IsolationForest(
    n_estimators=100,
    contamination=0.05,   # assume ~5% anomalies
    random_state=42,
    n_jobs=-1
)

model.fit(df)

print("✅ Isolation Forest trained")

# ==============================
# 🔹 SAVE MODEL
# ==============================

os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)
joblib.dump(model, SAVE_PATH)

print("💾 Model saved at:", SAVE_PATH) 
