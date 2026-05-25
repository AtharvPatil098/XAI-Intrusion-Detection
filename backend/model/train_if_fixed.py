import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest

print("🔥 Training Isolation Forest...")

# ==============================
# 🔹 LOAD DATA
# ==============================
df = pd.read_csv("../data/processed/CICIDS/cicids_full.csv")
df.columns = df.columns.str.strip()

# ==============================
# 🔹 CLEAN
# ==============================
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# ==============================
# 🔹 REMOVE LABEL
# ==============================
if "Label" in df.columns:
    df = df.drop(columns=["Label"])

# ==============================
# 🔹 SAMPLE (important)
# ==============================
df = df.sample(n=100000, random_state=42)

print("✅ Data shape:", df.shape)

# ==============================
# 🔹 TRAIN IF
# ==============================
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

model.fit(df)

# ==============================
# 🔹 SAVE
# ==============================
os.makedirs("../saved_models/CICIDS", exist_ok=True)

joblib.dump(model, "../saved_models/CICIDS/cicids_if_model.pkl")

print("🔥 Isolation Forest Ready!")