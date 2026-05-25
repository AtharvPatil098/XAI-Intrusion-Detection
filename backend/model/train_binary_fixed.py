import pandas as pd
import numpy as np
import joblib
import os
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.utils import resample
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier

print("🔥 Training PERFECT Binary Model...")

# ==============================
# LOAD DATA
# ==============================
df = pd.read_csv("../data/processed/CICIDS/cicids_full.csv")
df.columns = df.columns.str.strip()

# ==============================
# CLEAN DATA
# ==============================
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

print("✅ After cleaning:", df.shape)

# ==============================
# CREATE LABEL
# ==============================
df["binary_label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

# ==============================
# SAMPLE (FAST)
# ==============================
df = df.sample(n=300000, random_state=42)

# ==============================
# BALANCE
# ==============================
normal = df[df["binary_label"] == 0]
attack = df[df["binary_label"] == 1]

attack = resample(
    attack,
    replace=True,
    n_samples=len(normal),
    random_state=42
)

df = pd.concat([normal, attack]).sample(frac=1, random_state=42)

print("✅ Balanced:", df.shape)

# ==============================
# FEATURES
# ==============================
X = df.drop(["Label", "binary_label"], axis=1)
y = df["binary_label"]

feature_columns = list(X.columns)

# ==============================
# SPLIT
# ==============================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ==============================
# SCALING
# ==============================
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ==============================
# MODEL
# ==============================
model = XGBClassifier(
    n_estimators=150,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric='logloss'
)

model.fit(X_train_scaled, y_train)

# ==============================
# EVAL
# ==============================
y_pred = model.predict(X_test_scaled)

print("\n🔥 PERFORMANCE")
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# ==============================
# SAVE
# ==============================
os.makedirs("../saved_models/CICIDS", exist_ok=True)
os.makedirs("../artifacts", exist_ok=True)

joblib.dump(model, "../saved_models/CICIDS/xgb_model.pkl")
joblib.dump(scaler, "../saved_models/CICIDS/scaler.pkl")

with open("../artifacts/cicids_feature_columns.json", "w") as f:
    json.dump(feature_columns, f)

print("🔥 Model + Scaler Saved!")