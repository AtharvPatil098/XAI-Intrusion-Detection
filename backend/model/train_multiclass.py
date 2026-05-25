import pandas as pd
import joblib
import os
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# -----------------------------
# LOAD DATA
# -----------------------------
X_train = pd.read_csv("../data/processed/cicids_X_train.csv")
X_test = pd.read_csv("../data/processed/cicids_X_test.csv")
y_train = pd.read_csv("../data/processed/cicids_y_train.csv").values.ravel()
y_test = pd.read_csv("../data/processed/cicids_y_test.csv").values.ravel()

print("✅ Data Loaded")

# -----------------------------
# 🚀 MODEL (MULTICLASS)
# -----------------------------
model = XGBClassifier(
    n_estimators=200,
    max_depth=10,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    objective='multi:softprob',   # 🔥 IMPORTANT
    eval_metric='mlogloss',
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# -----------------------------
# PREDICT
# -----------------------------
y_pred = model.predict(X_test)

print("\n🎯 Results:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# -----------------------------
# SAVE MODEL
# -----------------------------
os.makedirs("../saved_models/CICIDS", exist_ok=True)
joblib.dump(model, "../saved_models/CICIDS/xgb_multiclass.pkl")

print("\n✅ Model Saved!")