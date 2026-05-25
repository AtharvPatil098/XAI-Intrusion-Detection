import pandas as pd
import joblib
import os
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import cross_val_score

# -----------------------------
# LOAD DATA
# -----------------------------
X_train = pd.read_csv("../data/processed/cicids_X_train.csv")
X_test = pd.read_csv("../data/processed/cicids_X_test.csv")
y_train = pd.read_csv("../data/processed/cicids_y_train.csv").values.ravel()
y_test = pd.read_csv("../data/processed/cicids_y_test.csv").values.ravel()

print("✅ CICIDS Data Loaded")

# -----------------------------
# 🚨 NO UNDERSAMPLING (MULTICLASS FIX)
# -----------------------------
X_train_bal, y_train_bal = X_train, y_train

print("\n📊 Training data shape:", X_train_bal.shape)

# -----------------------------
# 🚀 XGBOOST MODEL (MULTICLASS)
# -----------------------------
print("\n🚀 Training XGBoost...")

xgb_model = XGBClassifier(
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

xgb_model.fit(X_train_bal, y_train_bal)

# Predictions
y_pred_xgb = xgb_model.predict(X_test)

print("\n🔹 XGBoost Results:")
print("Accuracy:", accuracy_score(y_test, y_pred_xgb))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred_xgb))
print("\nClassification Report:\n", classification_report(y_test, y_pred_xgb))

# Overfitting Check
print("\n🔍 XGBoost Overfitting Check:")
print("Train:", xgb_model.score(X_train_bal, y_train_bal))
print("Test:", xgb_model.score(X_test, y_test))

# -----------------------------
# 🌲 RANDOM FOREST
# -----------------------------
print("\n🌲 Training Random Forest...")

rf_model = RandomForestClassifier(
    n_estimators=150,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)

rf_model.fit(X_train_bal, y_train_bal)

y_pred_rf = rf_model.predict(X_test)

print("\n🔹 Random Forest Results:")
print("Accuracy:", accuracy_score(y_test, y_pred_rf))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred_rf))
print("\nClassification Report:\n", classification_report(y_test, y_pred_rf))

print("\n🔍 Random Forest Overfitting Check:")
print("Train:", rf_model.score(X_train_bal, y_train_bal))
print("Test:", rf_model.score(X_test, y_test))

# -----------------------------
# 📊 CROSS VALIDATION
# -----------------------------
print("\n📊 Cross Validation (RF):")

cv_scores = cross_val_score(rf_model, X_train_bal, y_train_bal, cv=3)

print("Scores:", cv_scores)
print("Mean CV Score:", cv_scores.mean())

# -----------------------------
# 🔥 FEATURE IMPORTANCE
# -----------------------------
feat_imp = pd.Series(rf_model.feature_importances_, index=X_train.columns)

print("\n🔥 Top 10 Important Features:")
print(feat_imp.sort_values(ascending=False).head(10))

# -----------------------------
# 💾 SAVE MODELS
# -----------------------------
save_path = "../saved_models/CICIDS"
os.makedirs(save_path, exist_ok=True)

joblib.dump(xgb_model, f"{save_path}/xgb_multiclass.pkl")
joblib.dump(rf_model, f"{save_path}/rf_multiclass.pkl")

print("\n✅ CICIDS models trained and saved successfully!")