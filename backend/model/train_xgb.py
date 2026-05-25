import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import cross_val_score

# -----------------------------
# LOAD DATA
# -----------------------------
X_train = pd.read_csv("../data/processed/X_train.csv")
X_test = pd.read_csv("../data/processed/X_test.csv")
y_train = pd.read_csv("../data/processed/y_train.csv").values.ravel()
y_test = pd.read_csv("../data/processed/y_test.csv").values.ravel()

print("✅ Data loaded successfully")

# -----------------------------
# 🔹 XGBoost Model (MAIN)
# -----------------------------
print("\n🚀 Training XGBoost...")

# Handle imbalance
scale_pos_weight = (len(y_train) - sum(y_train)) / sum(y_train)

xgb_model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=scale_pos_weight,
    eval_metric='logloss',
    random_state=42
)

xgb_model.fit(X_train, y_train)

# Predictions
y_pred_xgb = xgb_model.predict(X_test)

print("\n🔹 XGBoost Results:")
print("Accuracy:", accuracy_score(y_test, y_pred_xgb))
print(confusion_matrix(y_test, y_pred_xgb))
print(classification_report(y_test, y_pred_xgb))

# 🔥 Overfitting Check
print("\n🔍 XGBoost Overfitting Check:")
print("Train Accuracy:", xgb_model.score(X_train, y_train))
print("Test Accuracy:", xgb_model.score(X_test, y_test))

# Save model
joblib.dump(xgb_model, "../saved_models/NSL_KDD/xgb_model.pkl")

# -----------------------------
# 🔹 Random Forest (IMPROVED)
# -----------------------------
print("\n🌲 Training Random Forest...")

rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    class_weight='balanced',   # 🔥 IMPORTANT
    random_state=42,
    n_jobs=-1
)

rf_model.fit(X_train, y_train)

y_pred_rf = rf_model.predict(X_test)

print("\n🔹 Random Forest Results:")
print("Accuracy:", accuracy_score(y_test, y_pred_rf))
print(confusion_matrix(y_test, y_pred_rf))
print(classification_report(y_test, y_pred_rf))

# 🔥 Overfitting Check
print("\n🔍 Random Forest Overfitting Check:")
print("Train Accuracy:", rf_model.score(X_train, y_train))
print("Test Accuracy:", rf_model.score(X_test, y_test))

# -----------------------------
# 🔹 CROSS VALIDATION (IMPORTANT)
# -----------------------------
print("\n📊 Cross Validation (Random Forest):")

cv_scores = cross_val_score(rf_model, X_train, y_train, cv=5)

print("CV Scores:", cv_scores)
print("Mean CV Score:", cv_scores.mean())

# -----------------------------
# 🔹 FEATURE IMPORTANCE
# -----------------------------
feat_imp = pd.Series(rf_model.feature_importances_, index=X_train.columns)

print("\n🔥 Top 10 Important Features:")
print(feat_imp.sort_values(ascending=False).head(10))

# Save model
joblib.dump(rf_model, "../saved_models/NSL_KDD/rf_model.pkl")

print("\n✅ Models trained and saved successfully!")