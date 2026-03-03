import shap
import joblib
import os
import pandas as pd

from backend.config import DATASET


# -----------------------------
# Load RF Model
# -----------------------------
def load_rf_model():

    dataset = DATASET.strip().lower()

    if dataset == "cicids":
        model_path = "backend/saved_models/CICIDS/rf_model.pkl"
    elif dataset == "nsl_kdd":
        model_path = "backend/saved_models/NSL_KDD/rf_model.pkl"
    else:
        raise ValueError("Unsupported dataset")

    if not os.path.exists(model_path):
        raise FileNotFoundError("Trained RF model not found.")

    model = joblib.load(model_path)
    return model


# -----------------------------
# SHAP Explainer
# -----------------------------
def explain_prediction(input_df):

    model = load_rf_model()

    # Create SHAP TreeExplainer
    explainer = shap.TreeExplainer(model)

    # Compute SHAP values
    shap_values = explainer.shap_values(input_df)

    # For binary classification → index 1 = attack class
    shap_values_attack = shap_values[1][0]

    feature_names = input_df.columns

    explanation = []

    for feature, value in zip(feature_names, shap_values_attack):
        explanation.append({
            "feature": feature,
            "impact": float(value)
        })

    # Sort by absolute importance
    explanation = sorted(
        explanation,
        key=lambda x: abs(x["impact"]),
        reverse=True
    )

    # Return top 10 most important features
    return explanation[:10]