import os
import joblib
import numpy as np
import pandas as pd

from backend.config import DATASET
from backend.explainability.shap_explainer import explain_prediction

# PATH CONFIGURATION

def get_model_paths():
    dataset = DATASET.strip().lower()

    if dataset == "cicids":
        rf_path = "backend/saved_models/CICIDS/rf_model.pkl"
        if_path = "backend/saved_models/CICIDS/if_model.pkl"

    elif dataset == "nsl_kdd":
        rf_path = "backend/saved_models/NSL_KDD/rf_model.pkl"
        if_path = "backend/saved_models/NSL_KDD/if_model.pkl"

    else:
        raise ValueError(f"Unsupported dataset: {DATASET}")

    return rf_path, if_path


# LOAD MODELS

def load_models():
    rf_path, if_path = get_model_paths()

    if not os.path.exists(rf_path):
        raise FileNotFoundError("Random Forest model not found.")

    if not os.path.exists(if_path):
        raise FileNotFoundError("Isolation Forest model not found.")

    rf_model = joblib.load(rf_path)
    if_model = joblib.load(if_path)

    print("Models loaded successfully.")
    return rf_model, if_model


# RISK SCORE LOGIC

def compute_risk_score(rf_prob, if_flag):
    """
    Hybrid risk scoring logic (0–100)
    """

    # Base risk from RF probability
    base_score = rf_prob * 100

    # If anomaly detected, boost risk
    if if_flag == 1:
        base_score += 20

    # Cap at 100
    return min(base_score, 100)


# HYBRID PREDICTION
def predict(input_df):

    rf_model, if_model = load_models()

    # RF Prediction
    rf_pred_raw = rf_model.predict(input_df)[0]
    rf_prob = rf_model.predict_proba(input_df)[0][1]

    # Normalize RF Output
    if isinstance(rf_pred_raw, str):
        rf_pred = 1 if rf_pred_raw.lower() == "attack" else 0
    else:
        rf_pred = int(rf_pred_raw)

    # Isolation Forest Prediction
    if_pred_raw = if_model.predict(input_df)[0]
    if_flag = 1 if if_pred_raw == -1 else 0

    # Final Hybrid Decision
    final_prediction = 1 if (rf_pred == 1 or if_flag == 1) else 0

    # Risk Score
    risk_score = compute_risk_score(rf_prob, if_flag)

    explanation = explain_prediction(input_df)

    result = {
        "rf_prediction": rf_pred,
        "rf_attack_probability": float(rf_prob),
        "if_anomaly_flag": if_flag,
        "final_prediction": final_prediction,
        "risk_score": round(risk_score, 2),
        "top_features": explanation
    }

    return result

# TESTING BLOCK

if __name__ == "__main__":

    # Example: Load one row from processed dataset
    if DATASET.lower() == "cicids":
        df = pd.read_csv("backend/data/processed/cicids_processed.csv")

    else:
        df = pd.read_csv("backend/data/processed/nsl_kdd_processed.csv")

    # Remove label column automatically
    label_cols = ["Label", "label", "class", "Class"]
    for col in label_cols:
        if col in df.columns:
            df = df.drop(col, axis=1)
            break

    sample = df.sample(1)

    result = predict(sample)

    print("\nHybrid Prediction Result:")
    print(result)