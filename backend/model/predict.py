import pandas as pd
import joblib
import json
import numpy as np

print("🔥 XAI-IDS Predict System Starting...")

from config import (
    XGB_MODEL_PATH,
    IF_MODEL_PATH,
    FEATURE_COLUMNS_PATH,
    CICIDS_DATA,
    MULTI_CLASS_MODEL_PATH,
    LABEL_ENCODER_PATH,
    SCALER_PATH,
    calculate_risk_score,
    ATTACK_THRESHOLD,
    ANOMALY_LABEL
)

from explainability.shap_explainer import create_explainer
from explainability.explanation_engine import ExplanationEngine


# ==============================
# 🔹 LOAD FILES
# ==============================
def load_files():

    model = joblib.load(XGB_MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    if_model = joblib.load(IF_MODEL_PATH)

    with open(FEATURE_COLUMNS_PATH, "r") as f:
        feature_cols = json.load(f)

    multi_model = joblib.load(MULTI_CLASS_MODEL_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)

    # 🔥 SHAP background
    try:
        background = pd.read_csv(CICIDS_DATA)
        background.columns = background.columns.str.strip()
        background = background[feature_cols]
        background = background.sample(min(100, len(background)), random_state=42)
    except:
        background = pd.DataFrame(
            np.zeros((100, len(feature_cols))),
            columns=feature_cols
        )

    explainer = create_explainer(model, background)
    engine = ExplanationEngine(explainer, feature_cols)

    return model, if_model, feature_cols, engine, multi_model, label_encoder, scaler


# ==============================
# 🔹 PREDICT FUNCTION
# ==============================
def predict(
    sample_dict,
    model,
    if_model,
    feature_cols,
    engine,
    multi_model,
    label_encoder,
    scaler,
    is_raw_input=False
):

    # --------------------------
    # INPUT
    # --------------------------
    if is_raw_input:
        from preprocessing.feature_adapter import adapt_raw_input
        df = adapt_raw_input(sample_dict)
    else:
        df = pd.DataFrame([sample_dict])

        for col in feature_cols:
            if col not in df.columns:
                df[col] = 0

        df = df[feature_cols]

    # --------------------------
    # SCALE
    # --------------------------
    df_scaled = scaler.transform(df)

    # --------------------------
    # 🔹 BINARY MODEL
    # --------------------------
    probs = model.predict_proba(df_scaled)[0]
    attack_prob = float(probs[1])
    normal_prob = float(probs[0])

    label = "Attack" if attack_prob > ATTACK_THRESHOLD else "Normal"

    # --------------------------
    # 🔹 ANOMALY (USE SCALED ❗)
    # --------------------------
    anomaly_pred = int(if_model.predict(df_scaled)[0])
    anomaly_score = float(if_model.decision_function(df_scaled)[0])

    is_anomaly = anomaly_pred == ANOMALY_LABEL

    # --------------------------
    # 🔥 FINAL LABEL FIX
    # --------------------------
    if label == "Normal" and is_anomaly:
        final_label = "Unknown Attack"
    else:
        final_label = label

    # --------------------------
    # 🔥 MULTI-CLASS FIX
    # --------------------------
    if final_label == "Attack":

        attack_class = multi_model.predict(df_scaled)[0]
        attack_type = label_encoder.inverse_transform([attack_class])[0]

        # ❌ CRITICAL FIX: NEVER allow BENIGN here
        if attack_type == "BENIGN":
            attack_type = "Unknown Attack"

    else:
        attack_type = "Normal"

    # --------------------------
    # 🔹 RISK
    # --------------------------
    risk_score = calculate_risk_score(
        attack_prob,
        anomaly_score,
        is_anomaly
    )

    # --------------------------
    # 🔥 SHAP FIX (USE SAME INPUT AS MODEL)
    # --------------------------
    explanation = engine.generate(pd.DataFrame(df_scaled, columns=feature_cols))

    print(f"🚨 {final_label} | Type: {attack_type} | Risk: {risk_score}")

    return {
        "prediction": final_label,
        "attack_type": attack_type,
        "confidence": float(attack_prob if label == "Attack" else normal_prob),
        "attack_probability": attack_prob,
        "risk_score": risk_score,
        "is_anomaly": bool(is_anomaly),
        "anomaly_score": anomaly_score,
        "explanation": explanation
    }