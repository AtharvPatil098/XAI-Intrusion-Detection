print("🔥 FILE IS RUNNING")
import pandas as pd
import joblib
import json

# -----------------------------
# LOAD MODEL
# -----------------------------
model = joblib.load("../saved_models/CICIDS/xgb_model.pkl")

# -----------------------------
# LOAD FEATURE COLUMNS
# -----------------------------
with open("../artifacts/cicids_feature_columns.json", "r") as f:
    feature_columns = json.load(f)

# -----------------------------
# FUNCTION: PREPARE INPUT
# -----------------------------
def prepare_input(input_dict):
    df = pd.DataFrame([input_dict])

    # Add missing columns
    for col in feature_columns:
        if col not in df.columns:
            df[col] = 0

    # Ensure same column order
    df = df[feature_columns]

    return df

# -----------------------------
# FUNCTION: PREDICT
# -----------------------------
def predict(input_dict):
    df = prepare_input(input_dict)

    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0].max()

    result = {
        "prediction": "Attack" if prediction == 1 else "Normal",
        "confidence": float(probability)
    }

    return result

# -----------------------------
# TEST (RUN FILE DIRECTLY)
# -----------------------------
if __name__ == "__main__":
    print("🚀 Running prediction script...")

    sample_input = {
        "Destination Port": 80,
        "Flow Duration": 1000,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 5,
        "Total Length of Fwd Packets": 500,
        "Total Length of Bwd Packets": 300
    }

    try:
        output = predict(sample_input)
        print("\n🔍 Prediction Result:")
        print(output)
    except Exception as e:
        print("\n❌ Error occurred:")
        print(e)