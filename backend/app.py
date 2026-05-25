from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
import sys
import pandas as pd

# ==============================
# 🔹 FIX PATH
# ==============================
CURRENT_DIR = os.path.dirname(__file__)
sys.path.append(CURRENT_DIR)

# ==============================
# 🔹 IMPORTS
# ==============================
from model.predict import load_files, predict
from config import API_HOST, API_PORT, CICIDS_DATA

# ==============================
# 🔹 INIT APP
# ==============================
app = FastAPI(title="XAI-IDS API", version="1.0")

# ==============================
# 🔹 CORS
# ==============================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================
# 🔹 GLOBAL VARIABLES
# ==============================
model = None
if_model = None
feature_cols = None
engine = None
multi_model = None
label_encoder = None
scaler = None
data_df = None

# ==============================
# 🔹 LOAD EVERYTHING
# ==============================
@app.on_event("startup")
def load_model_once():
    global model, if_model, feature_cols, engine, multi_model, label_encoder, scaler, data_df

    print("🚀 Loading models + dataset...")

    # --------------------------
    # 🔹 LOAD MODELS
    # --------------------------
    model, if_model, feature_cols, engine, multi_model, label_encoder, scaler = load_files()

    # --------------------------
    # 🔹 LOAD DATASET (FIXED 🔥)
    # --------------------------
    try:
        print("📂 Loading dataset...")

        data_df = pd.read_csv(CICIDS_DATA)

        # clean column names
        data_df.columns = data_df.columns.str.strip()

        # 🔥 REMOVE LABEL COLUMN (VERY IMPORTANT)
        if "Label" in data_df.columns:
            data_df = data_df.drop(columns=["Label"])

        # align features
        data_df = data_df[feature_cols]

        print(f"✅ Dataset loaded: {data_df.shape}")

    except Exception as e:
        print("❌ DATASET LOAD FAILED:", e)
        data_df = None

    print("✅ System ready")

# ==============================
# 🔹 INPUT SCHEMA
# ==============================
class TrafficInput(BaseModel):
    packets: float
    bytes: float
    duration: float
    port: int

# ==============================
# 🔹 HEALTH CHECK
# ==============================
@app.get("/")
def home():
    return {"message": "🚀 XAI-IDS API running"}

# ==============================
# 🔹 REAL DATA PREDICTION
# ==============================
@app.get("/predict_sample")
def predict_sample():

    if data_df is None:
        return {"error": "Dataset not loaded"}

    sample = data_df.sample(1)
    sample_dict = sample.to_dict(orient="records")[0]

    result = predict(
        sample_dict,
        model,
        if_model,
        feature_cols,
        engine,
        multi_model,
        label_encoder,
        scaler,
        is_raw_input=False
    )

    return result

# ==============================
# 🔹 MANUAL INPUT
# ==============================
@app.post("/predict")
def predict_api(data: TrafficInput):

    try:
        input_dict = data.dict()

        result = predict(
            input_dict,
            model,
            if_model,
            feature_cols,
            engine,
            multi_model,
            label_encoder,
            scaler,
            is_raw_input=True
        )

        return result

    except Exception as e:
        print("❌ ERROR:", e)
        return {"error": str(e)}

# ==============================
# 🔹 RUN
# ==============================
if __name__ == "__main__":
    uvicorn.run("app:app", host=API_HOST, port=API_PORT, reload=True)