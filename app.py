from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict

from backend.model.predict import predictor
from backend.explainability.explanation_engine import explanation_engine

app = FastAPI(title="XAI Intrusion Detection System")

# Request Schema
class InputData(BaseModel):
    data: Dict
    dataset: str  # "nsl_kdd" or "cicids"

# Health Check
@app.get("/")
def home():
    return {"message": "XAI IDS is running 🚀"}


# Prediction Endpoint
@app.post("/predict")
def predict(input_data: InputData):

    data = input_data.data
    dataset = input_data.dataset.lower()

    # Step 1: Prediction
    prediction = predictor.predict(data, dataset)

    # Step 2: Explanation
    explanation = explanation_engine.explain(
        data,
        dataset,
        prediction
    )

    return {
        "prediction": prediction,
        "explanation": explanation
    }