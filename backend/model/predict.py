import joblib
from backend.config import MODEL_PATHS, DATASETS

# Load all models once
models = {}

def load_models():
    global models

    for dataset in DATASETS:
        paths = MODEL_PATHS[dataset]

        rf_model = joblib.load(paths["rf"])
        if_model = joblib.load(paths["if"])

        models[dataset] = {
            "rf": rf_model,
            "if": if_model
        }

    return models


def predict(features):
    results = {}

    for dataset in DATASETS:
        rf_model = models[dataset]["rf"]
        if_model = models[dataset]["if"]

        # Random Forest prediction
        rf_pred = rf_model.predict([features])[0]
        rf_prob = rf_model.predict_proba([features])[0][1]

        # Isolation Forest prediction
        if_pred = if_model.predict([features])[0]

        results[dataset] = {
            "rf_pred": int(rf_pred),
            "rf_prob": float(rf_prob),
            "if_pred": int(if_pred)
        }

    return results