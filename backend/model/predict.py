import joblib
import pandas as pd

from backend.config import get_model_path
from backend.preprocessing.feature_adapter import adapter


class Predictor:
    def __init__(self):
        self.models = {
            "nsl_kdd": {
                "rf": self._load_model("nsl_kdd", "rf"),
                "if": self._load_model("nsl_kdd", "if")
            },
            "cicids": {
                "rf": self._load_model("cicids", "rf"),
                "if": self._load_model("cicids", "if")
            }
        }

    def _load_model(self, dataset, model_type):
        path = get_model_path(dataset, model_type)
        return joblib.load(path)

    def predict(self, input_data, dataset):
        """
        input_data: dict / DataFrame
        dataset: 'nsl_kdd' or 'cicids'
        """

        # Step 1: Adapt features
        X = adapter.transform(input_data, dataset)

        # Step 2: RF Prediction
        rf_model = self.models[dataset]["rf"]
        rf_pred = rf_model.predict(X)[0]
        rf_prob = rf_model.predict_proba(X)[0][1]  # probability of attack

        # Step 3: IF Prediction
        if_model = self.models[dataset]["if"]
        if_pred = if_model.predict(X)[0]  # 1 or -1
        if_score = if_model.decision_function(X)[0]

        # Convert IF output
        anomaly = 1 if if_pred == -1 else 0

        # Final result
        result = {
            "prediction": int(rf_pred),        # 0 normal, 1 attack
            "attack_probability": float(rf_prob),
            "anomaly": anomaly,               # 1 anomaly, 0 normal
            "anomaly_score": float(if_score)
        }

        return result


# Singleton instance
predictor = Predictor()