import shap
import joblib
import numpy as np

from backend.config import get_model_path
from backend.preprocessing.feature_adapter import adapter


class SHAPExplainer:
    def __init__(self):
        self.models = {
            "nsl_kdd": self._load_model("nsl_kdd"),
            "cicids": self._load_model("cicids")
        }

        self.explainers = {
            dataset: shap.TreeExplainer(model)
            for dataset, model in self.models.items()
        }

    def _load_model(self, dataset):
        path = get_model_path(dataset, "rf")
        return joblib.load(path)

    def explain(self, input_data, dataset):
        """
        Returns SHAP feature contributions
        """

        # Step 1: Adapt input
        X = adapter.transform(input_data, dataset)

        # Step 2: Get explainer
        explainer = self.explainers[dataset]

        # Step 3: Compute SHAP values
        shap_values = explainer.shap_values(X)

        # For binary classification → take class 1 (attack)
        
        # Handle different SHAP output formats
        if isinstance(shap_values, list):
            shap_values = shap_values[1]  # class 1 (attack)

        shap_values = np.array(shap_values)

        # Ensure correct shape → (1, num_features)
        if len(shap_values.shape) == 3:
            shap_values = shap_values[0]

        # Step 4: Map feature → importance
        feature_names = X.columns

        

        contributions = {}

        for feature, value in zip(feature_names, shap_values[0]):
            value = np.array(value)

            # Flatten and take first element safely
            scalar_value = float(value.flatten()[0])

            contributions[feature] = scalar_value

        return contributions


# Singleton instance
shap_explainer = SHAPExplainer()