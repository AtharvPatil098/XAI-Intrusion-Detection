import shap
import numpy as np
from backend.model.predict import models

# Store SHAP explainers
explainers = {}

def load_explainers():
    global explainers

    for dataset, model_dict in models.items():
        rf_model = model_dict["rf"]

        explainer = shap.TreeExplainer(rf_model)
        explainers[dataset] = explainer


def explain(features):
    explanations = {}

    features_array = np.array(features).reshape(1, -1)

    for dataset, explainer in explainers.items():
        shap_values = explainer.shap_values(features_array)

        # For classification → take class 1 (attack)
        if isinstance(shap_values, list):
            shap_vals = shap_values[1][0]
        else:
            shap_vals = shap_values[0]

        # Get top 3 important features
        top_indices = np.argsort(np.abs(shap_vals))[-3:][::-1]

        explanations[dataset] = [
            {
                "feature_index": int(idx),
                "impact": float(shap_vals[idx])
            }
            for idx in top_indices
        ]

    return explanations