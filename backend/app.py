from backend.model.predict import load_models, predict
from backend.model.risk_score import calculate_risk
from backend.explainability.shap_explainer import load_explainers, explain

# INIT
load_models()
load_explainers()


def run_ids(features):
    predictions = predict(features)
    risk_result = calculate_risk(predictions)
    explanations = explain(features)

    return {
        "predictions": predictions,
        "risk": risk_result,
        "explanations": explanations
    }


# SIMPLE OUTPUT FORMAT
def print_output(result):
    risk = result["risk"]

    print("\n===== IDS ALERT =====")
    print(f"Risk Score: {risk['risk_score']}")
    print(f"Status: {risk['status']}")

    if risk["zero_day"]:
        print("⚠️ Possible Zero-Day Attack Detected")

    print("=====================\n")


# TEST
if __name__ == "__main__":
    # Dummy input (replace later with real features)
    sample_features = [0] * 41

    result = run_ids(sample_features)
    print_output(result)