import time
import pandas as pd

from backend.model.predict import predictor
from backend.model.risk_score import calculate_risk_score, get_risk_level
from backend.explainability.explanation_engine import explanation_engine


class RealtimeDetector:
    def __init__(self, dataset="nsl_kdd"):
        self.dataset = dataset

    def process_row(self, row):
        """
        Process single data row
        """

        input_data = row.to_dict()

        # Step 1: Prediction
        prediction = predictor.predict(input_data, self.dataset)

        # Step 2: Risk score
        risk_score = calculate_risk_score(prediction)
        risk_level = get_risk_level(risk_score)

        # Step 3: Explanation
        explanation = explanation_engine.explain(
            input_data,
            self.dataset,
            prediction
        )

        # Step 4: Output
        print("\n==============================")
        print(f"Prediction: {'ATTACK' if prediction['prediction'] else 'NORMAL'}")
        print(f"Attack Probability: {prediction['attack_probability']:.4f}")
        print(f"Anomaly: {prediction['anomaly']}")
        print(f"Risk Score: {risk_score} ({risk_level})")
        print(f"Reason: {', '.join(explanation['reason'])}")
        print("==============================")

    def run_from_csv(self, file_path, delay=1, max_rows=10):
        """
        Simulate real-time detection using CSV
        """

        print(f"🚀 Starting real-time detection on {file_path}...\n")

        df = pd.read_csv(file_path)

        # Drop label if exists
        if "label" in df.columns:
            df = df.drop(columns=["label"])

        for i, row in df.iterrows():
            if i >= max_rows:
                break

            self.process_row(row)

            time.sleep(delay)


# Example usage
if __name__ == "__main__":
    detector = RealtimeDetector(dataset="nsl_kdd")

    detector.run_from_csv(
        "backend/data/processed/nsl_kdd_processed.csv",
        delay=1,
        max_rows=5
    )