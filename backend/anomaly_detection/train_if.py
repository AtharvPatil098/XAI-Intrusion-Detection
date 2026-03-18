import pandas as pd
import os
import joblib

from sklearn.ensemble import IsolationForest

from backend.config import get_datasets, get_processed_data_path, get_model_path, RANDOM_STATE


def train_model(dataset):
    print(f"\n🔄 Training Isolation Forest for {dataset.upper()}...")

    # Load processed data
    data_path = get_processed_data_path(dataset)
    df = pd.read_csv(data_path)

    # Use only features (ignore label)
    X = df.drop(columns=["label"])

    # Initialize model
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,  # assumes ~10% anomalies
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    # Train model
    model.fit(X)

    # Save model
    model_path = get_model_path(dataset, "if")

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)

    print(f"💾 Model saved at: {model_path}")


def main():
    print("🚀 Starting Isolation Forest Training...")

    datasets = get_datasets()

    for dataset in datasets:
        train_model(dataset)

    print("\n✅ All Isolation Forest models trained successfully!")


if __name__ == "__main__":
    main()