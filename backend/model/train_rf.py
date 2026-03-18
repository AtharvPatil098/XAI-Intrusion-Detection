import pandas as pd
import os
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

from backend.config import get_datasets, get_processed_data_path, get_model_path, RANDOM_STATE, TEST_SIZE


def train_model(dataset):
    print(f"\n🔄 Training Random Forest for {dataset.upper()}...")

    # Load processed data
    data_path = get_processed_data_path(dataset)
    df = pd.read_csv(data_path)

    # Split features and label
    X = df.drop(columns=["label"])
    y = df["label"]

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE
    )

    # Initialize model
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    # Train
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print(f"✅ Accuracy ({dataset}): {acc:.4f}")
    print(classification_report(y_test, y_pred))

    # Save model
    model_path = get_model_path(dataset, "rf")

    # Ensure directory exists
    os.makedirs(os.path.dirname(model_path), exist_ok=True)

    joblib.dump(model, model_path)

    print(f"💾 Model saved at: {model_path}")


def main():
    print("🚀 Starting Random Forest Training...")

    datasets = get_datasets()

    for dataset in datasets:
        train_model(dataset)

    print("\n✅ All models trained successfully!")


if __name__ == "__main__":
    main()