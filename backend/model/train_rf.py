import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

from backend.config import DATASET

def get_paths():
    dataset = DATASET.strip().lower()

    if dataset == "cicids":
        data_path = "backend/data/processed/cicids_processed.csv"
        model_path = "backend/saved_models/CICIDS/rf_model.pkl"

    elif dataset == "nsl_kdd":
        data_path = "backend/data/processed/nsl_kdd_processed.csv"
        model_path = "backend/saved_models/NSL_KDD/rf_model.pkl"

    else:
        raise ValueError(f"Unsupported dataset: '{DATASET}'")

    return data_path, model_path


def load_data(path):
    if not os.path.exists(path):
        raise FileNotFoundError("Processed dataset not found. Run preprocessing first.")

    df = pd.read_csv(path)
    print("Dataset loaded:", df.shape)
    return df


def train_model(df):
    X = df.drop("Label", axis=1)
    y = df["Label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )

    print("Training Random Forest...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("\nAccuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n")
    print(classification_report(y_test, y_pred))

    return model


def save_model(model, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    print("Model saved to:", path)


def main():
    data_path, model_path = get_paths()

    df = load_data(data_path)
    model = train_model(df)
    save_model(model, model_path)


if __name__ == "__main__":
    main()