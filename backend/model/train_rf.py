import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

from backend.config import DATASET


# PATH HANDLING
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


# LOAD DATA
def load_data(path):
    if not os.path.exists(path):
        raise FileNotFoundError("Processed dataset not found. Run preprocessing first.")

    df = pd.read_csv(path)
    print("Dataset loaded:", df.shape)
    return df


# AUTO DETECT LABEL COLUMN
def detect_label_column(df):
    possible_labels = ["Label", "label", "class", "Class"]

    for col in possible_labels:
        if col in df.columns:
            print(f"Using label column: {col}")
            return col

    raise ValueError("No label column found in dataset.")


# ENCODE LABELS TO 0 / 1
def encode_labels(df, label_col):

    # If already numeric → do nothing
    if df[label_col].dtype != "object":
        print("Labels already numeric.")
        return df

    print("Encoding string labels to numeric (normal=0, attack=1)...")

    df[label_col] = df[label_col].apply(
        lambda x: 0 if str(x).lower() == "normal" else 1
    )

    return df


# TRAIN MODEL
def train_model(df):

    label_col = detect_label_column(df)
    df = encode_labels(df, label_col)

    X = df.drop(label_col, axis=1)
    y = df[label_col]

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

# SAVE MODEL
def save_model(model, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    print("Model saved to:", path)


# MAIN
def main():
    data_path, model_path = get_paths()

    df = load_data(data_path)
    model = train_model(df)
    save_model(model, model_path)


if __name__ == "__main__":
    main()