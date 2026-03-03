import os
import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

from backend.config import DATASET


def get_paths():
    dataset = DATASET.strip().lower()

    if dataset == "cicids":
        data_path = "backend/data/processed/cicids_processed.csv"
        model_path = "backend/saved_models/CICIDS/if_model.pkl"

    elif dataset == "nsl_kdd":
        data_path = "backend/data/processed/nsl_kdd_processed.csv"
        model_path = "backend/saved_models/NSL_KDD/if_model.pkl"

    else:
        raise ValueError(f"Unsupported dataset: '{DATASET}'")

    return data_path, model_path


def load_data(path):
    if not os.path.exists(path):
        raise FileNotFoundError("Processed dataset not found. Run preprocessing first.")

    df = pd.read_csv(path)
    print("Dataset loaded:", df.shape)
    return df


def get_label_column(df):
    """
    Automatically detect label column
    """
    possible_labels = ["Label", "label", "class", "Class"]

    for col in possible_labels:
        if col in df.columns:
            print(f"Using label column: {col}")
            return col

    raise ValueError("No label column found in dataset.")


def train_isolation_forest(df, label_col):
    """
    Train only on normal traffic.
    Automatically detect which label represents normal traffic.
    """

    label_counts = df[label_col].value_counts()

    print("\nLabel distribution:")
    print(label_counts)

    # Assume normal class is majority class
    normal_label = label_counts.idxmax()

    print(f"\nDetected normal label value: {normal_label}")

    df_normal = df[df[label_col] == normal_label]

    X_train = df_normal.drop(label_col, axis=1)

    print(f"Normal samples used for training: {len(X_train)}")

    if len(X_train) == 0:
        raise ValueError("No normal samples found. Check label encoding.")

    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
        n_jobs=-1
    )

    print("Training Isolation Forest on normal traffic only...")
    model.fit(X_train)

    return model


def evaluate_model(model, df, label_col):
    """
    Evaluate model on full dataset (handles string or numeric labels)
    """

    X_full = df.drop(label_col, axis=1)
    y_true_raw = df[label_col]

    # Detect normal label (majority class)
    normal_label = y_true_raw.value_counts().idxmax()

    # Convert true labels to binary
    # normal -> 0
    # attack -> 1
    y_true = y_true_raw.apply(lambda x: 0 if x == normal_label else 1)

    # Model prediction
    y_pred = model.predict(X_full)

    # Convert Isolation Forest output
    # 1  -> normal (0)
    # -1 -> anomaly (1)
    y_pred_binary = [1 if x == -1 else 0 for x in y_pred]

    print("\nIsolation Forest Evaluation:\n")

    print("Confusion Matrix:\n")
    print(confusion_matrix(y_true, y_pred_binary))

    print("\nClassification Report:\n")
    print(classification_report(y_true, y_pred_binary))


def save_model(model, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    print("Model saved to:", path)


def main():
    data_path, model_path = get_paths()

    df = load_data(data_path)

    label_col = get_label_column(df)

    model = train_isolation_forest(df, label_col)

    evaluate_model(model, df, label_col)

    save_model(model, model_path)


if __name__ == "__main__":
    main()