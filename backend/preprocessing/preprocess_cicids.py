import pandas as pd
import os
import numpy as np

from backend.config import RAW_DATA_DIR, get_processed_data_path


def load_data():
    cicids_path = os.path.join(RAW_DATA_DIR, "CICIDS")

    # Load all CSV files inside CICIDS folder
    files = [f for f in os.listdir(cicids_path) if f.endswith(".csv")]

    df_list = []
    for file in files:
        file_path = os.path.join(cicids_path, file)
        print(f"Loading {file}...")
        temp_df = pd.read_csv(file_path)
        df_list.append(temp_df)

    df = pd.concat(df_list, ignore_index=True)

    return df


def clean_data(df):
    # Remove duplicates
    df = df.drop_duplicates()

    # Replace infinities with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Fill NaN with 0
    df.fillna(0, inplace=True)

    return df


def standardize_columns(df):
    df.columns = [
        col.strip().lower()
        .replace(" ", "_")
        .replace("/", "_per_")
        .replace("-", "_")
        for col in df.columns
    ]
    return df


def process_labels(df):
    # Label column usually named 'label'
    df["label"] = df["label"].apply(
        lambda x: 0 if str(x).lower() == "benign" else 1
    )
    return df


def convert_to_numeric(df):
    # Convert all columns except label to numeric
    for col in df.columns:
        if col != "label":
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Replace NaN again if conversion caused any
    df.fillna(0, inplace=True)

    return df


def save_data(df):
    output_path = get_processed_data_path("cicids")
    df.to_csv(output_path, index=False)
    print(f"✅ CICIDS processed data saved at: {output_path}")


def main():
    print("🔄 Processing CICIDS dataset...")

    df = load_data()
    df = clean_data(df)
    df = standardize_columns(df)
    df = process_labels(df)
    df = convert_to_numeric(df)

    save_data(df)

    print("✅ Preprocessing complete!")


if __name__ == "__main__":
    main()