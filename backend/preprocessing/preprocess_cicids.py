import os
import glob
import pandas as pd
import numpy as np

from backend.config import RAW_DATA_DIR, PROCESSED_DATA_PATH, FEATURE_COLUMNS


def load_and_merge_csv():
    """
    Load all CICIDS CSV files and merge into one dataframe.
    """
    all_files = glob.glob(os.path.join(RAW_DATA_DIR, "*.csv"))

    if not all_files:
        raise FileNotFoundError("No CSV files found in RAW_DATA_DIR")

    df_list = []

    for file in all_files:
        print(f"Loading: {file}")
        df = pd.read_csv(file, low_memory=False)
        df_list.append(df)

    merged_df = pd.concat(df_list, ignore_index=True)
    print("All files merged successfully.")
    print("Shape after merge:", merged_df.shape)

    return merged_df


def clean_data(df):
    """
    Clean CICIDS dataset:
    - Strip column names
    - Remove infinite values
    - Fill missing values
    """

    print("Cleaning data...")

    # Remove extra spaces in column names
    df.columns = df.columns.str.strip()

    # Replace infinite values with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Fill NaN with 0
    df.fillna(0, inplace=True)

    print("Data cleaning completed.")
    return df


def encode_labels(df):
    """
    Convert Label column to binary:
    BENIGN → 0
    Attack → 1
    """

    if "Label" not in df.columns:
        raise ValueError("Label column not found in dataset")

    df["Label"] = df["Label"].apply(
        lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
    )

    print("Label encoding completed.")
    return df


def select_features(df):
    """
    Select only required feature columns + Label
    """

    missing_features = [col for col in FEATURE_COLUMNS if col not in df.columns]

    if missing_features:
        print("Warning: Missing features:", missing_features)

    selected_columns = FEATURE_COLUMNS + ["Label"]

    df = df[selected_columns]

    print("Feature selection completed.")
    print("Final shape:", df.shape)

    return df


def save_processed_data(df):
    """
    Save cleaned dataset to processed folder
    """

    os.makedirs(os.path.dirname(PROCESSED_DATA_PATH), exist_ok=True)
    df.to_csv(PROCESSED_DATA_PATH, index=False)

    print(f"Processed dataset saved to: {PROCESSED_DATA_PATH}")


def main():
    df = load_and_merge_csv()
    df = clean_data(df)
    df = encode_labels(df)
    df = select_features(df)
    save_processed_data(df)


if __name__ == "__main__":
    main()