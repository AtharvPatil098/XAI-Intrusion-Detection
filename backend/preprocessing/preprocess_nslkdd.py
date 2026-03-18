import pandas as pd
import os

from backend.config import RAW_DATA_DIR, get_processed_data_path


def load_data():
    # NSL-KDD files (adjust if needed)
    train_path = os.path.join(RAW_DATA_DIR, "NSL_KDD", "KDDTrain+.txt")
    test_path = os.path.join(RAW_DATA_DIR, "NSL_KDD", "KDDTest+.txt")

    # Column names (NSL-KDD has no headers)
    columns = [
        "duration","protocol_type","service","flag","src_bytes","dst_bytes",
        "land","wrong_fragment","urgent","hot","num_failed_logins",
        "logged_in","num_compromised","root_shell","su_attempted","num_root",
        "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
        "is_host_login","is_guest_login","count","srv_count","serror_rate",
        "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
        "diff_srv_rate","srv_diff_host_rate","dst_host_count",
        "dst_host_srv_count","dst_host_same_srv_rate",
        "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate","dst_host_serror_rate",
        "dst_host_srv_serror_rate","dst_host_rerror_rate",
        "dst_host_srv_rerror_rate","label","difficulty"
    ]

    train_df = pd.read_csv(train_path, names=columns)
    test_df = pd.read_csv(test_path, names=columns)

    df = pd.concat([train_df, test_df], ignore_index=True)

    return df


def clean_data(df):
    # Drop unnecessary column
    if "difficulty" in df.columns:
        df = df.drop(columns=["difficulty"])

    # Remove duplicates
    df = df.drop_duplicates()

    # Handle missing values (just in case)
    df = df.fillna(0)

    return df


def encode_categorical(df):
    categorical_cols = ["protocol_type", "service", "flag"]

    df = pd.get_dummies(df, columns=categorical_cols)

    return df


def process_labels(df):
    # Convert attack labels → binary
    df["label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)
    return df


def standardize_columns(df):
    # Lowercase + clean names
    df.columns = [
        col.strip().lower().replace(" ", "_").replace("/", "_per_")
        for col in df.columns
    ]
    return df


def save_data(df):
    output_path = get_processed_data_path("nsl_kdd")
    df.to_csv(output_path, index=False)
    print(f"✅ NSL-KDD processed data saved at: {output_path}")


def main():
    print("🔄 Processing NSL-KDD dataset...")

    df = load_data()
    df = clean_data(df)
    df = encode_categorical(df)
    df = process_labels(df)
    df = standardize_columns(df)

    #save_data(df)

    print("✅ Preprocessing complete!")


if __name__ == "__main__":
    main()