# Handles data loading, cleaning, encoding, and normalization
import pandas as pd
import numpy as np
import os

from sklearn.preprocessing import LabelEncoder, StandardScaler

from backend.config import(
    TRAIN_DATA_FILE,
    TEST_DATA_FILE,
    PROCESSED_DATA_DIR,
    PROCESSED_DATA_FILE
)

# NSL-KDD feature names
columns = [
    "duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot",
    "num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count",
    "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label","difficulty"
]

# Load train and test data
train_df = pd.read_csv(TRAIN_DATA_FILE, names=columns)
test_df = pd.read_csv(TEST_DATA_FILE, names=columns)

# Combine datasets
df = pd.concat([train_df, test_df], axis=0)
df.reset_index(drop=True, inplace=True)

# Drop difficulty column
df.drop("difficulty", axis=1, inplace=True)

# Convert labels to binary
df["label"] = df["label"].apply(
    lambda x: "normal" if x == "normal" else "attack"
)

# Encode categorical columns
categorical_cols = ["protocol_type", "service", "flag"]

encoder = LabelEncoder()
for col in categorical_cols:
    df[col] = encoder.fit_transform(df[col])

# Seperate features and labels
X = df.drop("label", axis=1)
y = df["label"]

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Create processed directory if it doesn't exists
os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)

# Save processed dataset
processed_df = pd.DataFrame(X_scaled, columns=X.columns)
processed_df["label"] = y.values

processed_df.to_csv(PROCESSED_DATA_FILE, index=False)

print("Processing completed successfully!")
print(f"Saved to: ", {PROCESSED_DATA_FILE})