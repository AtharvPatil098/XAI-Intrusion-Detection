import pandas as pd
import json
from sklearn.model_selection import train_test_split

# Step 1: Define column names
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins',
    'logged_in','num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'label','difficulty'
]

# Step 2: Load dataset
train_path = "../data/raw/NSL_KDD/KDDTrain+.txt"
df = pd.read_csv(train_path, names=columns)

# Step 3: Basic checks
print("✅ Dataset shape:", df.shape)

print("\n🔹 First 5 rows:")
print(df.head())

print("\n🔹 Dataset Info:")
print(df.info())

print("\n🔹 Label distribution (original):")
print(df['label'].value_counts())

# ==============================
# 🚀 STEP 2: DATA CLEANING FLOW
# ==============================

# ✅ 1. Drop column
df = df.drop(columns=['difficulty'])

# ✅ 2. Convert label (binary classification)
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

# ✅ 3. One-hot encoding
categorical_cols = ['protocol_type', 'service', 'flag']
df = pd.get_dummies(df, columns=categorical_cols)

# ✅ 4. Split features & target
X = df.drop('label', axis=1)
y = df['label']

# ✅ 5. Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ✅ 6. Save feature columns
feature_columns = X.columns.tolist()

with open("../artifacts/feature_columns.json", "w") as f:
    json.dump(feature_columns, f)

# ✅ 7. Save processed data
X_train.to_csv("../data/processed/X_train.csv", index=False)
X_test.to_csv("../data/processed/X_test.csv", index=False)
y_train.to_csv("../data/processed/y_train.csv", index=False)
y_test.to_csv("../data/processed/y_test.csv", index=False)

# ✅ 8. Print shapes
print("\n✅ Final Shapes:")
print("X_train:", X_train.shape)
print("X_test:", X_test.shape)