import pandas as pd
import numpy as np
import os
import glob
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

print("🚀 Starting CICIDS preprocessing...")

# -----------------------------
# STEP 1: LOAD DATA
# -----------------------------
data_path = "../data/raw/CICIDS/"
all_files = glob.glob(os.path.join(data_path, "*.csv"))

df_list = []
for file in all_files:
    print(f"Loading: {file}")
    temp_df = pd.read_csv(file)
    df_list.append(temp_df)

df = pd.concat(df_list, ignore_index=True)
print("✅ Combined shape:", df.shape)

# -----------------------------
# STEP 2: CLEAN COLUMNS
# -----------------------------
df.columns = df.columns.str.strip()

# -----------------------------
# STEP 3: DROP USELESS
# -----------------------------
drop_cols = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
df = df.drop(columns=[c for c in drop_cols if c in df.columns])

# -----------------------------
# STEP 4: HANDLE INF / NaN
# -----------------------------
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# -----------------------------
# 🚨 STEP 5: MULTICLASS LABEL (FIX)
# -----------------------------
y = df['Label']   # KEEP ORIGINAL LABELS

# Encode labels
le = LabelEncoder()
y = le.fit_transform(y)

# Save label classes
os.makedirs("../artifacts", exist_ok=True)
with open("../artifacts/label_classes.json", "w") as f:
    json.dump(list(le.classes_), f)

# -----------------------------
# STEP 6: FEATURES
# -----------------------------
X = df.drop(columns=['Label'])

# -----------------------------
# 🔥 STEP 7: DROP DOMINATING FEATURES
# -----------------------------
drop_strong = [
    'Destination Port',
    'Flow Bytes/s',
    'Flow Packets/s'
]

X = X.drop(columns=[c for c in drop_strong if c in X.columns])

# -----------------------------
# STEP 8: SHUFFLE
# -----------------------------
df_shuffled = X.copy()
df_shuffled['target'] = y
df_shuffled = df_shuffled.sample(frac=1, random_state=42)

X = df_shuffled.drop('target', axis=1)
y = df_shuffled['target']

# -----------------------------
# STEP 9: SPLIT
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("✅ Split Done")

# -----------------------------
# STEP 10: SAVE
# -----------------------------
X_train.to_csv("../data/processed/cicids_X_train.csv", index=False)
X_test.to_csv("../data/processed/cicids_X_test.csv", index=False)
y_train.to_csv("../data/processed/cicids_y_train.csv", index=False)
y_test.to_csv("../data/processed/cicids_y_test.csv", index=False)

print("✅ Preprocessing Done!")  