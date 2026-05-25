import pandas as pd
import os

print("🔥 Merging CICIDS dataset...")

# ==============================
# 🔹 PATH
# ==============================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RAW_PATH = os.path.join(BASE_DIR, "data", "raw", "CICIDS")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "processed", "CICIDS", "cicids_full.csv")

# ==============================
# 🔹 LOAD ALL FILES
# ==============================
all_files = [f for f in os.listdir(RAW_PATH) if f.endswith(".csv")]

df_list = []

for file in all_files:
    file_path = os.path.join(RAW_PATH, file)
    print(f"📂 Loading: {file}")

    df = pd.read_csv(file_path)

    df_list.append(df)

# ==============================
# 🔹 MERGE
# ==============================
full_df = pd.concat(df_list, ignore_index=True)

print("✅ Merged shape:", full_df.shape)

# ==============================
# 🔹 SAVE
# ==============================
full_df.to_csv(OUTPUT_PATH, index=False)

print("💾 Saved to:", OUTPUT_PATH)