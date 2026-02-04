# Central configuration file for the XAI Intrusion Detection System
import os

#Base directory of the backend folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Data directories
DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DATA_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")

# Dataset files (NSL-KDD)
TRAIN_DATA_FILE = os.path.join(RAW_DATA_DIR, "KDDTrain+.txt")
TEST_DATA_FILE = os.path.join(RAW_DATA_DIR, "KDDTest+.txt")

# Processed dataset output
PROCESSED_DATA_FILE = os.path.join(
    PROCESSED_DATA_DIR, "processed_data.csv"
)

# Model storage
MODEL_DIR = os.path.join(BASE_DIR, "saved_models")
MODEL_FILE = os.path.join(MODEL_DIR, "rf_model.pkl")

# Random seed for reproducibility
RANDOM_STATE = 42