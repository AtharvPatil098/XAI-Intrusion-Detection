import os

# BASE PATHS
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DATA_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")

MODEL_DIR = os.path.join(BASE_DIR, "saved_models")


# DATASET CONFIG
# Options: "nsl_kdd", "cicids", "all"
DATASET = "all"


# PROCESSED DATA PATHS
PROCESSED_PATHS = {
    "nsl_kdd": os.path.join(PROCESSED_DATA_DIR, "nsl_kdd_processed.csv"),
    "cicids": os.path.join(PROCESSED_DATA_DIR, "cicids_processed.csv")
}



# MODEL PATHS
MODEL_PATHS = {
    "nsl_kdd": {
        "rf": os.path.join(MODEL_DIR, "NSL_KDD", "rf_model.pkl"),
        "if": os.path.join(MODEL_DIR, "NSL_KDD", "if_model.pkl"),
    },
    "cicids": {
        "rf": os.path.join(MODEL_DIR, "CICIDS", "rf_model.pkl"),
        "if": os.path.join(MODEL_DIR, "CICIDS", "if_model.pkl"),
    }
}



# GENERAL SETTINGS
RANDOM_STATE = 42
TEST_SIZE = 0.2


# HELPER FUNCTIONS
def get_datasets():
    """
    Returns list of datasets to use
    """
    if DATASET == "all":
        return ["nsl_kdd", "cicids"]
    return [DATASET]


def get_model_path(dataset, model_type):
    """
    dataset: 'nsl_kdd' or 'cicids'
    model_type: 'rf' or 'if'
    """
    return MODEL_PATHS[dataset][model_type]


def get_processed_data_path(dataset):
    """
    Returns processed CSV path
    """
    return PROCESSED_PATHS[dataset]