# utils/helpers.py
# Shared utility functions used across the project.

import os
import numpy as np
import pandas as pd


def numpy_to_python(obj):
    """
    Recursively convert numpy types → native Python for JSON serialisation.
    Handles: np.integer, np.floating, np.bool_, np.ndarray, and nested
    dicts/lists. This must be called on every response that touches model
    output to prevent 'only length-1 arrays can be converted' errors.
    """
    if isinstance(obj, dict):
        return {k: numpy_to_python(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [numpy_to_python(v) for v in obj]
    if isinstance(obj, np.bool_):
        return bool(obj)
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


def sample_random_record(dataset: str = "nslkdd") -> dict:
    """
    Return a random feature dict from the processed dataset.
    Values are explicitly cast to native Python types so they are safe
    to pass into the feature adapter and JSON serialiser.
    """
    from config import DATA_PROCESSED
    filename = "nsl_kdd_processed.csv" if dataset == "nslkdd" else "cicids_processed.csv"
    df  = pd.read_csv(os.path.join(DATA_PROCESSED, filename))
    row = df.sample(1).iloc[0].to_dict()

    # Strip label columns
    for col in ["binary_label", "attack_category", "label_encoded"]:
        row.pop(col, None)

    # Convert all values to native Python types — pandas to_dict() can
    # return np.int64 / np.float64 which cause downstream type errors
    return numpy_to_python(row)


def summarise_results(results: list) -> dict:
    """Summarise a list of single-dataset prediction results."""
    return {
        "total":        len(results),
        "attacks_rf":   sum(1 for r in results if r.get("rf_prediction") == 1),
        "anomalies_if": sum(1 for r in results if r.get("if_prediction") == 1),
        "critical":     sum(1 for r in results if r.get("risk_level") == "Critical"),
        "high":         sum(1 for r in results if r.get("risk_level") == "High"),
        "medium":       sum(1 for r in results if r.get("risk_level") == "Medium"),
        "low":          sum(1 for r in results if r.get("risk_level") == "Low"),
    }


def summarise_dual_results(results: list) -> dict:
    """Summarise a list of dual-mode prediction results (all 4 model signals)."""
    return {
        "total":               len(results),
        "nslkdd_rf_attacks":   sum(1 for r in results if r.get("nslkdd_rf_prediction") == 1),
        "nslkdd_if_anomalies": sum(1 for r in results if r.get("nslkdd_if_prediction") == 1),
        "cicids_rf_attacks":   sum(1 for r in results if r.get("cicids_rf_prediction")  == 1),
        "cicids_if_anomalies": sum(1 for r in results if r.get("cicids_if_prediction")  == 1),
        "critical":            sum(1 for r in results if r.get("risk_level") == "Critical"),
        "high":                sum(1 for r in results if r.get("risk_level") == "High"),
        "medium":              sum(1 for r in results if r.get("risk_level") == "Medium"),
        "low":                 sum(1 for r in results if r.get("risk_level") == "Low"),
    }