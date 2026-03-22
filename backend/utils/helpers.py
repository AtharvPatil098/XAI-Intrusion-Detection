# utils/helpers.py
# Shared utility functions used across the project.

import os
import numpy as np
import pandas as pd


def numpy_to_python(obj):
    """Recursively convert numpy types to native Python for JSON serialisation."""
    if isinstance(obj, dict):
        return {k: numpy_to_python(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [numpy_to_python(v) for v in obj]
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


def sample_random_record(dataset: str = "nslkdd") -> dict:
    """Return a random feature dict from the processed dataset (for API testing)."""
    from config import DATA_PROCESSED
    filename = "nsl_kdd_processed.csv" if dataset == "nslkdd" else "cicids_processed.csv"
    df  = pd.read_csv(os.path.join(DATA_PROCESSED, filename))
    row = df.sample(1).iloc[0].to_dict()
    for col in ["binary_label", "attack_category", "label_encoded"]:
        row.pop(col, None)
    return row


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
        "total":              len(results),
        # Flag if ANY model detected an attack/anomaly
        "nslkdd_rf_attacks":  sum(1 for r in results if r.get("nslkdd_rf_prediction") == 1),
        "nslkdd_if_anomalies":sum(1 for r in results if r.get("nslkdd_if_prediction") == 1),
        "cicids_rf_attacks":  sum(1 for r in results if r.get("cicids_rf_prediction") == 1),
        "cicids_if_anomalies":sum(1 for r in results if r.get("cicids_if_prediction") == 1),
        # Combined risk level distribution
        "critical":           sum(1 for r in results if r.get("risk_level") == "Critical"),
        "high":               sum(1 for r in results if r.get("risk_level") == "High"),
        "medium":             sum(1 for r in results if r.get("risk_level") == "Medium"),
        "low":                sum(1 for r in results if r.get("risk_level") == "Low"),
    }