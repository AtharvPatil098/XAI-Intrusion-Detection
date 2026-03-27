# realtime_detection/realtime_detector.py
# Processes network flow records through RF + IF models in real time.
# Supports single-dataset mode and dual mode (all 4 models simultaneously).

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import csv
import time

from model.predict import Predictor, DualPredictor
from model.risk_score import compute_risk_score, compute_dual_risk_score
from preprocessing.feature_adapter import infer_attack_type_v2 

def is_header_line(line: str) -> bool:
    """Return True if the line looks like a CSV header (first token is non-numeric)."""
    first_token = line.strip().split(",")[0].strip()
    try:
        float(first_token)
        return False
    except ValueError:
        return True


# ── Single dataset detector ───────────────────────────────────────────────────

class RealtimeDetector:
    """
    Processes flow records through one dataset's RF + IF models.

    Usage:
        detector = RealtimeDetector("nslkdd")
        result   = detector.process_row({"duration": 0, "flag": "S0", ...})
    """

    def __init__(self, dataset: str = "nslkdd"):
        self.dataset   = dataset
        self.predictor = Predictor(dataset)
        self.results   = []

    def process_row(self, row_dict: dict) -> dict:
        pred           = self.predictor.predict(row_dict)
        rf_prob_attack = pred["rf_probability"][1] if pred["rf_probability"] else 0.5
        anomaly_score  = pred["anomaly_score"]     if pred["anomaly_score"] is not None else -0.3
        risk           = compute_risk_score(rf_prob_attack, anomaly_score)
        return {**pred, **risk}

    def process_csv_file(self, filepath: str, max_rows: int = 100) -> list:
        """Read a CSV (with header) and process up to max_rows records."""
        results = []
        with open(filepath, "r") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break
                results.append(self.process_row(row))
        return results

    def process_raw_line(self, line: str, columns: list) -> dict:
        row_dict = dict(zip(columns, line.strip().split(",")))
        return self.process_row(row_dict)

    def monitor_log(self, log_path: str, interval: float = 1.0):
        """Tail a log file and run inference on each new line."""
        if self.dataset == "nslkdd":
            from config import NSL_KDD_COLUMNS
            columns = [c for c in NSL_KDD_COLUMNS if c not in ["label", "difficulty"]]
        else:
            from preprocessing.preprocess_cicids import CICIDS_FEATURES
            columns = CICIDS_FEATURES

        print(f"[RealtimeDetector] Monitoring {log_path} ({self.dataset})...")
        with open(log_path, "r") as f:
            first_line = f.readline()
            if first_line and not is_header_line(first_line):
                result = self.process_raw_line(first_line, columns)
                self._print_result(result)
                self.results.append(result)
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line and line.strip():
                    result = self.process_raw_line(line, columns)
                    self._print_result(result)
                    self.results.append(result)
                else:
                    time.sleep(interval)

    def _print_result(self, result: dict):
        level = result.get("risk_level", "?")
        score = result.get("risk_score", 0)
        rf    = result.get("rf_prediction", "?")
        ifo   = result.get("if_prediction", "?")
        print(f"  [{level:8s}] Risk: {score:5.1f}  RF: {rf}  IF: {ifo}")


# ── Dual mode detector — all 4 models simultaneously ─────────────────────────

class DualRealtimeDetector:
    """
    Processes flow records through all 4 models simultaneously.
    This is the detector used by flow_extractor.py for live VM traffic.

    The input dict is a unified superset of both feature spaces.
    Each model silently ignores fields it doesn't recognise.

    Usage:
        detector = DualRealtimeDetector()
        result   = detector.process_row({
            "duration": 0, "protocol_type": "tcp",   # NSL-KDD fields
            "Destination Port": 80, "SYN Flag Count": 1,  # CICIDS fields
            ...
        })
    """

    def __init__(self):
        self.predictor = DualPredictor()
        self.results   = []

    def process_row(self, row_dict: dict) -> dict:
        pred = self.predictor.predict(row_dict)

        # Extract signals with safe fallbacks
        nslkdd_rf_prob  = pred["nslkdd_rf_probability"][1] if pred["nslkdd_rf_probability"] else 0.5
        nslkdd_anom     = pred["nslkdd_anomaly_score"]     if pred["nslkdd_anomaly_score"] is not None else -0.3
        cicids_rf_prob  = pred["cicids_rf_probability"][1]  if pred["cicids_rf_probability"]  else 0.5
        cicids_anom     = pred["cicids_anomaly_score"]      if pred["cicids_anomaly_score"]  is not None else -0.3

        risk = compute_dual_risk_score(
            nslkdd_rf_prob, nslkdd_anom,
            cicids_rf_prob, cicids_anom
        )

        # 🔥 ADD THIS BLOCK
        features = row_dict  # original features

        count = float(features.get("count", 0))
        srv_count = float(features.get("srv_count", 0))
        src_bytes = float(features.get("src_bytes", 0))
        dst_bytes = float(features.get("dst_bytes", 0))

        rf_attack = (
            pred["nslkdd_rf_prediction"] == 1 or
            pred["cicids_rf_prediction"] == 1
        )

        if_anomaly = (
            pred["nslkdd_if_prediction"] == -1 or
            pred["cicids_if_prediction"] == -1
        )

        attack_type = infer_attack_type_v2(
            row_dict,
            rf_attack,
            if_anomaly
        )

        # ✅ FINAL RETURN
        return {
            **pred,
            **risk,
            "attack_type": attack_type
        }

    def process_csv_file(self, filepath: str, max_rows: int = 100) -> list:
        """Read a CSV (with header) and process up to max_rows records."""
        results = []
        with open(filepath, "r") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break
                results.append(self.process_row(dict(row)))
        return results

    def _print_result(self, result: dict):
        level    = result.get("risk_level", "?")
        score    = result.get("risk_score", 0)
        nslkdd_r = result.get("nslkdd_rf_prediction", "?")
        nslkdd_i = result.get("nslkdd_if_prediction", "?")
        cicids_r = result.get("cicids_rf_prediction",  "?")
        cicids_i = result.get("cicids_if_prediction",  "?")
        print(f"  [{level:8s}] Risk: {score:5.1f}  "
              f"NSL-KDD RF:{nslkdd_r} IF:{nslkdd_i}  "
              f"CICIDS RF:{cicids_r} IF:{cicids_i}")