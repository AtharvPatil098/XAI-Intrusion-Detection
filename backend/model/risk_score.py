# model/risk_score.py
# Risk scoring functions.
# compute_risk_score()      — single dataset (2 signals)
# compute_dual_risk_score() — both datasets  (4 signals)

def _normalise_anomaly(anomaly_score: float) -> float:
    """Convert IF score_samples value → 0-1 (0=normal, 1=very anomalous)."""
    return min(max((-anomaly_score) / 0.7, 0.0), 1.0)


def _risk_level(score: float) -> str:
    if   score < 25: return "Low"
    elif score < 50: return "Medium"
    elif score < 75: return "High"
    else:            return "Critical"


# ── Single dataset (2 signals) ────────────────────────────────────────────────

def compute_risk_score(rf_prob_attack: float, anomaly_score: float) -> dict:
    """
    Combines RF + IF from one dataset into a 0-100 risk score.

    Args:
        rf_prob_attack : RF probability of attack   (0.0 – 1.0)
        anomaly_score  : IF score_samples value     (more negative = more anomalous)
    """
    anom_norm  = _normalise_anomaly(anomaly_score)
    combined   = 0.6 * rf_prob_attack + 0.4 * anom_norm
    risk_score = round(combined * 100, 1)

    return {
        "risk_score":           risk_score,
        "risk_level":           _risk_level(risk_score),
        "rf_contribution":      round(rf_prob_attack * 100, 1),
        "anomaly_contribution": round(anom_norm      * 100, 1),
    }


# ── Dual dataset (4 signals) ──────────────────────────────────────────────────

def compute_dual_risk_score(
    nslkdd_rf_prob:     float,
    nslkdd_anom_score:  float,
    cicids_rf_prob:     float,
    cicids_anom_score:  float,
) -> dict:
    """
    Combines all 4 model signals (NSL-KDD RF, NSL-KDD IF, CICIDS RF, CICIDS IF)
    into a single 0-100 risk score.

    Weighting rationale:
      - RF models (known attack classification) carry 60% of their dataset's weight
      - IF models (zero-day anomaly detection)  carry 40% of their dataset's weight
      - Both datasets contribute equally (50/50) to the final score
      - This means: any one model flagging strongly still pushes the score up

    Args:
        nslkdd_rf_prob    : NSL-KDD RF probability of attack  (0.0 – 1.0)
        nslkdd_anom_score : NSL-KDD IF score_samples value
        cicids_rf_prob    : CICIDS  RF probability of attack  (0.0 – 1.0)
        cicids_anom_score : CICIDS  IF score_samples value
    """
    # Normalise both anomaly scores to 0-1
    nslkdd_anom_norm = _normalise_anomaly(nslkdd_anom_score)
    cicids_anom_norm  = _normalise_anomaly(cicids_anom_score)

    # Per-dataset combined signal (RF=60%, IF=40%)
    nslkdd_signal = 0.6 * nslkdd_rf_prob    + 0.4 * nslkdd_anom_norm
    cicids_signal  = 0.6 * cicids_rf_prob   + 0.4 * cicids_anom_norm

    # Equal weight to both datasets
    combined   = 0.5 * nslkdd_signal + 0.5 * cicids_signal
    risk_score = round(combined * 100, 1)

    return {
        "risk_score":              risk_score,
        "risk_level":              _risk_level(risk_score),
        # Per-model contributions (0-100) for dashboard display
        "nslkdd_rf_contribution":  round(nslkdd_rf_prob    * 100, 1),
        "nslkdd_if_contribution":  round(nslkdd_anom_norm  * 100, 1),
        "cicids_rf_contribution":  round(cicids_rf_prob    * 100, 1),
        "cicids_if_contribution":  round(cicids_anom_norm  * 100, 1),
    }