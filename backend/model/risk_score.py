# model/risk_score.py
# Risk scoring functions.
# compute_risk_score()      — single dataset (2 signals)
# compute_dual_risk_score() — both datasets  (4 signals)
#
# All inputs are cast to plain Python float at entry to strip numpy scalar
# types (np.float64 etc.) which cause "only length-1 arrays" errors during
# JSON serialisation or downstream float() calls.


def _to_float(v) -> float:
    """Cast any numeric value (including numpy scalars) to plain Python float."""
    try:
        return float(v)
    except Exception:
        return 0.0


def _normalise_anomaly(anomaly_score: float) -> float:
    """Convert IF score_samples value → 0-1 (0=normal, 1=very anomalous)."""
    return min(max((-anomaly_score) / 0.7, 0.0), 1.0)


def _risk_level(score: float) -> str:
    if   score < 25: return "Low"
    elif score < 50: return "Medium"
    elif score < 75: return "High"
    else:            return "Critical"


# ── Single dataset (2 signals) ────────────────────────────────────────────────

def compute_risk_score(rf_prob_attack, anomaly_score) -> dict:
    """Combines RF + IF from one dataset into a 0-100 risk score."""
    rf   = _to_float(rf_prob_attack)
    anom = _to_float(anomaly_score)

    anom_norm  = _normalise_anomaly(anom)
    combined   = 0.6 * rf + 0.4 * anom_norm
    risk_score = round(combined * 100, 1)

    return {
        "risk_score":           risk_score,
        "risk_level":           _risk_level(risk_score),
        "rf_contribution":      round(rf        * 100, 1),
        "anomaly_contribution": round(anom_norm * 100, 1),
    }


# ── Dual dataset (4 signals) ──────────────────────────────────────────────────

def compute_dual_risk_score(
    nslkdd_rf_prob,
    nslkdd_anom_score,
    cicids_rf_prob,
    cicids_anom_score,
) -> dict:
    """
    Combines all 4 model signals into a single 0-100 risk score.
    RF=60%, IF=40% per dataset. Both datasets weighted equally (50/50).
    """
    # Cast all inputs to plain float — strips numpy scalar types
    nsl_rf  = _to_float(nslkdd_rf_prob)
    nsl_an  = _to_float(nslkdd_anom_score)
    cic_rf  = _to_float(cicids_rf_prob)
    cic_an  = _to_float(cicids_anom_score)

    nsl_anom_norm = _normalise_anomaly(nsl_an)
    cic_anom_norm = _normalise_anomaly(cic_an)

    nslkdd_signal = 0.6 * nsl_rf + 0.4 * nsl_anom_norm
    cicids_signal = 0.6 * cic_rf + 0.4 * cic_anom_norm

    combined   = 0.5 * nslkdd_signal + 0.5 * cicids_signal
    risk_score = round(combined * 100, 1)

    return {
        "risk_score":             risk_score,
        "risk_level":             _risk_level(risk_score),
        "nslkdd_rf_contribution": round(nsl_rf        * 100, 1),
        "nslkdd_if_contribution": round(nsl_anom_norm * 100, 1),
        "cicids_rf_contribution": round(cic_rf        * 100, 1),
        "cicids_if_contribution": round(cic_anom_norm * 100, 1),
    }