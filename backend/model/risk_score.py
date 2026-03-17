from backend.config import RISK_THRESHOLDS

def calculate_risk(predictions):
    scores = []
    details = {}

    for dataset, result in predictions.items():
        rf_prob = result["rf_prob"]
        if_pred = result["if_pred"]

        # Convert IF output
        if_score = 1 if if_pred == -1 else 0

        # Combine RF + IF
        combined_score = (rf_prob + if_score) / 2

        scores.append(combined_score)

        details[dataset] = {
            "rf_prob": rf_prob,
            "if_anomaly": if_pred == -1,
            "combined_score": combined_score
        }

    # Final risk = max across datasets
    final_risk = max(scores)

    # Determine status
    if final_risk >= RISK_THRESHOLDS["attack"]:
        status = "ATTACK"
    elif final_risk >= RISK_THRESHOLDS["suspicious"]:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    # Zero-day flag
    zero_day = any(
        (res["rf_pred"] == 0 and res["if_pred"] == -1)
        for res in predictions.values()
    )

    return {
        "risk_score": round(final_risk, 3),
        "status": status,
        "zero_day": zero_day,
        "details": details
    }