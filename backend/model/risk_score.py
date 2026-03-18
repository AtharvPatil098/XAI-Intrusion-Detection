def calculate_risk_score(prediction_result):
    """
    Combines RF + IF outputs into a single risk score

    prediction_result: dict from predictor.predict()
    """

    rf_pred = prediction_result["prediction"]          # 0 or 1
    rf_prob = prediction_result["attack_probability"]  # 0 to 1
    anomaly = prediction_result["anomaly"]             # 0 or 1

    # Weighted score
    risk_score = (0.5 * rf_prob) + (0.3 * rf_pred) + (0.2 * anomaly)

    return round(risk_score, 4)


def get_risk_level(risk_score):
    """
    Converts numeric score → human-readable level
    """

    if risk_score < 0.3:
        return "Low"
    elif risk_score < 0.7:
        return "Medium"
    else:
        return "High"