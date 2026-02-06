def calculate_risk_score(prediction: str, probablity: float):
    # Calculate threat risk score (0-100) based on model prediction

    # Safety check
    probablity =max(0.0, min(1.0,probablity))

    if prediction == "normal":
        risk_score = int(probablity * 30)   # Cap normal risk
    else:
        risk_score = int(probablity * 100)  # Full risk range

    # Assign risk level
    if risk_score <= 30:
        risk_level = "Low"
    elif risk_score <= 70:
        risk_level = "Medium"
    elif risk_score <= 100:
        risk_level = "High"

    return risk_score, risk_level

#print(calculate_risk_score("attack", 0.95))
#print(calculate_risk_score("normal", 0.30))