def calculate_risk_score(attack_prob, anomaly_score, is_anomaly):
    """
    Final Stable + Visual-Friendly Risk Scoring
    """

    # --------------------------
    # 🔹 BASE RISK
    # --------------------------
    base_risk = attack_prob * 100

    # --------------------------
    # 🔹 ANOMALY STRENGTH
    # --------------------------
    anomaly_strength = abs(anomaly_score)

    # normalize anomaly (controlled impact)
    anomaly_factor = min(anomaly_strength * 40, 25)

    # --------------------------
    # 🔴 CASE 1: CONFIRMED ATTACK
    # --------------------------
    if attack_prob >= 0.5:
        risk = base_risk + anomaly_factor

    # --------------------------
    # 🟠 CASE 2: SUSPICIOUS / UNKNOWN
    # --------------------------
    elif is_anomaly:
        risk = 65 + anomaly_factor   # always visibly high

    # --------------------------
    # 🟢 CASE 3: NORMAL
    # --------------------------
    else:
        risk = base_risk * 0.3   # keep low (green)

    # --------------------------
    # 🔒 CLAMP (0–100)
    # --------------------------
    return round(min(max(risk, 0), 100), 2)