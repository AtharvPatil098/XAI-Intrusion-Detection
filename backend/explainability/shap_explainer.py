import shap

# ==============================
# 🔹 CREATE EXPLAINER
# ==============================

def create_explainer(model, background_data):
    """
    Create SHAP explainer using model.predict_proba
    Compatible with XGBoost >= 3.x
    """
    return shap.Explainer(model.predict_proba, background_data)


# ==============================
# 🔹 GET SHAP VALUES
# ==============================

def get_shap_values(explainer, df):
    """
    Generate SHAP values for given input
    """
    return explainer(df)


# ==============================
# 🔹 EXTRACT TOP FEATURES
# ==============================

def get_top_features(shap_values, feature_names, top_n=5):
    """
    Extract top contributing features
    """

    # ==============================
    # 🔹 HANDLE SHAPE SAFELY
    # ==============================
    try:
        # Multi-class / classification
        values = shap_values.values[0][:, 1]   # attack class
    except:
        # Binary fallback
        values = shap_values.values[0]

    # ==============================
    # 🔹 FEATURE IMPORTANCE
    # ==============================
    feature_importance = list(zip(feature_names, values))
    feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)

    top_features = feature_importance[:top_n]

    results = []

    for feature, value in top_features:

        impact = (
            "increases attack probability"
            if value > 0
            else "supports normal behavior"
        )

        results.append({
            "feature": feature,
            "impact": impact,
            "shap_value": float(value)
        })

    return results


# ==============================
# 🔹 OPTIONAL: HUMAN MAPPING
# ==============================

def convert_to_human_readable(shap_output):
    """
    Convert technical features to human explanations
    """

    explanations = []

    for item in shap_output:
        feature = item["feature"]
        impact = item["impact"]

        f = feature.lower()

        # -----------------------------
        # 🔥 HUMAN MAPPING
        # -----------------------------

        if "flow packets/s" in f:
            reason = "High packet rate detected (possible flooding attack)"

        elif "flow bytes/s" in f:
            reason = "High data transfer rate detected"

        elif "flow duration" in f:
            reason = "Abnormal or very short connection duration"

        elif "destination port" in f:
            reason = "Traffic targeting specific or sensitive service port"

        elif "total fwd packets" in f:
            reason = "Large number of forward packets detected"

        elif "total backward packets" in f:
            reason = "High response traffic observed"

        elif "init_win_bytes" in f:
            reason = "Abnormal TCP window size detected"

        elif "packet length" in f:
            reason = "Unusual packet size behavior detected"

        elif "header length" in f:
            reason = "Abnormal packet structure detected"

        elif "idle" in f:
            reason = "Irregular idle time between packets"

        elif "psh flag" in f:
            reason = "Suspicious push flag activity detected"

        else:
            reason = "Suspicious network behavior pattern"

        explanations.append({
            "feature": feature,
            "reason": reason,
            "effect": impact
        })

    return explanations