def interpret_feature(feature_name):
    """
    Maps feature names to cybersecurity meaning.
    """

    feature_map = {
        "src_bytes": "Unusually high outgoing data volume",
        "dst_bytes": "Unusually high incoming data volume",
        "duration": "Abnormal connection duration",
        "wrong_fragment": "Suspicious packet fragmentation",
        "logged_in": "Suspicious authentication behavior",
        "count": "High number of connections in short time",
        "srv_count": "High service request frequency",
        "serror_rate": "Frequent connection errors",
        "dst_host_count": "Multiple connections to same host",
        "dst_host_srv_count": "Repeated service requests to host"
    }

    return feature_map.get(feature_name, f"Abnormal behavior in {feature_name}")



def generate_known_attack_explanation(prediction, confidence, top_features):
    """
    Explanation for known attacks detected by Random Forest.
    """

    feature_reasons = [
        interpret_feature(feature) for feature in top_features
    ]

    explanation = f"""
The system classified this traffic as a {prediction} attack 
with a confidence of {round(confidence * 100, 2)}%.

Key contributing factors:
- {feature_reasons[0]}
- {feature_reasons[1] if len(feature_reasons) > 1 else ""}

These patterns are consistent with previously learned attack behaviors.
"""

    return explanation.strip()



def generate_zero_day_explanation(anomaly_score, top_features):
    """
    Explanation for zero-day detection using Isolation Forest.
    """

    feature_reasons = [
        interpret_feature(feature) for feature in top_features
    ]

    explanation = f"""
The traffic significantly deviates from normal behavior patterns 
with an anomaly score of {round(anomaly_score, 3)}.

Primary unusual characteristics:
- {feature_reasons[0]}
- {feature_reasons[1] if len(feature_reasons) > 1 else ""}

Since this pattern does not match known attack signatures,
it is flagged as a potential zero-day attack.
"""

    return explanation.strip()



def generate_benign_explanation(confidence):
    """
    Explanation for normal traffic.
    """

    return f"""
The traffic is classified as normal with {round(confidence * 100, 2)}% confidence.

No significant abnormal patterns were detected in the analyzed features.
"""



def generate_final_explanation(
    rf_prediction,
    rf_confidence,
    anomaly_score,
    top_features,
    zero_day_threshold=0.6
):
    """
    Master function that decides which explanation to generate.
    """

    # Case 1: Known attack detected
    if rf_prediction != "normal" and rf_confidence >= 0.7:
        return generate_known_attack_explanation(
            rf_prediction,
            rf_confidence,
            top_features
        )

    # Case 2: Zero-day detection via Isolation Forest
    if anomaly_score > zero_day_threshold:
        return generate_zero_day_explanation(
            anomaly_score,
            top_features
        )

    # Case 3: Normal traffic
    return generate_benign_explanation(rf_confidence)