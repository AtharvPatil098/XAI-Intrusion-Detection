from backend.explainability.shap_explainer import shap_explainer
from backend.model.risk_score import calculate_risk_score, get_risk_level


class ExplanationEngine:
    def __init__(self):
        pass

    def get_top_features(self, shap_values, top_n=5):
        """
        Get top contributing features
        """
        sorted_features = sorted(
            shap_values.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )

        return sorted_features[:top_n]

    def generate_reason(self, top_features):
        """
        Convert features → human-readable reasoning
        """
        feature_names = [feat for feat, _ in top_features]

        # Simple mapping (can expand later)
        mapping = {
            "src_bytes": "high source data transfer",
            "dst_bytes": "high destination data transfer",
            "count": "high number of connections",
            "srv_count": "frequent service requests",
            "flow_bytes_per_sec": "high traffic flow rate",
            "flow_packets_per_sec": "high packet rate",
        }

        reasons = []

        for feat in feature_names:
            for key in mapping:
                if key in feat:
                    reasons.append(mapping[key])
                    break

        # fallback if no mapping found
        if not reasons:
            reasons = feature_names[:3]

        return reasons

    def explain(self, input_data, dataset, prediction_result):
        """
        Full explanation pipeline
        """

        # Step 1: Get SHAP values
        shap_values = shap_explainer.explain(input_data, dataset)

        # Step 2: Top features
        top_features = self.get_top_features(shap_values)

        # Step 3: Generate reasons
        reasons = self.generate_reason(top_features)

        # Step 4: Risk score
        risk_score = calculate_risk_score(prediction_result)
        risk_level = get_risk_level(risk_score)

        # Step 5: Final message
        if prediction_result["prediction"] == 1:
            message = f"⚠️ Potential attack detected due to {', '.join(reasons)}."
        else:
            message = f"✅ Normal traffic with minor variations in {', '.join(reasons)}."

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "top_features": top_features,
            "reason": reasons,
            "message": message
        }


# Singleton
explanation_engine = ExplanationEngine()