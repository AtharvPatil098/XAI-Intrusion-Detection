class ExplanationEngine:

    def __init__(self, explainer, feature_cols):
        self.explainer = explainer
        self.feature_cols = feature_cols

    def generate(self, df):

        # ==============================
        # 🔹 GET SHAP VALUES (SAFE)
        # ==============================
        shap_values = self.explainer(df)

        try:
            values = shap_values.values[0][:, 1]   # attack class
        except:
            values = shap_values.values[0]         # fallback

        # ==============================
        # 🔹 FEATURE IMPORTANCE
        # ==============================
        feature_importance = list(zip(self.feature_cols, values))
        feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)

        # ==============================
        # 🔹 REMOVE DUPLICATE MEANINGS
        # ==============================
        seen_meanings = set()
        top_features = []

        for feature, value in feature_importance:

            f = feature.lower()

            # 🔥 Map feature → meaning category
            if "flow packets/s" in f:
                meaning = "packet_rate"
            elif "flow bytes/s" in f:
                meaning = "data_rate"
            elif "flow duration" in f:
                meaning = "duration"
            elif "destination port" in f:
                meaning = "port"
            elif "total fwd packets" in f:
                meaning = "fwd_packets"
            elif "total backward packets" in f:
                meaning = "bwd_packets"
            elif "init_win_bytes" in f:
                meaning = "tcp_window"
            elif "packet length" in f:
                meaning = "packet_size"
            elif "header length" in f:
                meaning = "header"
            elif "idle" in f:
                meaning = "idle"
            elif "psh flag" in f:
                meaning = "psh_flag"
            else:
                meaning = "generic"

            # ✅ Remove duplicate meanings
            if meaning not in seen_meanings:
                seen_meanings.add(meaning)
                top_features.append((feature, value))

            if len(top_features) == 5:
                break

        # ==============================
        # 🔹 HUMAN READABLE EXPLANATION
        # ==============================
        explanation = []

        for feature, impact in top_features:

            f = feature.lower()

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
                reason = "Unusual network activity deviating from normal patterns"

            explanation.append({
                "feature": feature,
                "reason": reason,
                "effect": "increases attack probability" if impact > 0 else "supports normal behavior"
            })

        return explanation