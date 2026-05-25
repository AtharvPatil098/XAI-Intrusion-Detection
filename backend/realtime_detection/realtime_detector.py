import time
import random
import requests

API_URL = "http://127.0.0.1:8000/predict"


def generate_traffic():
    return {
        "packets": random.randint(10, 50000),
        "bytes": random.randint(500, 10000000),
        "duration": round(random.uniform(0.01, 5), 3),
        "port": random.choice([80, 443, 22])
    }


def run():
    print("🚀 Real-Time Detection Started...\n")

    while True:
        data = generate_traffic()

        try:
            res = requests.post(API_URL, json=data)
            out = res.json()

            print("🔹 Traffic:", data)
            print("➡ Prediction:", out["prediction"])
            print("➡ Risk:", out["risk_score"])
            print("➡ Anomaly:", out["is_anomaly"])
            print("-" * 50)

        except Exception as e:
            print("❌ API Error:", e)

        time.sleep(3)


if __name__ == "__main__":
    run()