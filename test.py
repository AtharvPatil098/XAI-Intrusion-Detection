from backend.model.predict import predictor
import pandas as pd

"""
df = pd.read_csv("backend/data/processed/nsl_kdd_processed.csv", nrows=1)

sample = df.drop(columns=["label"]).iloc[0].to_dict()

result = predictor.predict(sample, "nsl_kdd")
print(result)

df = pd.read_csv("backend/data/processed/cicids_processed.csv", nrows=1)

sample = df.drop(columns=["label"]).iloc[0].to_dict()

result = predictor.predict(sample, "cicids")
print(result)
"""
#================

"""
from backend.model.predict import predictor
from backend.model.risk_score import calculate_risk_score, get_risk_level
import pandas as pd

df = pd.read_csv("backend/data/processed/nsl_kdd_processed.csv", nrows=1)

sample = df.drop(columns=["label"]).iloc[0].to_dict()

result = predictor.predict(sample, "nsl_kdd")

score = calculate_risk_score(result)
level = get_risk_level(score)

print(score, level)
"""

#================
#================


# from backend.explainability.shap_explainer import shap_explainer
# import pandas as pd

# df = pd.read_csv("backend/data/processed/nsl_kdd_processed.csv", nrows=1)

# sample = df.drop(columns=["label"]).iloc[0].to_dict()

# explanation = shap_explainer.explain(sample, "nsl_kdd")

# # Top 5 important features
# top_features = sorted(explanation.items(), key=lambda x: abs(x[1]), reverse=True)[:5]

# print(top_features)

#===================
#===================

from backend.model.predict import predictor
from backend.explainability.explanation_engine import explanation_engine
import pandas as pd

df = pd.read_csv("backend/data/processed/nsl_kdd_processed.csv", nrows=1)

sample = df.drop(columns=["label"]).iloc[0].to_dict()

prediction = predictor.predict(sample, "nsl_kdd")

explanation = explanation_engine.explain(sample, "nsl_kdd", prediction)

print(explanation)