import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Load processed data
DATA_PATH = "backend/data/processed/processed_data.csv"

data = pd.read_csv(DATA_PATH)

# Split features and labels
X = data.drop("label", axis=1)      #input features
y = data["label"]                   #target

# Train-test split
X_train, X_test,  y_train, y_test = train_test_split(
    X,y,
    test_size = 0.2,
    random_state = 42,
    stratify = y  
)

# Initialize Random Forest
model = RandomForestClassifier(
    n_estimators=100,
    max_depth = None,
    random_state= 42,
    n_jobs =-1
)

# Training the model
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)

print("Accuracy: ", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

# Save trained model
MODEL_PATH = "backend/saved_models/rf_model.pkl" 
joblib.dump(model, MODEL_PATH)

print(f"\nModel saved at: {MODEL_PATH}")