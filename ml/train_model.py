import pandas as pd
from sklearn.linear_model import LogisticRegression
import json
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.metrics import precision_score, recall_score, f1_score

# Load dataset
data = pd.read_csv("ml/final_dataset.csv")

# Features
X = data[["length", "hasNumbers", "numDots", "hasHyphen", "hasAtSymbol"]]

# Labels
y = data["label"]

# Train model
model = LogisticRegression()
model.fit(X, y)

# Predictions
y_pred = model.predict(X)

print("Accuracy:", accuracy_score(y, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y, y_pred))
print("Precision:", precision_score(y, y_pred))
print("Recall:", recall_score(y, y_pred))
print("F1 Score:", f1_score(y, y_pred))

# Get weights
weights = model.coef_[0]
intercept = model.intercept_[0]

# Save model
model_data = {
    "weights": weights.tolist(),
    "intercept": intercept
}

with open("model.json", "w") as f:
    json.dump(model_data, f)

print("Model trained and saved!")