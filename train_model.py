import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Sample dataset (you can expand later)
data = pd.read_csv("dns_features.csv")

X = data.drop("label", axis=1)
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=42
)

model.fit(X_train, y_train)

joblib.dump(model, "dns_rf_model.pkl")
print("Model trained & saved")
print(f"Model Accuracy: {model.score(X_test, y_test) * 100:.2f}%")
