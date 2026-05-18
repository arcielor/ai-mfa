import numpy as np
from sklearn.tree import DecisionTreeClassifier
import pickle
import os
import random

MODEL_PATH = os.path.join(os.path.dirname(__file__), "risk_model.pkl")

def _rule_score(failed, short_interval, unknown_device, unusual_hour, password_match):
    score = 0
    if failed >= 3:          score += 2
    if short_interval == 1:  score += 2
    if unknown_device == 1:  score += 1
    if unusual_hour == 1:    score += 1
    if password_match == 0:  score += 2
    return score

def _generate_training_data(n=3000):
    rng = random.Random(42)
    np.random.seed(42)
    X, y = [], []
    for _ in range(n):
        f = rng.randint(0, 10)
        si = rng.randint(0, 1)
        ud = rng.randint(0, 1)
        uh = rng.randint(0, 1)
        pm = rng.randint(0, 1)
        score = _rule_score(f, si, ud, uh, pm)
        label = 2 if score >= 5 else (1 if score >= 3 else 0)
        X.append([f, si, ud, uh, pm])
        y.append(label)
    return np.array(X), np.array(y)

def train_model():
    X, y = _generate_training_data()
    model = DecisionTreeClassifier(max_depth=8, random_state=42)
    model.fit(X, y)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print("[ML Engine] Decision Tree trained and saved.")
    return model

def load_model():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return train_model()

_model = None

def predict_risk(features: dict):
    """
    Predict risk level from feature dict.
    Returns: (risk_int, confidence_pct, risk_str, risk_score_rule)
    """
    global _model
    if _model is None:
        _model = load_model()

    X = np.array([[
        features["failed_attempts"],
        features["short_interval"],
        features["unknown_device"],
        features["unusual_hour"],
        features["password_match"],
    ]])
    pred = int(_model.predict(X)[0])
    probs = _model.predict_proba(X)[0]
    confidence = round(float(max(probs)) * 100, 1)
    risk_map = {0: "low", 1: "medium", 2: "high"}

    # Also compute rule score for display
    rule_score = _rule_score(
        features["failed_attempts"], features["short_interval"],
        features["unknown_device"], features["unusual_hour"],
        features["password_match"]
    )
    return pred, confidence, risk_map[pred], rule_score
