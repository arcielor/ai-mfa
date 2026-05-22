import numpy as np
from sklearn.tree import DecisionTreeClassifier
import pickle
import os
import random

MODEL_PATH = os.path.join(os.path.dirname(__file__), "risk_model.pkl")

def _rule_score(failed, short_interval, unknown_device, unusual_hour, password_match, otp_resends, unusual_location=0, anonymous_ip=0):
    score = 0
    if failed >= 3:          score += 2
    if short_interval == 1:  score += 2
    if unknown_device == 1:  score += 3
    if unusual_hour == 1:    score += 1
    if password_match == 0:  score += 2
    if otp_resends == 1:     score += 1
    elif otp_resends >= 2:   score += 2
    if unusual_location == 1: score += 2
    if anonymous_ip == 1:    score += 2
    return score

def _generate_training_data(n=3000):
    rng = random.Random(42)
    np.random.seed(42)
    X, y = [], []
    for _ in range(n):
        f = rng.randint(0, 10)
        si = rng.randint(0, 1) # short_interval
        ud = rng.randint(0, 1) # unknown_device
        uh = rng.randint(0, 1) # unusual_hour
        pm = rng.randint(0, 1) # password_match
        r = rng.randint(0, 1)  # otp_resends
        ul = rng.randint(0, 1) # unusual_location
        ai = rng.randint(0, 1) # anonymous_ip
        score = _rule_score(f, si, ud, uh, pm, r, ul, ai)
        label = 2 if score >= 5 else (1 if score >= 3 else 0)
        X.append([f, si, ud, uh, pm, r, ul, ai])
        y.append(label)
    return np.array(X), np.array(y)

def train_model():
    X, y = _generate_training_data()
    model = DecisionTreeClassifier(max_depth=8, random_state=42)
    model.fit(X, y)
    try:
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(model, f)
        print("[ML Engine] Decision Tree trained and saved.")
    except Exception as e:
        print(f"[ML Engine] Warning: Could not save model to {MODEL_PATH}: {e}")
    return model

def load_model():
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f:
                model = pickle.load(f)
            # Retrain if model feature count changed (8 features now instead of 6)
            if model.n_features_in_ != 8:
                print("[ML Engine] Model feature count changed. Retraining...")
                return train_model()
            return model
        except Exception:
            pass
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
        features["otp_resends"],
        features.get("unusual_location", 0),
        features.get("anonymous_ip", 0),
    ]])
    pred = int(_model.predict(X)[0])
    probs = _model.predict_proba(X)[0]
    confidence = round(float(max(probs)) * 100, 1)
    risk_map = {0: "low", 1: "medium", 2: "high"}

    # Also compute rule score for display
    rule_score = _rule_score(
        features["failed_attempts"], features["short_interval"],
        features["unknown_device"], features["unusual_hour"],
        features["password_match"], features["otp_resends"],
        features.get("unusual_location", 0), features.get("anonymous_ip", 0)
    )
    return pred, confidence, risk_map[pred], rule_score
