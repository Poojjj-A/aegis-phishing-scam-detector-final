"""
model.py
---------
Loads the trained TF-IDF vectorizer + Logistic Regression classifier. If no
trained model is found on disk (e.g. first run after cloning the repo), it
trains one automatically from data/dataset.csv so the app works out of the
box with zero manual setup steps.
"""

import os
import sys
import joblib
import numpy as np

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
VEC_PATH = os.path.join(MODEL_DIR, "vectorizer.joblib")
CLF_PATH = os.path.join(MODEL_DIR, "classifier.joblib")

_vectorizer = None
_classifier = None


def _ensure_trained():
    global _vectorizer, _classifier
    if os.path.exists(VEC_PATH) and os.path.exists(CLF_PATH):
        return
    print("[model] No trained model found - training one now (first run only)...", file=sys.stderr)
    root = os.path.join(os.path.dirname(__file__), "..")
    cwd = os.getcwd()
    try:
        os.chdir(root)
        sys.path.insert(0, root)
        import train_model
        train_model.train()
    finally:
        os.chdir(cwd)


def load():
    global _vectorizer, _classifier
    if _vectorizer is not None and _classifier is not None:
        return _vectorizer, _classifier
    _ensure_trained()
    _vectorizer = joblib.load(VEC_PATH)
    _classifier = joblib.load(CLF_PATH)
    return _vectorizer, _classifier


def predict_proba(text: str) -> float:
    """Returns the model's estimated probability (0-1) that `text` is phishing/scam."""
    vectorizer, classifier = load()
    vec = vectorizer.transform([text])
    proba = classifier.predict_proba(vec)[0]
    classes = list(classifier.classes_)
    return float(proba[classes.index(1)])


def top_contributing_terms(text: str, top_n: int = 6):
    """
    Returns the top TF-IDF terms present in `text` that most pushed the
    classifier's decision towards "phishing/scam", using the logistic
    regression coefficients as per-term weights. This is what gives the
    model's contribution to the risk score a human-readable explanation.
    """
    vectorizer, classifier = load()
    vec = vectorizer.transform([text])
    if vec.nnz == 0:
        return []

    coefs = classifier.coef_[0]
    feature_names = np.array(vectorizer.get_feature_names_out())

    nz_idx = vec.nonzero()[1]
    contributions = []
    for idx in nz_idx:
        weight = coefs[idx] * vec[0, idx]
        if weight > 0:
            contributions.append((feature_names[idx], float(weight)))

    contributions.sort(key=lambda x: x[1], reverse=True)
    return contributions[:top_n]
