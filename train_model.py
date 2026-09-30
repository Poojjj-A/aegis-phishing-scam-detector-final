"""
train_model.py
----------------
Trains a TF-IDF + Logistic Regression classifier on data/dataset.csv and
saves the fitted vectorizer + model to models/. Logistic Regression is
chosen deliberately over a black-box model: its coefficients map directly
to vocabulary terms, which lets risk_engine.py show *which words* pushed a
message towards "phishing" - real explainability, not just a score.

Run manually with `python train_model.py`, or it will run automatically on
first server startup if models/ is empty (see app/model.py).
"""

import csv
import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

DATA_PATH = "data/dataset.csv"
MODEL_DIR = "models"


def load_dataset(path=DATA_PATH):
    texts, labels = [], []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            texts.append(row["text"])
            labels.append(int(row["label"]))
    return texts, labels


def train():
    if not os.path.exists(DATA_PATH):
        print("Dataset not found, generating it first...")
        os.system("python3 generate_dataset.py")

    texts, labels = load_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        ngram_range=(1, 2),
        min_df=1,
        max_df=0.9,
        sublinear_tf=True,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    clf = LogisticRegression(max_iter=2000, class_weight="balanced", C=3.0)
    clf.fit(X_train_vec, y_train)

    preds = clf.predict(X_test_vec)
    acc = accuracy_score(y_test, preds)
    print(f"Held-out accuracy: {acc:.3f}")
    print(classification_report(y_test, preds, target_names=["legitimate", "phishing/scam"]))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(vectorizer, os.path.join(MODEL_DIR, "vectorizer.joblib"))
    joblib.dump(clf, os.path.join(MODEL_DIR, "classifier.joblib"))
    print(f"Saved model artifacts to {MODEL_DIR}/")


if __name__ == "__main__":
    train()
