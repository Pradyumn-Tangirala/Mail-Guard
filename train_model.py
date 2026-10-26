"""
train_model.py — Train and evaluate the MailGuard NLP phishing classifier.
==========================================================================

Data (download first:  python scripts/download_data.py)
  data/raw/Nazario_5.csv   train / test   (Nazario phishing + 5 legitimate corpora)
  data/raw/Nigerian_5.csv  cross-dataset generalisation test (advance-fee fraud)
  Source: Champa et al., "Phishing Email Curated Datasets", Zenodo,
          DOI 10.5281/zenodo.8339691, CC BY 4.0

Protocol
  1. Text = normalize_for_model(clean_text(body))   ← identical to inference
  2. Stratified 80/20 train/test split of Nazario_5 (random_state=42)
  3. 5-fold stratified CV on the TRAIN split for both candidates:
       - TF-IDF + LogisticRegression          (baseline)
       - TF-IDF + GradientBoostingClassifier   (previous model type)
     The winner is chosen on mean CV F1 — the test split is never used for selection.
  4. Winner is refit on the full train split and evaluated once on the test split.
  5. Cross-dataset test on Nigerian_5, after removing every email whose body also
     appears in Nazario_5 (the two files share ~1.3k legitimate emails).
  6. Leakage ablation: baseline CV with vs. without corpus-token masking.

Outputs
  models/artifacts/model.pkl, vectorizer.pkl   ← loaded by the pipeline
  models/artifacts/metrics.json                ← every number quoted in the README
"""

import json
import pathlib
import pickle
import re
import sys
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score,
    recall_score, roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from preprocessing import clean_text, normalize_for_model  # noqa: E402

RAW_DIR = ROOT / "data" / "raw"
ARTIFACTS = ROOT / "models" / "artifacts"
SEED = 42


# ── Data ───────────────────────────────────────────────────────────────────────

def load(name: str) -> pd.DataFrame:
    path = RAW_DIR / name
    if not path.exists():
        sys.exit(f"{path} not found. Run: python scripts/download_data.py")
    df = pd.read_csv(path)
    df["clean"] = df["body"].fillna("").astype(str).map(clean_text)
    df["text"] = df["clean"].map(normalize_for_model)
    df = df[df["text"].str.len() > 0]
    return df.drop_duplicates(subset="text").reset_index(drop=True)


def _norm_key(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


# ── Models ─────────────────────────────────────────────────────────────────────

def make_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        stop_words="english", sublinear_tf=True, ngram_range=(1, 2),
        min_df=2, max_df=0.95, max_features=20000,
    )


CANDIDATES = {
    "logistic_regression": lambda: LogisticRegression(max_iter=2000, random_state=SEED),
    "gradient_boosting":   lambda: GradientBoostingClassifier(random_state=SEED),
}


def make_pipeline(name: str) -> Pipeline:
    return Pipeline([("tfidf", make_vectorizer()), ("clf", CANDIDATES[name]())])


# ── Metrics ────────────────────────────────────────────────────────────────────

def evaluate(y_true, proba, threshold: float = 0.5) -> dict:
    y_pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "n": int(len(y_true)),
        "accuracy":  round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall":    round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1":        round(f1_score(y_true, y_pred, zero_division=0), 4),
        "false_positive_rate": round(float(fp / (fp + tn)), 4) if (fp + tn) else None,
        "roc_auc":   round(roc_auc_score(y_true, proba), 4) if len(set(y_true)) > 1 else None,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def cv_scores(pipe: Pipeline, X, y) -> dict:
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    res = cross_validate(pipe, X, y, cv=cv, n_jobs=-1,
                         scoring=["f1", "precision", "recall", "roc_auc"])
    return {m: {"mean": round(float(np.mean(res[f"test_{m}"])), 4),
                "std":  round(float(np.std(res[f"test_{m}"])), 4)}
            for m in ["f1", "precision", "recall", "roc_auc"]}


def top_features(pipe: Pipeline, k: int = 15) -> dict:
    vocab = np.array(pipe.named_steps["tfidf"].get_feature_names_out())
    clf = pipe.named_steps["clf"]
    if hasattr(clf, "coef_"):
        w = clf.coef_[0]
        return {"phishing": vocab[np.argsort(w)[-k:][::-1]].tolist(),
                "legitimate": vocab[np.argsort(w)[:k]].tolist()}
    return {"most_important": vocab[np.argsort(clf.feature_importances_)[-k:][::-1]].tolist()}


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    t0 = time.time()
    nazario = load("Nazario_5.csv")
    X_tr, X_te, y_tr, y_te = train_test_split(
        nazario["text"], nazario["label"], test_size=0.2,
        stratify=nazario["label"], random_state=SEED,
    )
    print(f"Nazario_5: {len(nazario)} emails  ->  train {len(X_tr)} / test {len(X_te)}")

    # 1. Model selection on CV (train split only)
    cv = {}
    for name in CANDIDATES:
        t = time.time()
        cv[name] = cv_scores(make_pipeline(name), X_tr, y_tr)
        print(f"  CV {name:20s} F1={cv[name]['f1']['mean']:.4f} +/-{cv[name]['f1']['std']:.4f}"
              f"  AUC={cv[name]['roc_auc']['mean']:.4f}  ({time.time() - t:.0f}s)")
    winner = max(cv, key=lambda n: cv[n]["f1"]["mean"])
    print(f"  -> selected: {winner}")

    # 2. Leakage ablation: what CV looks like WITHOUT corpus-token masking
    unmasked = nazario.loc[X_tr.index, "clean"]
    cv_unmasked = cv_scores(make_pipeline("logistic_regression"), unmasked, y_tr)
    print(f"  Ablation (no masking) logistic_regression F1={cv_unmasked['f1']['mean']:.4f}")

    # 3. Fit both on the full train split; report held-out test for both
    test, fitted = {}, {}
    for name in CANDIDATES:
        pipe = make_pipeline(name).fit(X_tr, y_tr)
        fitted[name] = pipe
        test[name] = evaluate(y_te.to_numpy(), pipe.predict_proba(X_te)[:, 1])
    best = fitted[winner]
    print(f"  Test ({winner}): {test[winner]}")

    # 4. Cross-dataset generalisation: Nigerian_5 minus anything seen in Nazario_5
    nigerian = load("Nigerian_5.csv")
    seen = set(nazario["text"].map(_norm_key))
    overlap = nigerian["text"].map(_norm_key).isin(seen)
    unseen = nigerian[~overlap]
    cross = evaluate(unseen["label"].to_numpy(), best.predict_proba(unseen["text"])[:, 1])
    print(f"  Cross-dataset Nigerian_5 ({int(overlap.sum())} overlapping rows removed): {cross}")

    # 5. Persist the winner in the format the pipeline loads (vectorizer + model)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with open(ARTIFACTS / "model.pkl", "wb") as f:
        pickle.dump(best.named_steps["clf"], f)
    with open(ARTIFACTS / "vectorizer.pkl", "wb") as f:
        pickle.dump(best.named_steps["tfidf"], f)

    metrics = {
        "trained_at": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__,
        "dataset": {
            "source": "Champa et al., Phishing Email Curated Datasets, Zenodo, "
                      "DOI 10.5281/zenodo.8339691 (CC BY 4.0)",
            "train_test_file": "Nazario_5.csv",
            "n_emails": int(len(nazario)),
            "n_phishing": int(nazario["label"].sum()),
            "n_legitimate": int((nazario["label"] == 0).sum()),
            "n_train": int(len(X_tr)), "n_test": int(len(X_te)),
            "split": "stratified 80/20, random_state=42",
        },
        "selected_model": winner,
        "selection": "highest mean 5-fold CV F1 on the train split",
        "cv_train_split": cv,
        "test_split": test,
        "cross_dataset": {
            "file": "Nigerian_5.csv",
            "overlapping_rows_removed": int(overlap.sum()),
            "metrics": cross,
        },
        "leakage_ablation": {
            "note": "logistic_regression CV F1 without masking corpus-identifying tokens "
                    "(jose / monkey.org / enron), year masking, or URL/email-address tokenisation",
            "cv_f1_unmasked": cv_unmasked["f1"],
            "cv_f1_masked": cv["logistic_regression"]["f1"],
        },
        "top_features": top_features(best),
        "vectorizer": {"vocabulary_size": len(best.named_steps["tfidf"].vocabulary_),
                       "ngram_range": [1, 2], "max_features": 20000},
    }
    with open(ARTIFACTS / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Saved model, vectorizer and metrics.json to {ARTIFACTS}  ({time.time() - t0:.0f}s total)")


if __name__ == "__main__":
    main()
