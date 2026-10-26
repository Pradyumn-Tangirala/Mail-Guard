import json
import os
import pathlib
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from preprocessing import normalize_for_model
from models import load_model, run_inference

ARTIFACTS = pathlib.Path(PROJECT_ROOT) / "models" / "artifacts"


def test_normalize_masks_urls_and_addresses():
    text = normalize_for_model("Login at https://evil.test/login or mail help@evil.test now")
    assert "urltoken" in text
    assert "emailtoken" in text
    assert "evil.test" not in text


def test_normalize_removes_corpus_identifying_tokens():
    # These tokens identify the source corpus (Nazario inbox / Enron), not phishing.
    text = normalize_for_model("Dear Jose, your monkey account at Enron")
    for token in ("jose", "monkey", "enron"):
        assert token not in text.lower()


def test_metrics_file_matches_shipped_model():
    metrics = json.loads((ARTIFACTS / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["selected_model"] in metrics["test_split"]
    bundle = load_model("phishing_classifier_v1")
    expected = {"logistic_regression": "LogisticRegression",
                "gradient_boosting": "GradientBoostingClassifier"}[metrics["selected_model"]]
    assert type(bundle["model"]).__name__ == expected


def test_model_ranks_phishing_above_legitimate():
    bundle = load_model("phishing_classifier_v1")
    phish = run_inference(bundle, {"clean_body":
        "Your account has been suspended. Verify your password immediately "
        "by clicking the link below or your mailbox will be closed."})
    legit = run_inference(bundle, {"clean_body":
        "Hi team, attached are the notes from Tuesday's planning meeting. "
        "Let me know if I missed anything before we finalise the schedule."})
    assert 0.0 <= legit["threat_probability"] <= 1.0
    assert phish["threat_probability"] > legit["threat_probability"]
