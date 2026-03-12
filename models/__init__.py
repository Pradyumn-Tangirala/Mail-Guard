"""
models/
Manages ML model loading, versioning, and inference interfaces.
All models used across the pipeline are centralized here.
"""

import pickle
import pathlib
import logging

logger = logging.getLogger("mailguard.models")

# ── Global model cache ────────────────────────────────────────────────────────
_CACHE = {}

def load_model(model_name: str):
    """
    Load a trained model and its vectorizer. 
    Returns a dict containing 'model' and 'vectorizer' objects.
    """
    if model_name in _CACHE:
        return _CACHE[model_name]

    # In this version, all models are expected to be in models/artifacts/
    artifacts_dir = pathlib.Path(__file__).parent / "artifacts"
    model_path = artifacts_dir / "model.pkl"
    vec_path = artifacts_dir / "vectorizer.pkl"

    if not model_path.exists() or not vec_path.exists():
        logger.error(f"Model artifacts not found in {artifacts_dir}")
        raise FileNotFoundError(f"Missing .pkl artifacts for {model_name} in {artifacts_dir}")

    try:
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        with open(vec_path, "rb") as f:
            vectorizer = pickle.load(f)
        
        bundle = {
            "model": model,
            "vectorizer": vectorizer,
            "name": model_name
        }
        _CACHE[model_name] = bundle
        logger.info(f"Loaded model bundle: {model_name}")
        return bundle
    except Exception as e:
        logger.exception(f"Failed to load model {model_name}: {e}")
        raise

def run_inference(model_bundle: dict, features: dict) -> dict:
    """
    Run inference on pre-extracted features.
    model_bundle: dict returned by load_model()
    features: dict e.g. from preprocessing.extract_features()
    """
    model = model_bundle["model"]
    vectorizer = model_bundle["vectorizer"]
    
    clean_body = features.get("clean_body", "")
    
    # Vectorize and Predict
    vec = vectorizer.transform([clean_body])
    pred = model.predict(vec)[0]
    proba = model.predict_proba(vec)[0] # Usually [safe_prob, phish_prob]
    
    threat_prob = float(proba[1] if hasattr(model, "classes_") and 1 in model.classes_ else proba[0])
    label = "Phishing Email" if pred == 1 else "Safe Email"

    return {
        "prediction": label,
        "threat_probability": threat_prob,
        "model_used": model_bundle["name"]
    }

def list_available_models() -> list:
    """Return a list of all registered model names."""
    return ["phishing_classifier_v1"]
