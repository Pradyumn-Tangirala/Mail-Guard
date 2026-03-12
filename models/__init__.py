"""
models/
Manages ML model loading, versioning, and inference interfaces.
All models used across the pipeline are centralized here.
"""

def load_model(model_name: str):
    """Load a trained model by name. Returns a model object."""
    raise NotImplementedError(f"load_model('{model_name}') not yet implemented.")


def run_inference(model, features: dict) -> dict:
    """Run inference on pre-extracted features. Returns a dict of raw scores."""
    raise NotImplementedError("run_inference() not yet implemented.")


def list_available_models() -> list:
    """Return a list of all registered model names."""
    raise NotImplementedError("list_available_models() not yet implemented.")
