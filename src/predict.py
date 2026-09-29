"""
DNS Threat Intelligence & Machine Learning
Module: Prediction Pipeline

This module provides functions to load the trained ML model and predict
threat classes (Benign, DGA, DNS Tunnelling) for new domain strings.
"""

import os
import sys
import json
import joblib
import pandas as pd

# Add parent directory to path if running directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_extraction import extract_features_from_domain

# Default model and metadata paths
MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "dns_threat_classifier.pkl"))
METADATA_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "model_metadata.json"))

_model = None
_metadata = None


def load_model(model_path: str = None, metadata_path: str = None):
    """
    Load the trained Random Forest model and metadata.
    """
    global _model, _metadata
    if model_path is None:
        model_path = MODEL_PATH
    if metadata_path is None:
        metadata_path = METADATA_PATH

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found at {model_path}")
    if not os.path.exists(metadata_path):
        raise FileNotFoundError(f"Metadata file not found at {metadata_path}")

    _model = joblib.load(model_path)
    with open(metadata_path, 'r') as f:
        _metadata = json.load(f)

    return _model, _metadata


def predict_domain(domain_str: str, model_path: str = None, metadata_path: str = None) -> dict:
    """
    Predict the threat class for a single domain name string.
    
    Returns:
        dict: {
            'domain': str,
            'predicted_class': str,
            'probabilities': dict,
            'extracted_features': dict
        }
    """
    global _model, _metadata
    if _model is None or _metadata is None:
        load_model(model_path, metadata_path)

    # 1. Extract features using exact same pipeline
    features_dict = extract_features_from_domain(domain_str)
    
    # 2. Arrange features in exact column order expected by model
    feature_names = _metadata['feature_names']
    feature_vector = pd.DataFrame([features_dict])[feature_names]

    # 3. Predict class and probabilities
    pred_class = _model.predict(feature_vector)[0]
    probs_array = _model.predict_proba(feature_vector)[0]
    classes = list(_model.classes_)
    
    probabilities = {cls: float(round(prob, 4)) for cls, prob in zip(classes, probs_array)}

    return {
        'domain': domain_str,
        'predicted_class': pred_class,
        'probabilities': probabilities,
        'extracted_features': features_dict
    }


if __name__ == "__main__":
    # Self-test predictions for sample domains from each class
    test_domains = [
        ("google.com", "Benign Sample"),
        ("chanceregretclubsurveyreport.com", "DGA Sample"),
        ("dnscat.0a1b2c3d4e5f.tunnel-domain.net", "DNS Tunnelling Sample")
    ]

    print("=== Testing Single Domain Prediction Pipeline ===")
    for domain, note in test_domains:
        result = predict_domain(domain)
        print(f"\nNote: {note}")
        print(f"Domain: {result['domain']}")
        print(f"Predicted Class: {result['predicted_class']}")
        print(f"Probabilities: {result['probabilities']}")
