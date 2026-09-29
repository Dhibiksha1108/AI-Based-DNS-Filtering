"""
DNS Threat Intelligence & Machine Learning
Module: Security Decision / Risk Engine

This module combines Threat Intelligence indicators (URLhaus) and ML classification
(Random Forest) to make deterministic ALLOW / BLOCK security decisions for DNS queries.
"""

import os
import sys

# Ensure project root is in Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.threat_intelligence import check_domain, normalize_domain
from src.predict import predict_domain


def analyze_domain(domain_str: str) -> dict:
    """
    Analyze a domain name using both Threat Intelligence lookups and ML classification.
    
    Returns:
        dict: Structured security analysis report including TI result, ML prediction,
              ML probabilities, final_status ('ALLOW' or 'BLOCK'), and decision reason.
    """
    # Step 1: Normalize domain
    norm_domain = normalize_domain(domain_str)

    # Step 2: Check Threat Intelligence Feed (URLhaus)
    ti_result = check_domain(domain_str)

    # Step 3: Run ML Classification Pipeline (Random Forest)
    ml_result = predict_domain(domain_str)

    ti_malicious = ti_result.get("known_malicious", False)
    ml_class = ml_result.get("predicted_class", "Benign")
    ml_probs = ml_result.get("probabilities", {})

    # Step 4: Apply Deterministic Security Decision Rules
    if ti_malicious:
        final_status = "BLOCK"
        reason = "Domain found in threat intelligence feed"
    elif ml_class == "DGA":
        final_status = "BLOCK"
        reason = "ML detected a DGA-generated domain"
    elif ml_class == "DNS Tunnelling":
        final_status = "BLOCK"
        reason = "ML detected a DNS tunnelling domain"
    elif ml_class == "Benign":
        final_status = "ALLOW"
        reason = "No known threat detected"
    else:
        final_status = "BLOCK"
        reason = f"ML flagged suspicious domain class '{ml_class}'"

    return {
        "domain": domain_str,
        "normalized_domain": norm_domain,
        "threat_intelligence": {
            "known_malicious": ti_result.get("known_malicious", False),
            "source": ti_result.get("source", "URLhaus by abuse.ch"),
            "status": ti_result.get("status", "not_found")
        },
        "ml_prediction": {
            "class": ml_class,
            "probabilities": ml_probs
        },
        "final_status": final_status,
        "reason": reason
    }


if __name__ == "__main__":
    from src.threat_intelligence import load_threat_feed

    print("=== Testing Security Decision Engine ===")
    ti_feed = load_threat_feed()
    sample_ti_indicator = list(ti_feed)[0] if ti_feed else "backupso.com"

    test_cases = [
        ("google.com", "Test 1: Benign Domain"),
        (sample_ti_indicator, "Test 2: Known TI Indicator"),
        ("chanceregretclubsurveyreport.com", "Test 3: DGA Malware Domain"),
        ("dnscat.0a1b2c3d4e5f.tunnel-domain.net", "Test 4: DNS Tunnelling Domain")
    ]

    for domain, test_name in test_cases:
        res = analyze_domain(domain)
        print(f"\n--- {test_name} ---")
        print(f"Domain            : {res['domain']}")
        print(f"TI Malicious      : {res['threat_intelligence']['known_malicious']} ({res['threat_intelligence']['status']})")
        print(f"ML Prediction     : {res['ml_prediction']['class']} (Probs: {res['ml_prediction']['probabilities']})")
        print(f"Final Decision    : {res['final_status']}")
        print(f"Reason            : {res['reason']}")
