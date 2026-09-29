import os
from src.feature_extraction import extract_features_from_domain
from src.predict import predict_domain
from src.threat_intelligence import check_domain, load_threat_feed
from src.security_engine import analyze_domain

def run_suite():
    print("=== Verification Suite: All Project Modules ===")
    
    print("\n1. Feature Extraction Module Test:")
    feat = extract_features_from_domain("google.com")
    print(f"Features for 'google.com': length={feat['domain_length']}, entropy={feat['character_entropy']}")
    assert feat['domain_length'] == 10
    
    print("\n2. ML Prediction Module Test:")
    ml_res = predict_domain("google.com")
    print(f"ML Class: {ml_res['predicted_class']} | Probs: {ml_res['probabilities']}")
    assert ml_res['predicted_class'] == "Benign"
    
    print("\n3. Threat Intelligence Module Test:")
    ti_feed = load_threat_feed()
    ti_res = check_domain("google.com")
    print(f"TI Check 'google.com': known_malicious={ti_res['known_malicious']}")
    assert ti_res['known_malicious'] == False
    
    print("\n4. Security Decision Engine Module Test:")
    sec_res = analyze_domain("google.com")
    print(f"Security Engine 'google.com': status={sec_res['final_status']} | reason={sec_res['reason']}")
    assert sec_res['final_status'] == "ALLOW"
    
    print("\nALL MODULE VERIFICATION CHECKS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_suite()
