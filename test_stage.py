import os
from src.predict import predict_domain
from src.threat_intelligence import check_domain, load_threat_feed

def run_verification():
    print("=== 1. Threat Intelligence Verification ===")
    feed = load_threat_feed()
    print(f"Loaded indicators count: {len(feed)}")
    assert len(feed) > 0, "Error: Threat feed is empty!"
    
    # Test known malicious domain from feed
    real_malicious_domain = list(feed)[0]
    ti_malicious_res = check_domain(real_malicious_domain)
    print("Real Indicator Check:")
    print(ti_malicious_res)
    assert ti_malicious_res["known_malicious"] == True
    assert ti_malicious_res["status"] == "known_malicious"
    
    # Test domain normalization (uppercase + trailing dot)
    norm_res = check_domain(real_malicious_domain.upper() + ".")
    print("Normalization Check:")
    print(norm_res)
    assert norm_res["known_malicious"] == True
    assert norm_res["normalized_domain"] == real_malicious_domain
    
    # Test benign domain (google.com)
    ti_benign_res = check_domain("google.com")
    print("Benign Domain Check:")
    print(ti_benign_res)
    assert ti_benign_res["known_malicious"] == False
    assert ti_benign_res["status"] == "not_found"
    
    print("\n=== 2. Existing ML Pipeline Verification ===")
    ml_res = predict_domain("google.com")
    print("ML Prediction for 'google.com':")
    print(f"Predicted Class: {ml_res['predicted_class']}")
    print(f"Probabilities: {ml_res['probabilities']}")
    assert ml_res['predicted_class'] == "Benign"
    
    print("\nAll Verification Checks Passed Successfully!")

if __name__ == "__main__":
    run_verification()
