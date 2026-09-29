"""
Unit Tests for Behavioral DNS Tunnelling Detector Module
"""

import sys
import os

# Add project root to sys.path
sys.path.append(os.path.dirname(__file__))

from src.dns_tunneling_detector import analyze_dns_behavior, calculate_entropy, get_parent_domain


def test_empty_input():
    res = analyze_dns_behavior([])
    assert res["analyzed_queries"] == 0
    assert res["unique_domains"] == 0
    assert res["tunnelling_score"] == 0.0
    assert res["risk_level"] == "LOW"
    print("[PASS] test_empty_input")


def test_normal_dns_behavior():
    normal_traffic = [
        {"domain": "google.com", "final_status": "ALLOW", "ml_prediction": {"class": "Benign"}},
        {"domain": "mail.google.com", "final_status": "ALLOW", "ml_prediction": {"class": "Benign"}},
        {"domain": "wikipedia.org", "final_status": "ALLOW", "ml_prediction": {"class": "Benign"}},
        {"domain": "github.com", "final_status": "ALLOW", "ml_prediction": {"class": "Benign"}},
        {"domain": "google.com", "final_status": "ALLOW", "ml_prediction": {"class": "Benign"}},
    ]
    res = analyze_dns_behavior(normal_traffic)
    assert res["analyzed_queries"] == 5
    assert res["unique_domains"] == 4
    assert res["risk_level"] in ("LOW", "MEDIUM")
    assert res["tunnelling_score"] < 0.60
    assert res["indicators"]["high_average_label_length"] is False
    print("[PASS] test_normal_dns_behavior")


def test_highly_unique_subdomain_behavior():
    # 60 unique subdomains under single parent domain
    unique_subdomains = [
        {"domain": f"client-payload-{i}.targetdomain.org", "final_status": "ALLOW", "ml_prediction": {"class": "Benign"}}
        for i in range(60)
    ]
    res = analyze_dns_behavior(unique_subdomains)
    assert res["unique_domains"] == 60
    assert res["indicators"]["high_unique_subdomain_ratio"] is True
    assert res["indicators"]["parent_domain_concentration"] is True
    assert res["tunnelling_score"] >= 0.40
    print("[PASS] test_highly_unique_subdomain_behavior")


def test_high_entropy_labels():
    high_entropy_traffic = [
        {"domain": f"x8f9z2k7m3q1p4v0w5u6-{i}.example.com", "final_status": "ALLOW", "ml_prediction": {"class": "Benign"}}
        for i in range(10)
    ]
    res = analyze_dns_behavior(high_entropy_traffic)
    assert res["avg_entropy"] > 3.5
    assert res["indicators"]["high_entropy"] is True
    print("[PASS] test_high_entropy_labels")


def test_long_labels():
    long_label_traffic = [
        {"domain": f"payload-{i}-" + "a" * 35 + ".tunnelingtest.net", "final_status": "BLOCK", "ml_prediction": {"class": "DNS Tunnelling"}}
        for i in range(15)
    ]
    res = analyze_dns_behavior(long_label_traffic)
    assert res["max_label_length"] >= 40
    assert res["indicators"]["high_average_label_length"] is True
    assert res["indicators"]["high_long_label_ratio"] is True
    assert res["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert res["tunnelling_score"] >= 0.50
    print("[PASS] test_long_labels")


if __name__ == "__main__":
    print("=== Running Unit Tests: Behavioral DNS Tunnelling Detector ===")
    test_empty_input()
    test_normal_dns_behavior()
    test_highly_unique_subdomain_behavior()
    test_high_entropy_labels()
    test_long_labels()
    print("ALL BEHAVIORAL DETECTOR UNIT TESTS PASSED SUCCESSFULLY!")
