"""
DNS Threat Intelligence & Machine Learning
Module: Behavioral DNS Tunnelling Detection

This module performs behavioral analysis across a sequence of DNS queries (e.g. extracted from PCAP).
While individual domain ML models classify single domains, this module analyzes collective traffic metrics:
- Subdomain uniqueness ratio
- Label length distribution & max label length
- Character entropy distribution
- Concentration under common parent domains
- High-digit / payload encoding ratio

It produces a transparent risk score (0.0 to 1.0), risk level (LOW, MEDIUM, HIGH, CRITICAL),
triggered indicators, and a human-readable explanation.
"""

import math
from collections import Counter
from typing import List, Dict, Any


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def get_parent_domain(domain_str: str) -> str:
    """Extract top-level parent domain (SLD + TLD, e.g. sub.example.com -> example.com)."""
    if not domain_str or not isinstance(domain_str, str):
        return ""
    parts = domain_str.strip().lower().split('.')
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return domain_str


def analyze_dns_behavior(domain_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze behavioral patterns across a collection of domain analysis results.
    
    Args:
        domain_results (List[Dict[str, Any]]): List of domain analysis dicts (each containing 'domain',
                                               'ml_prediction', 'final_status', etc.)
                                               
    Returns:
        Dict[str, Any]: Structured behavioral report.
    """
    if not domain_results:
        return {
            "analyzed_queries": 0,
            "unique_domains": 0,
            "unique_domain_ratio": 0.0,
            "suspicious_domains": 0,
            "avg_domain_length": 0.0,
            "max_domain_length": 0,
            "avg_label_length": 0.0,
            "max_label_length": 0,
            "avg_entropy": 0.0,
            "high_long_label_ratio": 0.0,
            "high_digit_ratio": 0.0,
            "top_parent_domain": "N/A",
            "parent_domain_concentration": 0.0,
            "tunnelling_score": 0.0,
            "risk_level": "LOW",
            "indicators": {
                "high_unique_subdomain_ratio": False,
                "high_average_label_length": False,
                "high_entropy": False,
                "parent_domain_concentration": False,
                "high_long_label_ratio": False
            },
            "explanation": "No DNS queries provided for behavioral analysis."
        }

    total_queries = 0
    domains_list = []
    suspicious_count = 0

    for item in domain_results:
        q_count = item.get("query_count_in_pcap", 1)
        d_name = item.get("domain", "") or item.get("normalized_domain", "")
        if d_name:
            domains_list.append(d_name)
            total_queries += q_count

        if item.get("final_status") == "BLOCK" or item.get("ml_prediction", {}).get("class") == "DNS Tunnelling":
            suspicious_count += 1

    if not domains_list:
        return analyze_dns_behavior([])

    unique_domains_set = set(domains_list)
    unique_domains_count = len(unique_domains_set)

    unique_domain_ratio = round(unique_domains_count / max(total_queries, 1), 4)

    domain_lengths = [len(d) for d in domains_list]
    avg_domain_len = round(sum(domain_lengths) / len(domain_lengths), 2)
    max_domain_len = max(domain_lengths)

    label_lengths = []
    entropies = []
    long_label_count = 0
    digit_ratio_count = 0

    parent_counter = Counter()

    for d in domains_list:
        parts = d.split('.')
        sub_labels = parts[:-2] if len(parts) > 2 else parts
        for lbl in sub_labels:
            lbl_len = len(lbl)
            label_lengths.append(lbl_len)
            if lbl_len > 25:
                long_label_count += 1

        ent = calculate_entropy(d)
        entropies.append(ent)

        digits = sum(1 for c in d if c.isdigit())
        if len(d) > 0 and (digits / len(d)) > 0.15:
            digit_ratio_count += 1

        parent = get_parent_domain(d)
        if parent:
            parent_counter[parent] += 1

    avg_label_len = round(sum(label_lengths) / max(len(label_lengths), 1), 2)
    max_label_len = max(label_lengths) if label_lengths else 0
    avg_entropy_val = round(sum(entropies) / len(entropies), 2)

    high_long_label_ratio = round(long_label_count / max(len(domains_list), 1), 4)
    high_digit_ratio = round(digit_ratio_count / max(len(domains_list), 1), 4)

    top_parent = "N/A"
    top_parent_count = 0
    if parent_counter:
        top_parent, top_parent_count = parent_counter.most_common(1)[0]
    parent_concentration = round(top_parent_count / len(domains_list), 4)

    score = 0.0
    indicators = {
        "high_unique_subdomain_ratio": False,
        "high_average_label_length": False,
        "high_entropy": False,
        "parent_domain_concentration": False,
        "high_long_label_ratio": False
    }

    reasons = []

    if unique_domain_ratio > 0.70 or unique_domains_count > 50:
        score += 0.25
        indicators["high_unique_subdomain_ratio"] = True
        reasons.append(f"High unique subdomain ratio ({unique_domain_ratio * 100:.1f}%) across queries")

    if avg_label_len > 20.0 or max_label_len > 35:
        score += 0.25
        indicators["high_average_label_length"] = True
        reasons.append(f"Unusually long subdomain labels (avg: {avg_label_len} chars, max: {max_label_len} chars)")

    if avg_entropy_val > 3.75:
        score += 0.20
        indicators["high_entropy"] = True
        reasons.append(f"High character entropy in queried names (avg: {avg_entropy_val:.2f} bits)")

    if parent_concentration > 0.60 and len(domains_list) >= 5:
        score += 0.20
        indicators["parent_domain_concentration"] = True
        reasons.append(f"High query concentration ({parent_concentration * 100:.1f}%) under parent domain '{top_parent}'")

    if high_long_label_ratio > 0.30:
        score += 0.10
        indicators["high_long_label_ratio"] = True
        reasons.append(f"Significant proportion ({high_long_label_ratio * 100:.1f}%) of queries contain long payload labels (>25 chars)")

    final_score = round(min(score, 1.0), 2)

    if final_score >= 0.80:
        risk_level = "CRITICAL"
    elif final_score >= 0.60:
        risk_level = "HIGH"
    elif final_score >= 0.35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if reasons:
        explanation = f"Behavioral DNS analysis flagged {risk_level} risk of DNS Tunnelling (Score: {final_score}). Triggered indicators: " + "; ".join(reasons) + "."
    else:
        explanation = f"DNS query traffic pattern exhibits normal benign behavior (Risk Level: {risk_level}, Score: {final_score}). No DNS Tunnelling behavioral anomalies detected."

    return {
        "analyzed_queries": total_queries,
        "unique_domains": unique_domains_count,
        "unique_domain_ratio": unique_domain_ratio,
        "suspicious_domains": suspicious_count,
        "avg_domain_length": avg_domain_len,
        "max_domain_length": max_domain_len,
        "avg_label_length": avg_label_len,
        "max_label_length": max_label_len,
        "avg_entropy": avg_entropy_val,
        "high_long_label_ratio": high_long_label_ratio,
        "high_digit_ratio": high_digit_ratio,
        "top_parent_domain": top_parent,
        "parent_domain_concentration": parent_concentration,
        "tunnelling_score": final_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "explanation": explanation
    }


if __name__ == "__main__":
    res = analyze_dns_behavior([{"domain": "google.com", "final_status": "ALLOW", "ml_prediction": {"class": "Benign"}}])
    print("Self-test output:", res["risk_level"], res["tunnelling_score"])
