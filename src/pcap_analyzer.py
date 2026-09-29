"""
DNS Threat Intelligence & Machine Learning
Module: Passive PCAP DNS Analysis

This module performs offline passive analysis on PCAP packet capture files.
It extracts DNS query domain names using Scapy and processes them through
the Security Decision Engine (Threat Intelligence + ML Random Forest).
"""

import os
import sys
import time
from collections import Counter

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.threat_intelligence import normalize_domain
from src.security_engine import analyze_domain

try:
    from scapy.utils import PcapReader
    from scapy.layers.dns import DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def analyze_pcap(pcap_path: str, max_domains: int = None, progress_interval: int = 2500) -> dict:
    """
    Analyze a PCAP file offline, extracting DNS query domain names and evaluating
    them using the existing Security Decision Engine.
    
    Args:
        pcap_path (str): Path to PCAP file.
        max_domains (int, optional): Max unique domains to analyze. Defaults to None (all domains).
        progress_interval (int): Print progress every N items. Defaults to 2500.

    Returns:
        dict: {
            "pcap_file": str,
            "statistics": dict,
            "domain_results": list
        }
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy library is not installed or available.")

    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found at path: '{pcap_path}'")

    print(f"1. Streaming PCAP file offline: {pcap_path}...")
    t_start = time.time()
    
    total_packets = 0
    total_dns_packets = 0
    total_dns_queries = 0

    domain_query_counts = Counter()
    raw_query_map = {}

    try:
        with PcapReader(pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                total_packets += 1
                if total_packets % 10000 == 0:
                    print(f"   [Progress] Scanned {total_packets} packets... ({time.time() - t_start:.1f}s)")

                if pkt.haslayer(DNS):
                    total_dns_packets += 1
                    dns_layer = pkt[DNS]
                    
                    # Check for DNS Query (qr == 0 indicates query)
                    if pkt.haslayer(DNSQR) and dns_layer.qr == 0:
                        total_dns_queries += 1
                        qname_raw = pkt[DNSQR].qname
                        
                        if qname_raw:
                            if isinstance(qname_raw, bytes):
                                qname_str = qname_raw.decode('utf-8', errors='ignore')
                            else:
                                qname_str = str(qname_raw)
                                
                            norm_domain = normalize_domain(qname_str)
                            
                            # Ignore empty domains or reverse IP lookups (.in-addr.arpa)
                            if norm_domain and not norm_domain.endswith('.arpa'):
                                domain_query_counts[norm_domain] += 1
                                if norm_domain not in raw_query_map:
                                    raw_query_map[norm_domain] = qname_str
    except Exception as e:
        raise ValueError(f"Failed to read or parse PCAP file '{pcap_path}'. Details: {str(e)}")

    all_unique_domains = list(domain_query_counts.keys())
    total_unique_found = len(all_unique_domains)
    
    if max_domains and max_domains < total_unique_found:
        unique_domains = all_unique_domains[:max_domains]
    else:
        unique_domains = all_unique_domains

    print(f"2. Extracted {total_packets} packets, {total_dns_packets} DNS packets, {total_dns_queries} queries.")
    print(f"3. Evaluating {len(unique_domains)} unique queried domains through Security Decision Engine...")
    
    domain_results = []
    allowed_count = 0
    blocked_count = 0
    dga_count = 0
    tunnel_count = 0
    ti_count = 0

    t_eval = time.time()
    num_to_eval = len(unique_domains)

    # Use fast vectorized batch evaluation for offline PCAP analysis
    from src.predict import load_model
    from src.feature_extraction import extract_features_from_domain
    from src.threat_intelligence import check_domain
    import pandas as pd

    model, metadata = load_model()
    feature_names = metadata['feature_names']
    classes = list(model.classes_)

    batch_size = progress_interval
    for start_idx in range(0, num_to_eval, batch_size):
        end_idx = min(start_idx + batch_size, num_to_eval)
        batch_domains = unique_domains[start_idx:end_idx]

        # 1. Extract features for batch
        batch_features = [extract_features_from_domain(d) for d in batch_domains]
        df_batch = pd.DataFrame(batch_features)[feature_names]

        # 2. Batch ML predict and predict_proba
        batch_preds = model.predict(df_batch)
        batch_probs = model.predict_proba(df_batch)

        # 3. Combine with TI and apply exact Security Decision rules
        for i, norm_domain in enumerate(batch_domains):
            ti_res = check_domain(norm_domain)
            ti_malicious = ti_res.get("known_malicious", False)

            ml_class = str(batch_preds[i])
            probs_dict = {cls: float(round(prob, 4)) for cls, prob in zip(classes, batch_probs[i])}

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

            analysis = {
                "domain": norm_domain,
                "normalized_domain": norm_domain,
                "threat_intelligence": {
                    "known_malicious": ti_malicious,
                    "source": ti_res.get("source", "URLhaus by abuse.ch"),
                    "status": ti_res.get("status", "not_found")
                },
                "ml_prediction": {
                    "class": ml_class,
                    "probabilities": probs_dict
                },
                "final_status": final_status,
                "reason": reason,
                "query_count_in_pcap": domain_query_counts[norm_domain],
                "raw_query": raw_query_map.get(norm_domain, norm_domain)
            }

            domain_results.append(analysis)

            if final_status == "BLOCK":
                blocked_count += 1
                if ti_malicious:
                    ti_count += 1
                if ml_class == "DGA":
                    dga_count += 1
                elif ml_class == "DNS Tunnelling":
                    tunnel_count += 1
            else:
                allowed_count += 1

        elapsed = time.time() - t_eval
        pct = (end_idx / num_to_eval) * 100
        print(f"   [Progress] Evaluated {end_idx}/{num_to_eval} domains ({pct:.1f}%) in {elapsed:.1f}s...")

    statistics = {
        "total_packets": total_packets,
        "total_dns_packets": total_dns_packets,
        "total_dns_queries": total_dns_queries,
        "unique_queried_domains": len(unique_domains),
        "allowed_domains": allowed_count,
        "blocked_domains": blocked_count,
        "dga_detections": dga_count,
        "dns_tunnelling_detections": tunnel_count,
        "threat_intelligence_detections": ti_count
    }

    # 4. Perform Behavioral DNS Analysis across all queries
    print("4. Running Behavioral DNS Tunnelling Analysis across query sequence...")
    from src.dns_tunneling_detector import analyze_dns_behavior
    behavioral_report = analyze_dns_behavior(domain_results)

    report = {
        "pcap_file": pcap_path,
        "statistics": statistics,
        "domain_results": domain_results,
        "behavioral_analysis": behavioral_report
    }

    return report


if __name__ == "__main__":
    sample_pcap = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "pcap", "sample_dns.pcap"))
    print("=== Testing Passive PCAP Analysis Module ===")
    if os.path.exists(sample_pcap):
        res = analyze_pcap(sample_pcap, max_domains=None)
        print("\nStatistics:")
        for k, v in res["statistics"].items():
            print(f"  {k:<32}: {v}")
        print("\nSample Analyzed Domains:")
        for item in res["domain_results"][:5]:
            print(f"  Domain: {item['domain']:<35} | Status: {item['final_status']:<5} | Reason: {item['reason']}")
    else:
        print(f"Sample PCAP file not found at {sample_pcap}. Run download_test_pcap.py first.")
