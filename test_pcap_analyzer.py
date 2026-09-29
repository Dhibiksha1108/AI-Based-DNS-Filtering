import os
import sys

# Ensure UTF-8 printing on Windows console
sys.stdout.reconfigure(encoding='utf-8')

from src.pcap_analyzer import analyze_pcap

def run_pcap_test():
    pcap_file = os.path.join("data", "pcap", "sample_dns.pcap")
    print(f"=== Command-Line Test: Passive PCAP Analyzer ===")
    print(f"PCAP File: {pcap_file}")
    
    if not os.path.exists(pcap_file):
        print(f"Error: Test PCAP file not found at {pcap_file}")
        return

    # Analyze ALL unique domains present in PCAP offline capture
    report = analyze_pcap(pcap_file, max_domains=None)
    
    stats = report["statistics"]
    print("\n--- Summary Statistics ---")
    print(f"Total Packets                     : {stats['total_packets']}")
    print(f"Total DNS Packets                 : {stats['total_dns_packets']}")
    print(f"Total DNS Queries                 : {stats['total_dns_queries']}")
    print(f"Unique Queried Domains            : {stats['unique_queried_domains']}")
    print(f"Allowed Domains                   : {stats['allowed_domains']}")
    print(f"Blocked Domains                   : {stats['blocked_domains']}")
    print(f"  |- DGA Detections               : {stats['dga_detections']}")
    print(f"  |- DNS Tunnelling Detections    : {stats['dns_tunnelling_detections']}")
    print(f"  |- Threat Intelligence Hits    : {stats['threat_intelligence_detections']}")

    beh = report.get("behavioral_analysis", {})
    print("\n--- Behavioral DNS Analysis ---")
    print(f"Risk Level                        : {beh.get('risk_level')}")
    print(f"Tunnelling Score                  : {beh.get('tunnelling_score')}")
    print(f"Unique Domain Ratio               : {beh.get('unique_domain_ratio') * 100:.1f}%")
    print(f"Average Domain Length             : {beh.get('avg_domain_length')} chars")
    print(f"Average Subdomain Label Length     : {beh.get('avg_label_length')} chars (Max: {beh.get('max_label_length')})")
    print(f"Average Character Entropy         : {beh.get('avg_entropy')} bits")
    print(f"High Long-Label Query Ratio       : {beh.get('high_long_label_ratio') * 100:.1f}%")
    print(f"Top Parent Domain                 : {beh.get('top_parent_domain')} ({beh.get('parent_domain_concentration') * 100:.1f}% concentration)")
    print(f"Explanation                       : {beh.get('explanation')}")

    print("\n--- Sample Domain Results (Top 10) ---")
    for idx, item in enumerate(report["domain_results"][:10], 1):
        print(f"{idx:2d}. Domain: {item['domain']}")
        print(f"    Status: {item['final_status']} | Reason: {item['reason']}")
        print(f"    ML Class: {item['ml_prediction']['class']} | TI Hit: {item['threat_intelligence']['known_malicious']}")

if __name__ == "__main__":
    run_pcap_test()
