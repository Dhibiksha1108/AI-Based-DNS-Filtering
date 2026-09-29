# AI-Based DNS Filtering Using Threat Intelligence and Machine Learning

Inspired by SIH problem statement SIH260003.

## Overview
This project focuses on building a machine learning, threat intelligence, and network analysis solution for detecting and classifying DNS-based security threats in network traffic.

## Current Objective
- **Objective**: ML-based DNS threat classification, Threat Intelligence integration, Security Decision Engine, FastAPI Backend API, Web Dashboard & Passive PCAP Analysis
- **Planned Target Classes**:
  - `Benign`: Normal/safe DNS queries
  - `DGA`: Domain Generation Algorithm generated domains
  - `DNS Tunnelling`: Malicious data exfiltration or command-and-control over DNS
- **Current Stage**: Passive PCAP Analysis (Offline Scapy Packet Processing)

## Project Structure
```
DNS-Threat-Intelligence-ML/
│
├── data/
│   ├── dns_threats_dataset.csv       # Raw multiclass DNS dataset (12,168 rows)
│   ├── dns_threats_features.csv      # Feature-engineered dataset (16 columns)
│   ├── train_combined_multiclass.csv # 80% train split
│   ├── test_combined_multiclass.csv  # 20% test split
│   ├── threat_intelligence/          # Threat intelligence feeds directory
│   │   ├── urlhaus_hosts.txt         # Original downloaded URLhaus host file
│   │   └── urlhaus_domains.txt       # Processed malicious domain list (357 indicators)
│   └── pcap/                         # Test PCAP files directory
│       └── sample_dns.pcap           # Official sample DNS traffic PCAP (5.86 MB)
│
├── frontend/                         # Web Dashboard UI Files
│   ├── index.html                    # Dashboard main HTML page
│   ├── style.css                     # Responsive dashboard styling
│   └── script.js                     # Frontend HTTP API interaction logic
│
├── models/
│   ├── dns_threat_classifier.pkl     # Trained Random Forest Classifier (86.94% accuracy)
│   ├── model_metadata.json           # Model metadata and feature column ordering
│   └── confusion_matrix.png          # Evaluation confusion matrix plot
│
├── notebooks/
│   └── 01_dataset_exploration.ipynb # Notebook covering EDA, ML, Security Engine & PCAP Analysis
│
├── src/
│   ├── __init__.py                   # Package initialization
│   ├── feature_extraction.py          # 12 numerical lexical feature extraction functions
│   ├── predict.py                    # Single-domain ML prediction pipeline
│   ├── threat_intelligence.py        # Standalone threat intelligence lookup module
│   ├── security_engine.py            # Security Decision Engine combining TI & ML
│   ├── api.py                        # FastAPI Backend Application serving API & Dashboard
│   └── pcap_analyzer.py              # Offline Scapy PCAP DNS packet analyzer
│
├── download_test_pcap.py             # Script to download test PCAP dataset
├── fetch_threat_intelligence.py      # Script to update/download URLhaus threat feed
├── process_dataset_features.py       # Script to extract features into CSV
├── train_and_evaluate.py             # Script to train and evaluate ML model
├── test_all_modules.py               # Complete project module test suite
├── test_api_endpoints.py             # HTTP API verification script
├── test_dashboard.py                 # Web Dashboard HTTP serving test script
├── test_pcap_analyzer.py             # Command-line PCAP analyzer test script
└── README.md                         # Project documentation & roadmap
```

## Passive PCAP Analysis
### What PCAP Analysis Means in This Project
PCAP (Packet Capture) analysis allows network administrators and security analysts to evaluate pre-recorded network traffic captures offline. The analyzer extracts DNS queries from PCAP files and passes each queried domain through our Security Decision Engine (`src/security_engine.py`) to identify threats without capturing live traffic.

### Why PCAP Analysis is Useful for DNS Security
- **Offline Forensic Auditing**: Allows security teams to inspect historical network traffic captures to detect past exfiltration or infection events.
- **Bulk Query Inspection**: Evaluates hundreds or thousands of DNS domain queries in a single automated scan.
- **Zero Risk**: Operates 100% offline without sending packets or generating active network traffic.

### How to Run the PCAP Analyzer
Run the command-line test script:
```bash
python test_pcap_analyzer.py
```

Or invoke programmatically:
```python
from src.pcap_analyzer import analyze_pcap

report = analyze_pcap("data/pcap/sample_dns.pcap")
print(report["statistics"])
```

### Statistics Produced
- `total_packets`: Total packet count in PCAP
- `total_dns_packets`: Total DNS layer packets
- `total_dns_queries`: Total DNS Query (DNSQR) packets
- `unique_queried_domains`: Count of unique normalized domain names
- `allowed_domains`: Count of clean domains (`ALLOW`)
- `blocked_domains`: Count of threat domains (`BLOCK`)
- `dga_detections`: Count of ML DGA blocks
- `dns_tunnelling_detections`: Count of ML DNS Tunnelling blocks
- `threat_intelligence_detections`: Count of Threat Intelligence feed hits

## Behavioral DNS Tunnelling Detection
### Why Individual-Domain Classification is Not Enough
Single-domain ML models evaluate each domain string in isolation. However, sophisticated attackers using DNS Tunnelling (such as `dnscat2`, `iodine`, or custom data exfiltration tools) split sensitive data into dozens or thousands of subdomains under a common controlled parent domain. While individual subdomains might occasionally bypass lexical single-domain thresholds, examining the **collective behavior** across a sequence of queries reveals undeniable exfiltration patterns.

### Behavioral Indicators Examined
1. **Unique Subdomain Ratio**: Proportion of queried subdomains that are unique (`unique_domains / total_queries`). Tunnelling traffic exhibits near 100% uniqueness due to unique data payload chunks.
2. **Average & Max Label Length**: Length of individual subdomain labels. Tunnelling subdomains carry encoded payloads leading to unusually long labels (>25–60 chars).
3. **Character Entropy**: Shannon entropy of queried names measuring randomness/information density. Encoded payloads (Base32/Base64/hex) have higher entropy (>3.75 bits).
4. **Parent Domain Concentration**: Percentage of total queries concentrated under the same top-level parent domain (SLD + TLD). Tunnelling attacks flood queries toward a single C2 server domain.
5. **High Long-Label Query Ratio**: Percentage of queries containing payload labels longer than 25 characters.

### Scoring & Risk Level Mapping
The module computes a transparent risk score from **0.00 to 1.00**:
- **CRITICAL** (`score >= 0.80`): High-confidence DNS Tunnelling attack detected across traffic capture.
- **HIGH** (`0.60 <= score < 0.80`): Strong behavioral indicators of data exfiltration or C2 activity.
- **MEDIUM** (`0.35 <= score < 0.60`): Elevated anomaly levels requiring analyst inspection.
- **LOW** (`score < 0.35`): Normal benign DNS query traffic patterns.

*Note: Behavioral analysis operates strictly offline on PCAP packet capture files.*

## Web Dashboard
- **Main Dashboard**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **API Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

Command to start application:
```bash
python -m uvicorn src.api:app --host 127.0.0.1 --port 8000 --reload
```

## Security Decision Engine Rules
1. **RULE 1 (TI Block)**: If TI `known_malicious = True` -> `BLOCK` ("Domain found in threat intelligence feed").
2. **RULE 2 (ML DGA Block)**: If ML predicts `DGA` -> `BLOCK` ("ML detected a DGA-generated domain").
3. **RULE 3 (ML Tunnelling Block)**: If ML predicts `DNS Tunnelling` -> `BLOCK` ("ML detected a DNS tunnelling domain").
4. **RULE 4 (Clean Allow)**: If TI `known_malicious = False` AND ML predicts `Benign` -> `ALLOW` ("No known threat detected").

## Roadmap & Progress
1. **Dataset Preparation & Exploration** *(Completed)*
2. **Feature Engineering & Extraction** *(Completed)*
3. **Model Training & Evaluation (Random Forest)** *(Completed)*
4. **Threat Intelligence Integration** *(Completed)*
5. **Security Decision Engine** *(Completed)*
6. **Backend API Service** *(Completed)*
7. **Web Dashboard UI** *(Completed)*
8. **Passive PCAP DNS Analysis** *(Completed)*
9. **Behavioral DNS Tunnelling Detection** *(Completed)*
10. **Final Integration & Verification** *(Completed)*

## Project Status & Limitations
### Summary of Completed Components
- **Dataset**: Multiclass dataset containing 12,168 domain rows (Benign, DGA, DNS Tunnelling).
- **Feature Engineering**: 12 lexical numerical features extracted per domain.
- **ML Classifier**: Baseline Random Forest Model (`n_estimators=100`, `random_state=42`) achieving **86.94% multiclass test accuracy**.
- **Threat Intelligence**: Integrated URLhaus feed by abuse.ch (357 malicious domain indicators).
- **Security Engine**: Deterministic ALLOW/BLOCK rules combining TI lookups & ML predictions.
- **Backend API**: FastAPI HTTP server serving `/analyze` and `/health` endpoints.
- **Web Dashboard**: Interactive responsive web interface connected to FastAPI backend.
- **Passive PCAP Analysis**: Offline Scapy-based PCAP parser analyzing DNS captures without live traffic.
- **Behavioral Detector**: Multi-indicator scoring engine evaluating sequence metrics across DNS queries.

### Current Project Limitations & Scope Boundaries
- **Research Prototype**: This codebase is a college/research prototype developed for SIH260003 and is **not a production DNS security service**.
- **Baseline Model**: The ML classifier is a baseline Random Forest trained strictly on the selected 12,168 row dataset. Generalization to unseen malware families may vary.
- **Heuristic Behavioral Scoring**: Behavioral tunnelling detection uses rule-based heuristic indicators and calibrated thresholds rather than a dynamic sequence ML model (such as LSTM or Transformer).
- **Offline Analysis Only**: Packet capture processing is strictly offline using pre-recorded PCAP files.
- **Out of Scope Features**:
  - Live active DNS resolver deployment is **not implemented**.
  - DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT) decryption is **not implemented**.
  - High-throughput production streaming (e.g. DPDK, eBPF) is **not implemented**.
