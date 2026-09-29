# Final Integration & Test Report

**Project Title**: AI-Based DNS Filtering Using Threat Intelligence and Machine Learning  
**Inspired By**: SIH Problem Statement SIH260003  
**Date**: September 13, 2026  
**Overall Project Status**: **PASS WITH LIMITATIONS**

---

## 1. Test Environment
- **Operating System**: Windows 11
- **Python Version**: 3.14.0a4 (Virtual Environment: `venv`)
- **Core Dependencies**: `pandas`, `numpy`, `scikit-learn` (1.6.1), `joblib`, `fastapi` (0.115.8), `uvicorn`, `scapy` (2.7.0)
- **Local Application URL**: `http://127.0.0.1:8000/`

---

## 2. Dataset
- **Raw Dataset**: `data/dns_threats_dataset.csv` (12,168 rows)
- **Class Breakdown**:
  - `Benign`: 4,056 domains (33.33%)
  - `DGA`: 4,056 domains (33.33%)
  - `DNS Tunnelling`: 4,056 domains (33.33%)
- **Feature Dataset**: `data/dns_threats_features.csv` (12 lexical features + target class)
- **Data Splits**: 80% Train split (9,734 rows), 20% Test split (2,434 rows)

---

## 3. Machine Learning Model
- **Algorithm**: Random Forest Classifier (`n_estimators=100`, `random_state=42`)
- **Trained Model Artifact**: `models/dns_threat_classifier.pkl` (9.02 MB)
- **Metadata**: `models/model_metadata.json`
- **Evaluation Accuracy**: **86.94%** on unseen test split
- **Feature Count**: 12 numerical features (`domain_length`, `number_of_digits`, `digit_ratio`, `number_of_letters`, `number_of_special_characters`, `number_of_subdomains`, `vowel_count`, `consonant_count`, `vowel_ratio`, `consonant_ratio`, `unique_character_count`, `character_entropy`)

---

## 4. Unit Tests
- **Test File**: `test_all_modules.py`
- **Status**: **PASS (100%)**
- **Modules Verified**:
  - Feature Extraction (`extract_features_from_domain`)
  - ML Prediction (`predict_domain`)
  - Threat Intelligence (`check_domain`)
  - Security Decision Engine (`analyze_domain`)

---

## 5. API Tests
- **Test File**: `test_api_endpoints.py`
- **Status**: **PASS (100%)**
- **Verified Scenarios**:
  - `GET /` -> Status 200 (Dashboard HTML)
  - `GET /health` -> Status 200 (`{"status": "healthy"}`)
  - `GET /docs` -> Status 200 (OpenAPI documentation)
  - `POST /analyze` (Benign: `google.com`) -> Status 200, `ALLOW`
  - `POST /analyze` (TI Malicious: `bnet.playm8ru.win`) -> Status 200, `BLOCK`
  - `POST /analyze` (DGA Malware: `chanceregretclubsurveyreport.com`) -> Status 200, `BLOCK`
  - `POST /analyze` (DNS Tunnelling: `dnscat.0a1b2c3d4e5f.tunnel-domain.net`) -> Status 200, `BLOCK`

---

## 6. Dashboard Tests
- **Web UI Assets**: `frontend/index.html`, `frontend/style.css`, `frontend/script.js`
- **Status**: **PASS (100%)**
- **Verified Behavior**:
  - Main Page loads cleanly at `http://127.0.0.1:8000/`
  - Form submission triggers AJAX fetch to `/analyze`
  - Loading spinner displays during HTTP request
  - Results render status badge (Green `ALLOW` / Red `BLOCK`)
  - Threat Intelligence source and status displayed
  - ML Predicted Class and 3-class probability progress bars render correctly

---

## 7. PCAP Tests
- **Test File**: `test_pcap_analyzer.py`
- **PCAP Sample**: `data/pcap/sample_dns.pcap` (5.86 MB)
- **Status**: **PASS (100%)**
- **Metrics**:
  - Total Packets Scanned: `36,697`
  - DNS Query Packets Extracted: `18,525`
  - Unique Queried Domains Processed: `18,525`
  - Allowed Domains: `13,314`
  - Blocked Domains: `5,211` (100% ML DNS Tunnelling detections)

---

## 8. Behavioral Tunnelling Tests
- **Test File**: `test_dns_tunneling_detector.py` & `src/dns_tunneling_detector.py`
- **Status**: **PASS (100%)**
- **Sample Capture Behavioral Results (`sample_dns.pcap`)**:
  - Unique Subdomain Ratio: `100.0%`
  - Average Domain Length: `46.88` chars (Max: `115` chars)
  - Average Subdomain Label Length: `15.52` chars (Max: `63` chars)
  - Average Character Entropy: `3.63` bits
  - High Long-Label Ratio (>25 chars): `56.6%`
  - Top Parent Domain Concentration: `ggy666.tk` (`100.0%` concentration)
  - Behavioral Risk Score: **`0.80`**
  - Behavioral Risk Level: **`CRITICAL`**

---

## 9. Edge-Case Tests
- `google.com.` (trailing dot) -> Normalized to `google.com` (`ALLOW`, Status 200)
- `GOOGLE.COM` (uppercase) -> Normalized to `google.com` (`ALLOW`, Status 200)
- `mail.google.com` (subdomain) -> Evaluated cleanly (`ALLOW`, Status 200)
- `""` (empty string) -> HTTP Status 400 (`Invalid domain input`)
- `"   "` (whitespace string) -> HTTP Status 400 (`Invalid domain input`)
- `{}` (missing domain body field) -> HTTP Status 422 (`Field required`)

---

## 10. Performance Observations
- **Single-Domain API Latency**: **~55.87 ms** (local HTTP roundtrip + ML feature extraction + TI lookup + Security decision)
- **PCAP File Parsing (36,697 packets)**: **~35.8 seconds** (Scapy streaming reader)
- **PCAP Domain Evaluation (18,525 unique domains)**: **~6.7 seconds** (Vectorized batch feature DataFrame prediction)
- **Behavioral Analysis**: **~0.05 seconds**

---

## 11. Known Project Limitations
1. **Baseline ML Model**: The Random Forest model is trained on a specific 12,168 row dataset and achieves 86.94% accuracy. It serves as a baseline prototype.
2. **Heuristic Behavioral Scoring**: The behavioral DNS detector utilizes rule-based heuristic indicator thresholds rather than a dynamic sequence deep learning model (e.g. LSTM/Transformer).
3. **Offline Packet Processing Only**: Network capture analysis operates strictly on pre-recorded PCAP files; live active packet capture is not included.
4. **Research Prototype Scope**: Live active DNS resolver deployment, DoH/DoT handling, and enterprise streaming pipelines (e.g., eBPF/DPDK) are out of scope.

---

## 12. Final Conclusion
The project **"AI-Based DNS Filtering Using Threat Intelligence and Machine Learning"** successfully integrates all 9 core development stages into a cohesive, fully functional software prototype. All automated module unit tests, HTTP API verification scripts, PCAP batch processing pipelines, and behavioral detection suites pass with **100% success**.
