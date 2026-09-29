# AI-Based DNS Filtering Using Threat Intelligence & Machine Learning

An intelligent DNS security system that analyzes domain queries using **Threat Intelligence, Machine Learning, and DNS traffic analysis** to identify potentially malicious domains and make automated **ALLOW / BLOCK** security decisions.

The system combines a **Random Forest classifier** with the **URLhaus threat-intelligence feed** and additional DNS tunnelling/PCAP analysis capabilities.

---

## 🚀 Live Demo

### 🌐 Web Application

**https://ai-based-dns-filtering.onrender.com**

### 📚 API Documentation

**https://ai-based-dns-filtering.onrender.com/docs**

The application is deployed as a live FastAPI web service using Render.

---

## 🎯 Project Objective

Traditional DNS filtering systems often rely on static blocklists. This project extends that approach by combining:

* Threat Intelligence
* Machine Learning
* Domain Feature Extraction
* DNS Tunnelling Detection
* PCAP Analysis
* Automated Security Decision Rules

The goal is to analyze DNS/domain queries and provide an explainable security decision rather than relying only on a predefined blacklist.

---

## ✨ Key Features

### 🛡️ Threat Intelligence Detection

Integrates the **URLhaus threat-intelligence feed by abuse.ch** to identify known malicious domains.

The system supports:

* Exact domain matching
* Parent-domain matching
* Domain normalization
* Local threat-intelligence lookup

### 🤖 Machine Learning Classification

A **Random Forest Classifier** analyzes extracted domain characteristics and classifies domains into:

* `Benign`
* `DGA`
* `DNS Tunnelling`

The prediction pipeline also returns class probabilities to provide additional insight into the model's decision.

### 🔍 Domain Feature Extraction

The system extracts lexical and statistical characteristics from domain names before sending them to the trained ML model.

The same feature-extraction pipeline used during training is reused during prediction to maintain consistency.

### 🚨 Security Decision Engine

The final security decision combines Threat Intelligence and Machine Learning results.

Example decision flow:

```text
Domain Query
     │
     ▼
Domain Normalization
     │
     ├───────────────┐
     ▼               ▼
URLhaus TI       Feature Extraction
     │               │
     │               ▼
     │          Random Forest
     │               │
     └───────┬───────┘
             ▼
     Security Decision Engine
             │
       ┌─────┴─────┐
       ▼           ▼
     ALLOW        BLOCK
```

### 🌐 Web Dashboard

The project includes a browser-based dashboard where users can enter a domain and receive its security analysis.

The dashboard communicates with the FastAPI backend through REST APIs.

### 📡 DNS Tunnelling Detection

The project also includes DNS tunnelling detection functionality for identifying suspicious DNS communication patterns.

### 📦 PCAP Analysis

PCAP files can be analyzed to inspect DNS traffic and identify potentially suspicious DNS behaviour.

---

## 🧠 Machine Learning Pipeline

The ML workflow consists of:

```text
Dataset
   ↓
Data Preparation
   ↓
Feature Extraction
   ↓
Training Dataset
   ↓
Random Forest Classifier
   ↓
Model Evaluation
   ↓
Trained Model
   ↓
Domain Prediction
```

The trained model is stored in:

```text
models/dns_threat_classifier.pkl
```

Model metadata is stored in:

```text
models/model_metadata.json
```

---

## 🔎 Threat Intelligence

The project uses **URLhaus by abuse.ch** as its threat-intelligence source.

Local feed files:

```text
data/threat_intelligence/urlhaus_domains.txt
data/threat_intelligence/urlhaus_hosts.txt
```

When a domain is analyzed, the system:

1. Normalizes the domain.
2. Checks for an exact match.
3. Checks parent domains where applicable.
4. Returns the Threat Intelligence status.
5. Combines the result with the ML prediction.

---

## ⚙️ Security Decision Logic

The Security Decision Engine applies deterministic rules.

### BLOCK

A domain is blocked when:

* It is found in the Threat Intelligence feed.
* The ML model detects a DGA domain.
* The ML model detects DNS tunnelling.
* Another suspicious ML classification is returned.

### ALLOW

A domain is allowed when:

* It is not identified by the Threat Intelligence feed.
* The ML model classifies it as `Benign`.

The API also returns the reason for the final decision.

---

## 🔌 API Endpoints

### `GET /`

Serves the web dashboard.

### `GET /health`

Checks whether the service is running.

Example response:

```json
{
  "status": "healthy"
}
```

### `POST /analyze`

Analyzes a domain using the complete security engine.

Request:

```json
{
  "domain": "google.com"
}
```

The response contains:

* Original domain
* Normalized domain
* Threat Intelligence result
* ML prediction
* ML probabilities
* Final security status
* Decision reason

### Interactive API Documentation

The complete API can be tested through FastAPI Swagger documentation:

**https://ai-based-dns-filtering.onrender.com/docs**

---

## 🧪 Example Analysis

### Benign Domain

```text
Input:
google.com

Expected decision:
ALLOW
```

### DGA Domain

```text
Input:
chanceregretclubsurveyreport.com

Possible decision:
BLOCK

Reason:
ML detected a DGA-generated domain
```

### DNS Tunnelling Example

```text
Input:
dnscat.0a1b2c3d4e5f.tunnel-domain.net

Possible decision:
BLOCK

Reason:
ML detected a DNS tunnelling domain
```

The actual result depends on the trained model prediction and Threat Intelligence data available to the deployed application.

---

## 📊 Model Evaluation

The project includes model evaluation artifacts such as:

```text
models/confusion_matrix.png
models/feature_importances.csv
models/model_metadata.json
```

These files are used to inspect model performance and feature importance.

---

## 📁 Project Structure

```text
AI-Based-DNS-Filtering/
│
├── data/
│   ├── pcap/
│   └── threat_intelligence/
│
├── docs/
│   └── final_test_report.md
│
├── frontend/
│   ├── index.html
│   ├── script.js
│   └── style.css
│
├── models/
│   ├── dns_threat_classifier.pkl
│   ├── model_metadata.json
│   ├── confusion_matrix.png
│   └── feature_importances.csv
│
├── notebooks/
│   └── 01_dataset_exploration.ipynb
│
├── src/
│   ├── api.py
│   ├── dns_tunneling_detector.py
│   ├── feature_extraction.py
│   ├── pcap_analyzer.py
│   ├── predict.py
│   ├── security_engine.py
│   └── threat_intelligence.py
│
├── requirements.txt
├── train_and_evaluate.py
├── prepare_dns_threats_dataset.py
├── process_dataset_features.py
├── test_all_modules.py
├── test_api_endpoints.py
├── test_dashboard.py
├── test_dns_tunneling_detector.py
├── test_pcap_analyzer.py
└── README.md
```

---

## 🛠️ Technology Stack

| Category             | Technology            |
| -------------------- | --------------------- |
| Programming Language | Python                |
| API Framework        | FastAPI               |
| Machine Learning     | Scikit-learn          |
| ML Algorithm         | Random Forest         |
| Data Processing      | Pandas, NumPy         |
| Model Serialization  | Joblib                |
| DNS Analysis         | dnspython             |
| Threat Intelligence  | URLhaus / abuse.ch    |
| Packet Analysis      | Scapy                 |
| Frontend             | HTML, CSS, JavaScript |
| API Server           | Uvicorn               |
| Deployment           | Render                |
| Version Control      | Git & GitHub          |

---

## 💻 Run Locally

Clone the repository:

```bash
git clone https://github.com/Dhibiksha1108/AI-Based-DNS-Filtering.git
cd AI-Based-DNS-Filtering
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the FastAPI server:

```bash
uvicorn src.api:app --host 0.0.0.0 --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

---

## ☁️ Deployment

The application is deployed using **Render**.

Deployment configuration:

```text
Environment: Python
Build Command:
pip install -r requirements.txt

Start Command:
uvicorn src.api:app --host 0.0.0.0 --port $PORT
```

### Live Deployment

**https://ai-based-dns-filtering.onrender.com**

The deployed application provides the web dashboard and REST API from the same service.

---

## 🧪 Testing

The project contains automated and module-level testing for:

* API endpoints
* Dashboard functionality
* DNS tunnelling detection
* PCAP analysis
* Feature extraction
* Threat Intelligence
* Prediction pipeline
* Complete security engine

Test files include:

```text
test_all_modules.py
test_api_endpoints.py
test_dashboard.py
test_dns_tunneling_detector.py
test_pcap_analyzer.py
test_stage.py
```

Detailed test results are available in:

```text
docs/final_test_report.md
```

---

## 🔐 Security Architecture

The system follows a layered detection approach:

```text
                 DNS DOMAIN
                      │
                      ▼
             Domain Normalization
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
 Threat Intelligence        ML Feature Extraction
      (URLhaus)                      │
          │                          ▼
          │                   Random Forest
          │                          │
          └───────────┬──────────────┘
                      ▼
             Security Engine
                      │
               ┌──────┴──────┐
               ▼             ▼
            ALLOW           BLOCK
```

This layered architecture allows known threats to be detected through Threat Intelligence while unknown or previously unseen patterns can be evaluated by the Machine Learning model.

---

## 🚀 Future Enhancements

Potential future improvements include:

* Real-time DNS traffic interception
* Automatic DNS query monitoring
* Expanded threat-intelligence sources
* Continuous model retraining
* Real-time threat feed updates
* Advanced DNS tunnelling detection
* Authentication and user management
* Security event logging
* Historical domain analysis
* Interactive analytics dashboard
* Containerized deployment using Docker

---

## 👩‍💻 Project

**AI-Based DNS Filtering Using Threat Intelligence & Machine Learning**

Developed as a cybersecurity and machine-learning project combining:

**Threat Intelligence + Machine Learning + DNS Security + Web API + Network Analysis**

### 🔗 Project Links

🌐 **Live Demo:**
https://ai-based-dns-filtering.onrender.com

📚 **API Documentation:**
https://ai-based-dns-filtering.onrender.com/docs

💻 **GitHub Repository:**
https://github.com/Dhibiksha1108/AI-Based-DNS-Filtering
