
#  AI-Powered Log Anomaly Detection

A practical cybersecurity project that simulates a small organizational environment with **central log collection**, **AI-based anomaly detection**, and an interactive dashboard built in Python (Dash + Plotly).

---

##  Overview

This project demonstrates end-to-end security monitoring inside a simulated organization.
Security logs from Windows machines are collected in real time, processed using **Artificial Intelligence**, and visualized through an interactive dashboard.

Environment includes:

* **Windows Server 2022** — Domain Controller (`orgnet.local`)
* **Windows 11 PC1 & PC2** — Employee workstations
* **Ubuntu** — Log Collector + AI Engine + Dashboard Host

Logs flow from Windows → NXLog → Ubuntu → Python ML Pipeline → Dashboard.

---

##  AI System

The core of the project is the **AI anomaly detection engine** built using Isolation Forest.

###  AI Workflow

```
Raw Windows Logs
        ↓
Data Cleaning & Normalization
        ↓
Feature Extraction
        ↓
Isolation Forest (Unsupervised ML)
        ↓
AI Tags + Severity Levels
        ↓
Dashboard Alerts
```

###  Model Output

| Field           | Meaning                            |
| --------------- | ---------------------------------- |
| `anomaly_score` | -1 = anomaly, 1 = normal           |
| `severity`      | High / Medium / Low                |
| `ai_tag`        | Category assigned based on EventID |

###  Event Categories

* Failed Authentication
* Process Creation
* Privilege Escalation
* Credential Access
* Policy / Service Changes
* Suspicious Network Activity

AI + rule-based mapping = hybrid detection engine.

---

##  Architecture

```
Windows 11 PC1 -----\
                      \
                       ➜ NXLog ➜ Ubuntu (Collector + AI + Dashboard)
                      /
Windows 11 PC2 -----/

Windows Server 2022 ➜ AD + DNS + Security Logs
```

---

##  Features

* Real-time log ingestion (UDP → JSON)
* AI anomaly detection (Isolation Forest)
* EventID categorization
* Intelligent alerting
* Severity & risk scoring
* Device / time-range / severity filtering
* Unified dataset (JSON + CSV merged)
* Modern dashboard UI
* Data visualization with Plotly

---

##  Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/AI-Powered-Log-Anomaly-Detection.git
cd AI-Powered-Log-Anomaly-Detection
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

---

##  Run the Log Collector

```bash
python3 log_collector.py
```

Logs will be stored in:

```
received_logs.json
```

Ensure NXLog sends logs to Ubuntu on port **5050**.

---

## 📊 Run the Dashboard

```bash
python3 dashboard.py
```

Dashboard opens at:

```
http://0.0.0.0:8050
```

---

##  Project Structure

```
/AI-Powered-Log-Anomaly-Detection
 ├── dashboard.py
 ├── log_collector.py
 ├── devices.json
 ├── eventlog.csv
 ├── received_logs.json
 ├── requirements.txt
 └── README.md
```

---

##  Roadmap

* Add Sysmon logs
* Add Elasticsearch + Kibana integration
* Add Slack/Email alerting
* Add deep learning sequence models
* Add automatic response capabilities (SOAR)
* Create Windows agent installer


---

##  Author

**Arjanit Pronaj**
Cybersecurity — AAB College
Project: *AI-Based Anomaly Detection in Organizational Infrastructure*


