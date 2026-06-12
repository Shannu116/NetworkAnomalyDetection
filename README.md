# 🛡️ Network Anomaly Detection System

**ML-Powered Real-Time Network Intrusion Detection with Live Packet Capture & SIEM Integration**

A complete end-to-end network anomaly detection system that captures **real network traffic** from live interfaces using Scapy, extracts flow-based features, and classifies them in real time using machine learning. Includes a dark-themed cybersecurity dashboard, SIEM-compatible logging (Splunk/CEF), and a full ML training pipeline benchmarking 7 algorithms across 2 industry-standard datasets.

---

## 📑 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Techniques](#-techniques--methodology)
- [Project Structure](#-project-structure)
- [Model Performance](#-model-performance)
- [Datasets](#-datasets)
- [Installation](#-installation)
- [Usage](#-usage)
- [Dashboard](#-dashboard)
- [SIEM Integration](#-siem-integration--splunk)
- [API Endpoints](#-api-endpoints)
- [Tech Stack](#-tech-stack)

---

## ✨ Features

### 🔴 Real-Time Live Detection
- **Real packet capture** from actual network interfaces (wlan0, eth0, etc.) using Scapy
- Bidirectional **flow tracking** — groups packets into flows and extracts 42 ML features
- Real TCP window sizes, sequence numbers, SYN→ACK RTT, jitter, inter-arrival times
- Connection tracking counters (ct_srv_src, ct_dst_ltm, ct_state_ttl, etc.)
- Automatic service detection from port numbers (HTTP, SSH, DNS, SSL, FTP, etc.)
- TCP state inference from flags (CON, FIN, RST, REQ, ACC, INT)

### 🤖 Machine Learning Pipeline
- **7 models** trained and benchmarked: XGBoost, LightGBM, Random Forest, Gradient Boosting, Decision Tree, KNN, Logistic Regression
- **2 datasets**: UNSW-NB15 and CIC-IDS-2017
- Automatic **best model selection** based on F1-score
- StandardScaler normalization + Label encoding for categorical features
- SMOTE-based class balancing for imbalanced datasets
- Generates confusion matrices, ROC curves, feature importance, and model comparison plots

### 🎯 False Alert Reduction
- **Confidence threshold gating** — only flags anomalies above 65% confidence
- **Benign traffic whitelisting** — skips multicast, mDNS, NTP, SSDP
- Minimum flow quality requirements (≥5 packets, ≥1s duration)
- Proper feature extraction (real TCP windows, RTT, not hardcoded values)

### 📊 Live Cybersecurity Dashboard
- Dark-themed real-time dashboard via FastAPI + WebSocket
- Live detection feed with severity badges (CRITICAL / HIGH / MEDIUM / LOW)
- Real-time charts: anomaly timeline, severity distribution, protocol breakdown
- Model training results & analysis plots viewer
- Interface selector for switching capture targets
- One-click Start/Stop detection controls

### 📝 SIEM-Compatible Logging (Splunk / ArcSight / QRadar)
- **NDJSON format** — one JSON event per line, native Splunk `_json` sourcetype
- **CEF format** — Common Event Format for ArcSight / QRadar
- Follows **Splunk Common Information Model (CIM)** field naming
- Separate alert-only log file for high-priority event pipelines
- Rotating log files (10 MB × 20 backups ≈ 200 MB max)
- Download logs via REST API

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Network Interface                     │
│                   (wlan0 / eth0 / ...)                   │
└──────────────────────┬──────────────────────────────────┘
                       │ Raw Packets (Scapy)
                       ▼
┌──────────────────────────────────────────────────────────┐
│              Live Packet Capture Engine                   │
│  ┌────────────────────────────────────────────────────┐  │
│  │  FlowTracker: Bidirectional flow grouping          │  │
│  │  → 42 UNSW-NB15 features per flow                 │  │
│  │  → TCP window, seq#, RTT, jitter, IAT             │  │
│  │  → Connection tracking counters                    │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────┬───────────────────────────────────┘
                       │ Feature Dict
                       ▼
┌──────────────────────────────────────────────────────────┐
│              Anomaly Detector                            │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Label Encode │→ │ StandardScale│→ │  XGBoost Model │  │
│  │ (proto,svc,  │  │ (42 features)│  │  predict()     │  │
│  │  state)      │  │              │  │  predict_proba │  │
│  └─────────────┘  └──────────────┘  └────────────────┘  │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ Confidence Gate (≥0.65) + Whitelist Filter          │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────┬─────────────────────────┬─────────────────┘
               │                         │
               ▼                         ▼
┌──────────────────────┐   ┌─────────────────────────────┐
│   SIEM Logger        │   │   FastAPI + WebSocket        │
│  • JSON (Splunk)     │   │  • REST API                  │
│  • CEF (ArcSight)    │   │  • Real-time dashboard       │
│  • Rotating files    │   │  • Live detection feed       │
└──────────────────────┘   └─────────────────────────────┘
```

---

## 🔬 Techniques & Methodology

### Data Preprocessing Pipeline

| Step | Technique | Details |
|------|-----------|---------|
| **Missing Values** | Median imputation (numeric), Mode imputation (categorical) | Handles NaN and Inf values across all features |
| **Infinity Handling** | Replace `±inf` → `NaN` → impute | Prevents scaler and model crashes on infinite values |
| **Encoding** | `LabelEncoder` (scikit-learn) | Converts categorical strings to integer codes |
| **Scaling** | `StandardScaler` (z-score normalization) | Fit on training set only, transform both train & test to prevent data leakage |
| **Class Balancing** | `SMOTE` (Synthetic Minority Oversampling Technique) | Generates synthetic minority class samples to balance the dataset |
| **Data Splitting** | Stratified train/test split (80/20) | Preserves class distribution ratio across splits |

### Encoding Details

**UNSW-NB15** — 3 categorical columns encoded via `LabelEncoder`:

| Column | Unique Classes | Example Values |
|--------|---------------|----------------|
| `proto` | 133 | tcp, udp, icmp, igmp, ospf, gre, sctp, ... |
| `service` | 13 | http, dns, ftp, ssh, ssl, smtp, dhcp, snmp, irc, pop3, radius, ftp-data, - |
| `state` | 11 | CON, FIN, RST, ACC, CLO, ECO, INT, PAR, REQ, URN, no |

**CIC-IDS-2017** — No categorical encoding needed (all features are numeric after dropping metadata columns: Flow ID, Source IP, Destination IP, Timestamp, Label).

### Feature Counts — Raw vs. Used

| Dataset | Raw Columns | Dropped | Final ML Features | Target |
|---------|-------------|---------|-------------------|--------|
| **UNSW-NB15** | 49 | 7 (`id`, `attack_cat`, + target) | **42** | `label` (binary: 0=Normal, 1=Anomaly) |
| **CIC-IDS-2017** | 85 | 8 (`Flow ID`, `Source IP`, `Dest IP`, `Source Port`, `Dest Port`, `Timestamp`, `Label`, + target) | **77** | `Label_binary` (BENIGN=0, Attack=1) |

### UNSW-NB15 — 42 Features Used (Deployed Model)

| Category | Features | Count |
|----------|----------|-------|
| **Flow basics** | `dur`, `rate`, `spkts`, `dpkts`, `sbytes`, `dbytes` | 6 |
| **Protocol info** | `proto`, `service`, `state` | 3 |
| **TTL & load** | `sttl`, `dttl`, `sload`, `dload` | 4 |
| **Loss & timing** | `sloss`, `dloss`, `sinpkt`, `dinpkt`, `sjit`, `djit` | 6 |
| **TCP internals** | `swin`, `dwin`, `stcpb`, `dtcpb`, `tcprtt`, `synack`, `ackdat` | 7 |
| **Packet stats** | `smean`, `dmean` | 2 |
| **HTTP/FTP** | `trans_depth`, `response_body_len`, `is_ftp_login`, `ct_ftp_cmd`, `ct_flw_http_mthd` | 5 |
| **Connection tracking** | `ct_srv_src`, `ct_state_ttl`, `ct_dst_ltm`, `ct_src_dport_ltm`, `ct_dst_sport_ltm`, `ct_dst_src_ltm`, `ct_src_ltm`, `ct_srv_dst` | 8 |
| **Flags** | `is_sm_ips_ports` | 1 |

### Live Feature Extraction Method

During real-time detection, features are **not read from a CSV** — they are **extracted from raw packets** captured by Scapy:

```
Raw Packets (Scapy sniff) → FlowTracker (bidirectional grouping) → 42 Features
```

| Extraction Technique | What It Computes |
|---------------------|------------------|
| **Bidirectional flow grouping** | Groups packets by 5-tuple `(src_ip, dst_ip, src_port, dst_port, proto)`, merges forward/reverse into one flow |
| **TCP header parsing** | Extracts real `window` size (`swin`/`dwin`), base sequence numbers (`stcpb`/`dtcpb`), and flag bits (SYN, ACK, FIN, RST, PSH, URG) |
| **TCP handshake timing** | Measures `synack` (SYN→SYN-ACK delay), `ackdat` (SYN-ACK→ACK delay), and `tcprtt` = synack + ackdat |
| **Inter-arrival time (IAT)** | Per-direction IAT arrays → computes `sinpkt` / `dinpkt` (mean IAT in ms) and `sjit` / `djit` (std dev = jitter) |
| **Byte statistics** | Per-direction byte arrays → `smean` / `dmean` (mean packet size), `sbytes` / `dbytes` (total bytes) |
| **Connection state inference** | Maps observed TCP flags → UNSW state labels: CON, FIN, RST, REQ, ACC, INT |
| **Service detection** | Maps well-known ports → service names: 80→http, 443→ssl, 22→ssh, 53→dns, etc. |
| **Connection tracking counters** | Running counters for `ct_srv_src`, `ct_dst_ltm`, `ct_src_dport_ltm`, etc. — tracks how many times a (service, src) pair or (dst, src) pair has been seen |
| **Flow emission criteria** | Flow emitted when: FIN×2 or RST seen (connection closed), timeout >15s (idle), or ≥5 packets and ≥1s duration |

### Model Selection Method

- All 7 models are trained on the **same** preprocessed data
- Evaluated on the **held-out test set** (no data leakage)
- **Best model selected automatically** by highest **F1-score**
- The best model + scaler + encoders + feature names are serialized via `joblib` for deployment
- During live inference: `LabelEncode → StandardScaler → model.predict_proba()` → confidence gating at ≥65%

---

## 📂 Project Structure

```
NetworkAnomalyDetection/
├── main.py                          # CLI entry point (preprocess/train/serve)
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
│
├── src/
│   ├── config.py                    # All configuration & paths
│   ├── preprocessing/
│   │   └── data_pipeline.py         # Dataset preprocessing (UNSW + CIC)
│   ├── models/
│   │   ├── trainer.py               # Train & benchmark 7 ML models
│   │   ├── detector.py              # Real-time anomaly detector
│   │   └── live_capture.py          # Scapy packet capture & flow tracking
│   ├── api/
│   │   └── server.py                # FastAPI backend + WebSocket
│   └── utils/
│       └── siem_logger.py           # SIEM-compatible JSON/CEF logger
│
├── templates/
│   └── dashboard.html               # Live cybersecurity dashboard
│
├── static/plots/                    # Auto-generated analysis plots
│   ├── confusion_unsw.png           # Confusion matrix (UNSW-NB15)
│   ├── confusion_cic.png            # Confusion matrix (CIC-IDS-2017)
│   ├── roc_unsw.png                 # ROC curves (UNSW-NB15)
│   ├── roc_cic.png                  # ROC curves (CIC-IDS-2017)
│   ├── features_unsw.png            # Feature importance (UNSW-NB15)
│   ├── features_cic.png             # Feature importance (CIC-IDS-2017)
│   ├── comparison_unsw.png          # Model comparison (UNSW-NB15)
│   └── comparison_cic.png           # Model comparison (CIC-IDS-2017)
│
├── data/
│   ├── raw/                         # Original datasets
│   │   ├── UNSW-NB15/
│   │   └── CIC-IDS-2017/
│   ├── processed/                   # Preprocessed datasets
│   └── models/                      # Saved model artifacts
│       ├── best_model_unsw.pkl      # Best model (XGBoost)
│       ├── best_model_cic.pkl       # Best model (LightGBM)
│       ├── scaler_unsw.pkl          # StandardScaler
│       ├── encoders_unsw.pkl        # Label encoders (proto/service/state)
│       ├── feature_names_unsw.pkl   # 42 feature names (ordered)
│       ├── results_unsw.json        # All model results (UNSW)
│       └── results_cic.json         # All model results (CIC)
│
└── logs/                            # SIEM-compatible log output
    ├── anomaly_detections.json      # All events (NDJSON / Splunk)
    ├── anomaly_alerts.json          # Anomaly-only alerts
    └── anomaly_detections.cef       # CEF format (ArcSight/QRadar)
```

---

## 📊 Model Performance

### UNSW-NB15 Dataset

| Model | Accuracy | Precision | Recall | F1-Score | ROC AUC | Train Time |
|-------|----------|-----------|--------|----------|---------|------------|
| **🏆 XGBoost** | **0.9498** | **0.9741** | **0.9466** | **0.9601** | **0.9924** | **11.74s** |
| Random Forest | 0.9490 | 0.9758 | 0.9436 | 0.9595 | 0.9921 | 35.64s |
| LightGBM | 0.9469 | 0.9723 | 0.9438 | 0.9579 | 0.9917 | 8.96s |
| Gradient Boosting | 0.9397 | 0.9668 | 0.9378 | 0.9521 | 0.9897 | 319.06s |
| Decision Tree | 0.9395 | 0.9772 | 0.9269 | 0.9514 | 0.9825 | 4.33s |
| KNN | 0.9118 | 0.9578 | 0.9017 | 0.9289 | 0.9698 | 0.02s |
| Logistic Regression | 0.8925 | 0.9269 | 0.9031 | 0.9148 | 0.9662 | 8.68s |

**Best Model: XGBoost** — F1-Score: 0.9601, AUC: 0.9924

### CIC-IDS-2017 Dataset

| Model | Accuracy | Precision | Recall | F1-Score | ROC AUC | Train Time |
|-------|----------|-----------|--------|----------|---------|------------|
| **🏆 LightGBM** | **0.9992** | **0.9974** | **0.9986** | **0.9980** | **1.0000** | **14.47s** |
| XGBoost | 0.9991 | 0.9970 | 0.9985 | 0.9978 | 1.0000 | 13.97s |
| Random Forest | 0.9985 | 0.9965 | 0.9958 | 0.9962 | 0.9999 | 83.10s |
| Gradient Boosting | 0.9981 | 0.9962 | 0.9940 | 0.9951 | 0.9998 | 735.85s |
| Decision Tree | 0.9977 | 0.9955 | 0.9928 | 0.9942 | 0.9981 | 18.19s |
| KNN | 0.9971 | 0.9912 | 0.9939 | 0.9926 | 0.9986 | 0.16s |
| Logistic Regression | 0.9271 | 0.8395 | 0.7792 | 0.8082 | 0.9776 | 33.44s |

**Best Model: LightGBM** — F1-Score: 0.9980, AUC: 1.0000

---

## 📦 Datasets

### UNSW-NB15
- **Source**: Australian Centre for Cyber Security (ACCS)
- **Records**: 175,341 training / 82,332 testing
- **Features**: 42 flow-based features (after preprocessing)
- **Attack types**: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms
- **Used for**: Live detection (XGBoost model deployed)

### CIC-IDS-2017
- **Source**: Canadian Institute for Cybersecurity
- **Records**: 2,830,743 total network flows
- **Features**: 78 flow-based features
- **Attack types**: Brute Force, Heartbleed, Botnet, DDoS, Web Attack, Infiltration, PortScan
- **Used for**: Benchmarking (LightGBM best performer)

---

## 🚀 Installation

### Prerequisites
- **Python** 3.10+
- **Linux** (packet capture uses raw sockets)
- **Root/sudo** access (required for Scapy live capture)

### Setup

```bash
# Clone the project
cd /path/to/project
cd NetworkAnomalyDetection

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Download Datasets

1. **UNSW-NB15**: Download from [UNSW Research](https://research.unsw.edu.au/projects/unsw-nb15-dataset) and place CSV files in `data/raw/UNSW-NB15/CSV Files/Training and Testing Sets/`

2. **CIC-IDS-2017**: Download from [UNB CIC](https://www.unb.ca/cic/datasets/ids-2017.html) and place CSV files in `data/raw/CIC-IDS-2017/`

---

## 💻 Usage

### Full Pipeline (Preprocess → Train → Serve)
```bash
sudo ./venv/bin/python main.py all
```

### Step-by-Step

#### 1. Preprocess Datasets
```bash
python main.py preprocess
```
Cleans both datasets, encodes categorical features, scales numerical features, and saves processed data.

#### 2. Train Models
```bash
python main.py train
```
Trains 7 ML models on both datasets, evaluates them, selects the best, and generates analysis plots.

#### 3. Start Live Detection Server
```bash
# Auto-detect network interface
sudo ./venv/bin/python main.py serve

# Specify interface
sudo ./venv/bin/python main.py serve --interface wlan0
```

> ⚠️ **Important**: Always use `sudo ./venv/bin/python` (full venv path) — plain `sudo python` uses the system Python which doesn't have the dependencies.

#### 4. Open Dashboard
Navigate to **http://localhost:8000** in your browser.

---

## 🖥️ Dashboard

The real-time cybersecurity dashboard includes:

| Section | Description |
|---------|-------------|
| **Live Detection Feed** | Real-time table showing every classified flow with severity, confidence, IPs, ports, protocol |
| **Anomaly Timeline** | Line chart of anomaly vs normal counts over time |
| **Severity Distribution** | Doughnut chart of CRITICAL / HIGH / MEDIUM / LOW alerts |
| **System Stats** | Total packets, anomaly rate, uptime, interface info |
| **Model Results** | Training metrics for all 7 models on both datasets |
| **Analysis Plots** | Confusion matrices, ROC curves, feature importance, model comparisons |
| **Interface Selector** | Dropdown to switch capture interface without restart |

---

## 📝 SIEM Integration — Splunk

### Log Files Generated

| File | Format | Content |
|------|--------|---------|
| `logs/anomaly_detections.json` | NDJSON | All detection events |
| `logs/anomaly_alerts.json` | NDJSON | Anomaly-only events |
| `logs/anomaly_detections.cef` | CEF | All events (ArcSight/QRadar) |

### Splunk Setup

1. **Add Data** → **Monitor** → **Files & Directories**
2. Point to the `logs/` directory
3. Set **Source type**: `_json`
4. Set **Index**: `network_security`

### Sample JSON Log Entry (Splunk CIM Fields)

```json
{
  "time": "2026-02-20 14:23:45.123",
  "_time": "2026-02-20T14:23:45.123456+00:00",
  "host": "archlinux",
  "source": "NetworkAnomalyDetection",
  "sourcetype": "nads:detection",
  "index": "network_security",
  "event_type": "anomaly_detection",
  "action": "ANOMALY",
  "severity": "HIGH",
  "severity_id": 8,
  "prediction": 1,
  "confidence": 0.9234,
  "src_ip": "10.2.24.194",
  "dest_ip": "142.250.190.46",
  "src_port": 54321,
  "dest_port": 443,
  "transport": "TCP",
  "app": "ssl",
  "flow_packets": 12,
  "flow_bytes": 4096,
  "category": ["network", "intrusion_detection"],
  "type": ["connection", "anomaly"]
}
```

### Sample CEF Log Entry

```
CEF:0|NADS|NetworkAnomalyDetection|1.0|ANOMALY|Network ANOMALY Detected|8|src=10.2.24.194 spt=54321 dst=142.250.190.46 dpt=443 proto=TCP app=ssl cn1=0.9234 cn1Label=Confidence
```

### Splunk Search Queries

```spl
# All anomalies in last 24 hours
index=network_security sourcetype="nads:detection" action="ANOMALY" earliest=-24h

# Critical severity alerts
index=network_security severity="CRITICAL" | table time src_ip dest_ip dest_port app confidence

# Top targeted destination IPs
index=network_security action="ANOMALY" | top dest_ip

# Anomaly rate over time
index=network_security | timechart count by action

# High-confidence alerts by protocol
index=network_security action="ANOMALY" confidence>0.9 | stats count by transport
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard UI |
| `GET` | `/api/status` | System status & stats |
| `POST` | `/api/start` | Start live detection |
| `POST` | `/api/stop` | Stop live detection |
| `GET` | `/api/stats` | Detection statistics |
| `GET` | `/api/history?n=50` | Recent detection history |
| `GET` | `/api/timeline` | Time-series chart data |
| `GET` | `/api/severity` | Severity distribution |
| `GET` | `/api/model-results` | Training results (all models) |
| `GET` | `/api/plots` | List analysis plot images |
| `GET` | `/api/interfaces` | Available network interfaces |
| `GET` | `/api/mode` | Current detection mode |
| `POST` | `/api/switch-interface` | Change capture interface |
| `GET` | `/api/logs?n=100` | Recent SIEM log entries |
| `GET` | `/api/logs/stats` | Logging statistics |
| `GET` | `/api/logs/download/all` | Download JSON log |
| `GET` | `/api/logs/download/alerts` | Download alerts log |
| `GET` | `/api/logs/download/cef` | Download CEF log |
| `WS` | `/ws` | WebSocket real-time feed |

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **ML Framework** | scikit-learn, XGBoost, LightGBM |
| **Packet Capture** | Scapy (raw socket capture) |
| **Backend** | FastAPI + Uvicorn (ASGI) |
| **Real-time** | WebSocket |
| **Frontend** | HTML5 + Chart.js + Vanilla JS |
| **Logging** | Python logging + RotatingFileHandler |
| **Data Processing** | Pandas, NumPy |
| **Visualization** | Matplotlib, Seaborn |
| **Class Balancing** | imbalanced-learn (SMOTE) |

---

## 📄 License

This project is developed as a **Capstone Project** for academic purposes.

---

## 👨‍💻 Author

**Shannu** — Network Security & Machine Learning
**MUNAGAPATI KESAVA MOHANA KRISHNA(KESAVA-0725)** 

---

> 🛡️ *Defending networks with intelligence, one flow at a time.*
