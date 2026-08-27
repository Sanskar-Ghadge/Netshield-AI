# 🛡️ NetShield AI

**Real-Time ML-Powered Network Intrusion Detection System**

NetShield AI captures live network packets from your Wi-Fi interface, classifies them using an XGBoost machine learning model trained on the CICIDS2017 dataset, and displays everything on a real-time dark-themed React dashboard with live traffic charts, threat indicators, alert banners, an AI chatbot, and PDF security reports.

---

## 📐 Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        REACT DASHBOARD (port 5173)                    │
│  Live Traffic Charts │ Threat Indicator │ Attack History │ Chatbot    │
│  Stats Cards │ Packet Feed │ Alert Banner │ System Info │ Reports     │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ Socket.io (WebSocket) + REST API
┌──────────────────────────▼───────────────────────────────────────────┐
│                   NODE.JS SERVER (port 3001)                         │
│  Express REST API │ Socket.io real-time push │ Python WS bridge     │
└──────────┬────────────────────────────────────────────────────────────┘
           │ HTTP + WebSocket
┌──────────▼──────────────────────────────────────────────────────────┐
│                PYTHON ENGINE (port 8000)                            │
│  FastAPI microservice:                                              │
│  • Scapy live packet capture (background thread)                    │
│  • Flow aggregation (bidirectional 5-tuple flows)                   │
│  • Traffic pre-filter (ICMP/DHCP/broadcast bypass)                  │
│  • XGBoost ML model → 9-class prediction                            │
│  • Confidence threshold (80% minimum for attacks)                   │
│  • SQLite logging │ Alert dispatch (Telegram/Email/Voice)            │
│  • Gemini AI chatbot │ PDF report generation                        │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow for a Live Packet

1. **Scapy** captures a raw packet on the Wi-Fi interface
2. The packet is normalized into a `PacketRecord` (IP, ports, protocol, flags, lengths)
3. The **FlowAggregator** groups packets by bidirectional 5-tuple and computes 40 CICFlowMeter-compatible flow features
4. When a flow completes (TCP FIN/RST or idle timeout), it enters the prediction queue
5. The **TrafficFilter** bypasses non-classifiable traffic (ICMP, DHCP, broadcast) to BENIGN
6. The **RuntimePreprocessor** applies the exact v3 training transformation (impute → log1p → clip → SelectKBest → RobustScaler)
7. The **XGBoost model** predicts one of 9 classes with a confidence probability
8. The **confidence threshold** downgrades any attack prediction below 80% to BENIGN
9. The result is logged to **SQLite**, broadcast via **WebSocket** → Node.js → **Socket.io** → React dashboard
10. If it's a genuine attack, alerts fire (Telegram, Email, Voice) and the dashboard banner flashes red

---

## ✨ Features

- **Real-time packet capture** — Scapy captures live traffic on your Wi-Fi interface
- **ML-powered detection** — XGBoost model trained on CICIDS2017 (2.8M flow records, 9 attack classes)
- **9 attack types detected** — DDoS, DoS, PortScan, BruteForce, Bot, WebAttack, Infiltration, Heartbleed, BENIGN
- **Live traffic chart** — Rolling 60-second area chart showing normal vs. malicious packets/sec
- **Threat indicator** — 🟢 SAFE / 🟡 ELEVATED / 🔴 CRITICAL with pulsing glow animation
- **Attack history table** — Sortable, filterable, paginated, CSV exportable
- **Live packet feed** — Scrolling feed of last 50 packet predictions with color coding
- **Attack type pie chart** — Donut chart showing attack distribution
- **Alert banner** — Flashing red banner on attack detection, auto-dismiss after 10s
- **AI chatbot** — Gemini-powered security assistant with live DB context (Ctrl+K to open)
- **PDF reports** — Multi-page security report with executive summary, attack breakdown, recommendations
- **Multi-channel alerts** — Telegram, Email, and Voice (pyttsx3) alert dispatch
- **System info panel** — Connection status, capture interface, model version, server uptime
- **False positive prevention** — Traffic pre-filter + 80% confidence threshold

---

## 🔧 Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| ML Training | Python, scikit-learn, XGBoost, pandas, numpy | Train and compare 4 models on CICIDS2017 |
| ML Inference | Python, joblib, numpy | Load model + preprocessor, real-time prediction |
| Packet Capture | Scapy, threading | Live Wi-Fi capture, flow aggregation |
| Python Backend | FastAPI, uvicorn, SQLite | REST API, WebSocket, prediction pipeline |
| Node.js Backend | Express, Socket.io, axios, better-sqlite3 | REST proxy, real-time push to frontend |
| Frontend | React 18, Vite 5, Recharts, Socket.io-client, lucide-react | Dashboard UI, charts, live updates |
| AI Chatbot | Google Gemini API | Conversational security assistant |
| PDF Reports | ReportLab | Multi-page security report generation |
| Alerts | Telegram Bot API, Gmail SMTP, pyttsx3 | Multi-channel attack notification |
| Dataset | CICIDS2017 | 8 CSV files, ~610MB, 2.8M flow records |

---

## 📋 Prerequisites

1. **Python 3.11+** — [Download](https://www.python.org/downloads/)
2. **Node.js 18+** — [Download](https://nodejs.org/)
3. **Npcap** (Windows) — Required for Scapy packet capture/send — [Download](https://npcap.com/)
4. **Google Gemini API Key** (optional) — For the AI chatbot — [Get free key](https://aistudio.google.com/app/apikey)

---

## 🚀 Quick Start

### Automated Setup (Windows PowerShell)

```powershell
# 1. Clone or download this project
cd "C:\path\to\CNT project"

# 2. Run the setup script (creates venv, installs all dependencies)
.\scripts\setup_env.ps1

# 3. Start all three servers
.\scripts\start_all.ps1

# 4. Open the dashboard
#    http://localhost:5173

# 5. (Optional) Simulate an attack for a demo
py scripts\simulate_attack.py --ddos

# To stop all servers:
.\scripts\stop_all.ps1
```

### Manual Setup

#### 1. Python Engine

```bash
cd python-engine
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux/Mac
source .venv/bin/activate

pip install -r requirements.txt
```

#### 2. Node.js Backend

```bash
cd server
npm install
```

#### 3. React Dashboard

```bash
cd dashboard
npm install
```

#### 4. Environment Configuration

```bash
# Copy the template and edit with your API keys
cp .env.example .env
```

Edit `.env` and add:
- `GEMINI_API_KEY` — for the AI chatbot (optional, chatbot shows fallback message without it)
- `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` — for Telegram alerts (optional)
- `EMAIL_SENDER`, `EMAIL_PASSWORD`, `EMAIL_RECIPIENT` — for email alerts (optional)
- `CAPTURE_INTERFACE` — your Wi-Fi interface name (e.g., `Wi-Fi` on Windows)

#### 5. Start Servers

```bash
# Terminal 1 — Python engine (port 8000)
cd python-engine
py -m uvicorn app:app --host 0.0.0.0 --port 8000

# Terminal 2 — Node.js backend (port 3001)
cd server
node src/index.js

# Terminal 3 — React dashboard (port 5173)
cd dashboard
npx vite --host
```

Open **http://localhost:5173** in your browser.

---

## ⚙️ Configuration

All settings are in the `.env` file at the project root:

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | FastAPI bind address |
| `PYTHON_PORT` | `8000` | Python engine port |
| `NODE_PORT` | `3001` | Node.js server port |
| `DB_PATH` | `python-engine/netshield.db` | SQLite database path |
| `MODEL_PATH` | (v3 default) | Override path for the XGBoost model |
| `PREPROCESSOR_PATH` | (v3 default) | Override path for the preprocessor |
| `ENCODER_PATH` | (v3 default) | Override path for the label encoder |
| `METADATA_PATH` | (v3 default) | Override path for the metadata JSON |
| `CAPTURE_ENABLED` | `true` | Enable live packet capture on startup |
| `CAPTURE_INTERFACE` | `Wi-Fi` | Network interface to sniff |
| `CAPTURE_BPF_FILTER` | (empty) | Optional BPF filter string |
| `IDLE_TIMEOUT_S` | `120` | Idle flow eviction threshold in seconds |
| `ATTACK_CONFIDENCE_THRESHOLD` | `0.80` | Minimum confidence for attack classification |
| `GEMINI_API_KEY` | (empty) | Google Gemini API key for chatbot |
| `TELEGRAM_BOT_TOKEN` | (empty) | Telegram bot token for alerts |
| `TELEGRAM_CHAT_ID` | (empty) | Telegram chat ID to send alerts to |
| `EMAIL_SENDER` | (empty) | Gmail address for email alerts |
| `EMAIL_PASSWORD` | (empty) | Gmail app password for email alerts |
| `EMAIL_RECIPIENT` | (empty) | Recipient email address for alerts |
| `ALERT_COOLDOWN_S` | `30` | Minimum seconds between alerts |
| `VOICE_ALERTS` | `true` | Enable pyttsx3 voice announcements |
| `REPORT_DIR` | `reports` | Directory for generated PDF reports |

---

## 📁 Project Structure

```
CNT project/
├── CICIDS2017/                    # 8 raw CSV files (~610MB)
├── dataset/processed/v3/          # Cleaned data, train/test arrays
├── ml-model/
│   ├── preprocessing/             # Data cleaning + feature engineering
│   └── training/                  # Model training script
├── python-engine/
│   ├── models/v3/                 # 8 model artifacts (best = XGBoost)
│   ├── packet_capture/            # Scapy capture, flow aggregation
│   ├── prediction/                # Preprocessor, predictor, filter, schemas
│   ├── alerts/                    # Telegram, Email, Voice dispatchers
│   ├── chatbot/                   # Gemini AI integration
│   ├── reports/                   # PDF generation
│   ├── tests/                     # 18+ test files
│   ├── app.py                     # FastAPI entry point
│   ├── config.py                  # Settings from .env
│   ├── database.py                # SQLite layer
│   └── ws_manager.py              # WebSocket broadcast manager
├── server/                        # Node.js backend
│   └── src/
│       ├── index.js               # Express + Socket.io server
│       ├── routes/                # 4 REST route files
│       └── utils/                 # SocketHandler + PythonWs client
├── dashboard/                     # React frontend
│   └── src/
│       ├── components/            # 11 React components
│       ├── pages/                 # 3 pages (Dashboard, History, Reports)
│       ├── context/               # DashboardContext provider
│       ├── hooks/                 # useSocket hook
│       ├── api/                   # Axios client
│       └── utils/                 # Formatters + constants
├── scripts/                       # Setup, start, stop, attack simulation
│   ├── simulate_attack.py
│   ├── setup_env.ps1
│   ├── start_all.ps1
│   └── stop_all.ps1
├── docs/                          # Feature contract documentation
├── .env                           # Environment configuration
├── .env.example                   # Template
└── README.md                      # This file
```

---

## 🧠 ML Pipeline

### Dataset: CICIDS2017

The Canadian Institute for Cybersecurity's 2017 dataset contains real network traffic captured over 5 days with both benign traffic and 14 attack types. The project uses all 8 CSV files (~610MB, ~2.8M flow records).

### Training Pipeline

1. **Data Cleaning** — Load 8 CSVs, strip whitespace, remove NaN/inf/duplicates, standardise 9 class labels
2. **Feature Engineering** — Label encoding, SelectKBest (75→40 features), SMOTE for class imbalance, RobustScaler, 80/20 stratified split
3. **Model Training** — Train 4 models (Random Forest, XGBoost, MLP, SVM), compare on F1/Precision/Recall/Accuracy, select best
4. **Deployment** — XGBoost selected (macro F1 = 0.975, accuracy = 99.92%), saved as `intrusion_model_v3.pkl`

### 9 Attack Classes

| ID | Class | Description |
|----|-------|-------------|
| 0 | BENIGN | Normal traffic |
| 1 | Bot | Botnet communication |
| 2 | BruteForce | Brute force password attacks |
| 3 | DDoS | Distributed Denial of Service |
| 4 | DoS | Denial of Service |
| 5 | Heartbleed | OpenSSL Heartbleed exploit |
| 6 | Infiltration | Network infiltration |
| 7 | PortScan | Port scanning |
| 8 | WebAttack | Web-based attacks (XSS, SQLi, etc.) |

### False Positive Prevention

Two-layer defense ensures the system doesn't cry wolf:

1. **Traffic Pre-Filter** — ICMP, IGMP, DHCP, broadcast/multicast, and link-local discovery traffic bypass the model entirely (it can't classify them meaningfully)
2. **Confidence Threshold** — Any attack prediction below 80% confidence is downgraded to BENIGN

---

## 📡 API Endpoints

### REST API (Node.js on port 3001)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Current threat level, packet counts, uptime |
| GET | `/api/stats` | Attack distribution, top attackers, summary |
| GET | `/api/attacks?limit=50&offset=0&attack_type=DDoS` | Paginated attack history |
| POST | `/api/chatbot` | Query the Gemini AI chatbot |
| POST | `/api/reports` | Trigger PDF report generation |
| GET | `/api/node-health` | Node.js server health check |

### Socket.io Events

| Event | Direction | Purpose |
|-------|-----------|---------|
| `initial:state` | Server→Client | Initial dashboard data on connect |
| `packet:data` | Server→Client | One predicted flow (benign or attack) |
| `attack:alert` | Server→Client | Attack detected — trigger alert banner |
| `threat:update` | Server→Client | Threat level update (every 10s) |

---

## 🎯 Demo Guide

Perfect for viva/presentation:

### Step 1: Start Everything
```powershell
.\scripts\start_all.ps1
```

### Step 2: Show Normal Traffic
- Open **http://localhost:5173**
- Dashboard shows green threat level
- Live traffic chart updates as you browse the internet
- Stats cards show packet counts increasing
- System Info panel shows capture active on Wi-Fi

### Step 3: Simulate a DDoS Attack
```powershell
py scripts\simulate_attack.py --ddos
```
- 500 TCP SYN packets sent to 8.8.8.8:80 (Google DNS)
- Packets are visible on the Wi-Fi capture interface
- Flows appear after the 2-minute idle timeout
- Dashboard shows new traffic in the chart

### Step 4: Simulate a Port Scan
```powershell
py scripts\simulate_attack.py --portscan
```
- 200 TCP SYN packets to ports 1-200 on 8.8.8.8
- Each port creates a separate flow (different 5-tuple)
- Flows appear after idle timeout

### Step 5: Simulate Brute Force
```powershell
py scripts\simulate_attack.py --bruteforce
```
- 200 TCP SYN packets to 8.8.8.8:22 (SSH)
- Rapid repeated connection attempts

### Step 6: Ask the Chatbot
- Press **Ctrl+K** to open the chatbot
- Ask: "What attacks happened today?"
- The AI responds with live data from the database
- (Requires Gemini API key in `.env` — shows fallback message without it)

### Step 7: Generate a PDF Report
- Go to the **Reports** page
- Click "Generate PDF Security Report"
- Report is generated with executive summary, attack breakdown, and recommendations

### Step 8: Stop Everything
```powershell
.\scripts\stop_all.ps1
```

### Note on Attack Detection

The XGBoost model was trained on CICIDS2017 **completed flow-level** data with bidirectional statistics (flow duration, inter-arrival times, backward packet lengths, TCP flag counts). Live SYN-only flows with no backward traffic produce feature vectors that the model classifies as BENIGN with high confidence — this is **correct behavior** since the model was trained on flow statistics, not individual packets.

For a demo where the model flags attacks, you can:
1. Temporarily lower the confidence threshold in `.env`: `ATTACK_CONFIDENCE_THRESHOLD=0.40`
2. Restart the Python engine
3. Run the attack simulation — low-confidence predictions will now be flagged as attacks

Alternatively, replay an actual CICIDS2017 attack PCAP through the CLI:
```bash
cd python-engine
py -m packet_capture pcap --file path/to/attack_traffic.pcap
```

---

## 🧪 Testing

### Python Tests

```bash
cd python-engine
py -m pytest tests/ -v
```

Key test files:

| Test File | Coverage |
|-----------|----------|
| `test_traffic_filter.py` | Traffic filter rules + confidence threshold (25 tests) |
| `test_predict_v3.py` | Model loading, prediction APIs, thread safety (22 tests) |
| `test_app_api.py` | REST endpoints, WebSocket, status, stats (11 tests) |
| `test_runtime_transform_v3.py` | Preprocessing parity with training (6 tests) |
| `test_flow_features.py` | Hand-calculated flow feature values |
| `test_flow_lifecycle.py` | Flow creation, FIN/RST, timeout |
| `test_database.py` | SQLite logging and queries |
| `test_alert_dispatcher.py` | Alert dispatch to all channels |

### Frontend Build

```bash
cd dashboard
npx vite build   # Should complete with 0 errors
```

---

## ⚠️ Known Limitations

1. **Cross-attack generalization** — The model detects only 2.17% of entirely unseen attack types. It is a closed-set classifier, not a novelty detector. High confidence on known attacks does not mean reliable detection of novel attacks.
2. **Windows-only packet capture** — Scapy requires Npcap on Windows. On Linux, `libpcap` is used instead.
3. **Administrator privileges** — Raw packet capture/send may require admin rights on some systems.
4. **Demo traffic on localhost** — The attack simulator sends traffic to `127.0.0.1`. For the model to see it, the Python engine must be capturing on an interface that observes loopback traffic.

---

## 📊 Model Performance

| Model | Accuracy | Macro F1 | Macro Precision | Macro Recall | Pred. Speed |
|-------|----------|----------|-----------------|--------------|-------------|
| **XGBoost** ✅ | 99.88% | 0.907 | 0.875 | 0.971 | 0.032ms |
| Random Forest | 99.79% | 0.897 | 0.876 | 0.948 | 0.024ms |
| MLP | 95.95% | 0.571 | 0.547 | 0.977 | 0.004ms |
| SVM (Linear) | 95.88% | 0.383 | 0.431 | 0.357 | 0.005ms |

**Deployment model (trained on full dataset):** Accuracy 99.92%, Macro F1 0.975, 0.020ms per prediction.

---

## 📝 Credits

- **Dataset:** [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) by the Canadian Institute for Cybersecurity, University of New Brunswick
- **ML Framework:** scikit-learn, XGBoost
- **Packet Capture:** Scapy
- **Backend:** FastAPI, Express, Socket.io
- **Frontend:** React, Vite, Recharts
- **AI Chatbot:** Google Gemini
- **PDF Reports:** ReportLab

---

## 📄 License

This project is an academic capstone project. The CICIDS2017 dataset is licensed for research and academic use by the Canadian Institute for Cybersecurity.
