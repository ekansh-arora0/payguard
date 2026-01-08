# 🛡️ PayGuard - AI-Powered Phishing & Scam Detector

**Real-time protection against phishing, scams, and AI-generated threats**

[![ML Accuracy](https://img.shields.io/badge/F1%20Score-95.4%25-brightgreen)](/)
[![ROC-AUC](https://img.shields.io/badge/ROC--AUC-0.994-blue)](/)
[![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey)](/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-yellow)](/)

---

## 🚀 Quick Start (For Friends!)

### Option 1: One-Click Install (Easiest)

```bash
# Clone the repo
git clone https://github.com/ekansh-arora0/payguard.git
cd payguard

# Run the installer
chmod +x install.sh
./install.sh
```

**That's it!** PayGuard will now:
- ✅ Install all dependencies
- ✅ Start automatically on login
- ✅ Show 🛡️ in your menu bar

---

### Option 2: Manual Setup

```bash
# Clone
git clone https://github.com/ekansh-arora0/payguard.git
cd payguard

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install rumps scikit-learn pandas numpy fastapi uvicorn

# Run menu bar app
python payguard_menubar_app.py &

# (Optional) Run enterprise dashboard
python payguard_enterprise.py &
```

---

## 🎯 Features

### 🔍 **Real-Time Detection**
| Threat Type | Detection |
|-------------|-----------|
| Phishing URLs | ✅ ML-based (95.4% F1) |
| Scam Emails | ✅ NLP analysis |
| Fake Login Pages | ✅ Visual fingerprinting |
| Suspicious Clipboard | ✅ Auto-scan |
| AI-Generated Scams | ✅ Behavioral analysis |

### 🖥️ **Menu Bar App**
Click the 🛡️ shield icon to:
- **Scan Screen** - Screenshot analysis for threats
- **Scan Clipboard** - Check copied URLs/text
- **Recent Alerts** - View detection history
- **Start/Stop Service** - Control backend

### 📊 **Enterprise Dashboard**
Access at `http://localhost:8003`:
- Real-time threat monitoring
- Organization management
- Email integration (Gmail/Outlook)
- Mobile push notifications

---

## 🔧 Usage

### Scan Your Screen
```bash
python payguard_scan.py --screen
```

### Scan Clipboard
```bash
python payguard_scan.py --clipboard
```

### Run Full Demo
```bash
python payguard_demo.py
```

### Start Enterprise Dashboard
```bash
python payguard_enterprise.py
# Open http://localhost:8003
```

---

## 📈 ML Benchmark Results

Tested on **13,792 real phishing samples**:

| Model | Accuracy | Precision | Recall | F1 | AUC |
|-------|----------|-----------|--------|-----|-----|
| **Logistic Regression** | 97.2% | 95.4% | 95.4% | **0.954** | **0.994** |
| Random Forest | 96.8% | 94.1% | 93.2% | 0.936 | 0.987 |
| Gradient Boosting | 96.5% | 93.8% | 92.9% | 0.933 | 0.985 |
| Naive Bayes | 95.1% | 91.2% | 90.8% | 0.910 | 0.971 |
| Linear SVM | 96.9% | 94.3% | 93.5% | 0.939 | 0.988 |

Run benchmark yourself:
```bash
python payguard_ml_benchmark.py
```

---

## 🔒 Privacy

PayGuard is **privacy-first**:
- 🔐 All processing happens **locally** on your device
- 🚫 No data sent to cloud without consent
- 🎭 Optional anonymous threat sharing with differential privacy
- 🗑️ Ephemeral storage - data auto-expires

### Opt-in Threat Sharing
```python
from payguard_threat_intel import ThreatIntelligenceHub, SharingLevel

hub = ThreatIntelligenceHub()
hub.set_sharing_level(SharingLevel.ANONYMOUS)  # Contribute anonymously
```

---

## 📁 Project Structure

```
payguard/
├── payguard_menubar_app.py   # 🖥️ Menu bar application
├── payguard_enterprise.py    # 🏢 Enterprise dashboard
├── payguard_ml_benchmark.py  # 📊 ML training & testing
├── payguard_threat_intel.py  # 🔒 Privacy-preserving intel
├── payguard_scan.py          # 🔍 Quick scan utility
├── payguard_demo.py          # 🎮 Feature demonstration
├── install.sh                # 📦 One-click installer
├── uninstall.sh              # 🗑️ Clean uninstaller
├── extension/                # 🌐 Browser extension (TypeScript)
├── backend/                  # ⚙️ API server
└── trained_models/           # 🧠 ML models
```

---

## 🛠️ Requirements

- **macOS** 10.14+ (for menu bar app)
- **Python** 3.9+
- **Dependencies:** rumps, scikit-learn, pandas, numpy, fastapi, uvicorn

---

## ❓ Troubleshooting

### Menu bar icon not showing?
```bash
# Restart the app
pkill -f payguard_menubar
python payguard_menubar_app.py &
```

### Permission errors on macOS?
Go to **System Preferences → Security & Privacy → Privacy**:
- Enable **Screen Recording** for Terminal
- Enable **Accessibility** for Terminal

### Backend not starting?
```bash
# Check if port 8002 is in use
lsof -i :8002
# Kill existing process if needed
kill -9 <PID>
```

---

## 🤝 Contributing

1. Fork the repo
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing`)
5. Open Pull Request

---

## 📜 License

MIT License - feel free to use for any purpose!

---

## 👨‍💻 Author

**Ekansh Arora** - [@ekansh-arora0](https://github.com/ekansh-arora0)

---

## ⭐ Star this repo if you find it useful!

