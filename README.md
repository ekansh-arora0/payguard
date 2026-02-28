# 🛡️ PayGuard - AI-Powered Phishing & Scam Detector

**Real-time protection against phishing, scams, and AI-generated threats**

[![ML Accuracy](https://img.shields.io/badge/F1%20Score-95.4%25-brightgreen)]()
[![ROC-AUC](https://img.shields.io/badge/ROC--AUC-0.994-blue)]()
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)]()
[![Python](https://img.shields.io/badge/Python-3.9%2B-yellow)]()

---

## 🚀 Quick Start

### Option 1: One-Click Install (macOS)

```bash
# Clone the repo
git clone https://github.com/ekansh-arora0/payguard.git
cd payguard

# Run the installer
chmod +x install.sh
./install.sh
```

**That's it!** PayGuard will:
- ✅ Install all dependencies
- ✅ Start automatically on login
- ✅ Show 🛡️ in your menu bar

### Option 2: Cross-Platform (Windows/Linux)

```bash
# Clone the repo
git clone https://github.com/ekansh-arora0/payguard.git
cd payguard

# Install dependencies
pip install -r requirements.txt

# Install cross-platform requirements
pip install pystray Pillow pyperclip pyautogui pyscreenshot win10toast

# Run the cross-platform version
python payguard_crossplatform.py
```

### Option 3: Backend API Only

```bash
# Clone and setup
git clone https://github.com/ekansh-arora0/payguard.git
cd payguard

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the backend API
cd backend
python -m uvicorn server:app --host 0.0.0.0 --port 8002

# API available at http://localhost:8002
# API docs at http://localhost:8002/docs
```

---

## 🎯 Features

### 🔍 **URL & Phishing Detection**
| Threat Type | Detection |
|-------------|-----------|
| Typosquatting (paypa1, amaz0n) | ✅ |
| Homograph attacks (xn-- domains) | ✅ |
| Phishing landers (/landers/) | ✅ |
| URL shortener unwrapping | ✅ |
| Click fraud tracking detection | ✅ |
| Suspicious paths (/login, /verify) | ✅ |
| Suspicious TLDs (.tk, .ml, .xyz) | ✅ |
| Crypto scams | ✅ |

### 🖼️ **AI Content Detection**
| Type | Method |
|------|--------|
| AI-generated faces | DIRE model (97%+ accuracy) |
| AI images (general) | Spectral/frequency analysis |
| AI metadata detection | EXIF/XMP/PNG chunk scanning |
| Video deepfakes | Frame extraction + DIRE |
| Audio deepfakes | Spectral voice analysis |

### 📱 **Real-Time Protection**
- **Menu Bar App** - Always-on protection
- **Browser Monitoring** - Scans Chrome/Safari history
- **Clipboard Scanning** - Auto-detect scam URLs
- **Screen Scanning** - Tile-based threat detection

---

## 📖 Usage

### Menu Bar App (macOS)

Click the 🛡️ shield icon to access:
- **Scan Screen** - Screenshot analysis for threats
- **Scan Clipboard** - Check copied URLs/text
- **Recent Alerts** - View detection history
- **Start/Stop Service** - Control backend

### Cross-Platform App (Windows/Linux)

System tray icon with:
- **Open** - Show main window
- **Scan Screen** - Capture and analyze
- **Check Clipboard** - Scan copied text
- **Settings** - Configure options
- **Quit** - Exit application

### Command Line Tools

```bash
# Scan a URL
curl -X POST "http://localhost:8002/api/v1/risk" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo_key" \
  -d '{"url": "https://example.com"}'

# Scan image for AI detection
curl -X POST "http://localhost:8002/api/v1/media-risk/ai-metadata" \
  -H "X-API-Key: demo_key" \
  -F "file=@/path/to/image.png"

# Check video for deepfakes
curl -X POST "http://localhost:8002/api/v1/media-risk/video-deepfake" \
  -H "X-API-Key: demo_key" \
  -F "file=@/path/to/video.mp4"

# Check audio for deepfakes
curl -X POST "http://localhost:8002/api/v1/media-risk/audio-deepfake" \
  -H "X-API-Key: demo_key" \
  -F "file=@/path/to/audio.mp3"
```

---

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the `backend/` directory:

```bash
# Required
MONGO_URL=mongodb://localhost:27017
DB_NAME=payguard

# Optional - API Settings
API_KEY=your_api_key_here
REDIS_URL=redis://localhost:6379

# Optional - Logging
LOG_LEVEL=INFO

# Optional - AI Detection
DIRE_HOME=/path/to/DIRE
PAYGUARD_AI_THRESHOLD_DEFAULT=0.7
PAYGUARD_AI_THRESHOLD_SAFE=0.9

# Optional - URL Analysis
PAYGUARD_SAFE_DOMAINS=localhost,127.0.0.1,example.com
```

### API Key Setup

The default API key is `demo_key`. For production:

```bash
# Generate a new API key
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Set it in your environment
export API_KEY=your_generated_key
```

---

## 🧪 Testing

### Run All Tests

```bash
# Python tests
cd backend
pytest tests/ -v

# Lint
flake8 backend/ --max-line-length=120
black --check backend/
isort --check-only backend/
```

### Run Specific Tests

```bash
# Test URL detection
python -c "
import requests
r = requests.post('http://localhost:8002/api/v1/risk', 
    json={'url': 'https://paypal-verify.com'},
    headers={'X-API-Key': 'demo_key'})
print(r.json())
"

# Test AI image detection
python backend/ai_metadata_checker.py /path/to/image.png
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

---

## 🔒 Privacy

PayGuard is **privacy-first**:
- 🔐 All processing happens **locally** on your device
- 🚫 No data sent to cloud without consent
- 🎭 Optional anonymous threat sharing
- 🗑️ Ephemeral storage - data auto-expires

### Privacy Scanner

Run the privacy scanner to verify no invasive code:

```bash
python scripts/privacy_scanner.py
```

---

## 📁 Project Structure

```
payguard/
├── payguard_menubar_app.py      # macOS menu bar app (rumps)
├── payguard_crossplatform.py    # Windows/Linux (pystray)
├── backend/                     # FastAPI backend
│   ├── server.py               # Main API server
│   ├── risk_engine.py          # URL risk analysis
│   ├── ai_metadata_checker.py  # AI image detection
│   ├── video_deepfake_detector.py
│   ├── audio_deepfake_detector.py
│   ├── models/                 # ML models
│   └── tests/                  # Unit tests
├── extension/                  # Browser extension (TypeScript)
├── website/                    # Landing page (Next.js)
├── scripts/                    # Utility scripts
└── requirements.txt            # Python dependencies
```

---

## 🛠️ Requirements

### For Menu Bar App (macOS)
- macOS 10.14+
- Python 3.9+
- Dependencies: `rumps`, `requests`, `pillow`

### For Cross-Platform App (Windows/Linux)
- Windows 10+ or Linux
- Python 3.9+
- Dependencies: `pystray`, `pillow`, `pyperclip`, `pyautogui`, `pyscreenshot`

### For Backend API
- Python 3.9+
- MongoDB (local or Atlas)
- Dependencies: `fastapi`, `uvicorn`, `motor`, `scikit-learn`

---

## 🚨 Troubleshooting

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

### Import errors?
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### MongoDB connection errors?
```bash
# Check MongoDB is running
mongod --version
# Or use MongoDB Atlas (cloud)
export MONGO_URL=mongodb+srv://...
```

---

## 🤝 Contributing

1. Fork the repo
2. Create feature branch (`git checkout -b feature/amazing`)
3. Run tests (`pytest backend/tests/`)
4. Ensure linting passes (`flake8 backend/`)
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push (`git push origin feature/amazing`)
7. Open Pull Request

---

## 📜 License

MIT License - feel free to use for any purpose!

---

## 👨‍💻 Author

**Ekansh Arora** - [@ekansh-arora0](https://github.com/ekansh-arora0)

---

## ⭐ Star this repo if you find it useful!
