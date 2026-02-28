# PayGuard User Guide

**Version 2.0.0 | Privacy-First Edition**

Welcome to PayGuard, your privacy-first protection against scams, phishing, and fraud. This guide will help you get started and make the most of PayGuard's features.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [How PayGuard Works](#how-payguard-works)
3. [Features](#features)
4. [Using PayGuard](#using-payguard)
5. [Understanding Alerts](#understanding-alerts)
6. [Privacy Controls](#privacy-controls)
7. [Settings](#settings)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)

---

## Getting Started

### Installation

#### Browser Extension (Chrome)

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" (top right toggle)
3. Click "Load unpacked"
4. Select the PayGuard `extension` folder
5. PayGuard icon appears in your toolbar

#### Desktop App (macOS)

1. Open Terminal
2. Navigate to PayGuard folder: `cd /path/to/payguard`
3. Run: `python3 launch_payguard.py`
4. PayGuard runs in privacy-first mode

#### Desktop App (Windows/Linux)

1. Install dependencies:
   ```bash
   pip install pystray Pillow pyperclip pyautogui pyscreenshot win10toast
   ```

2. Navigate to PayGuard folder:
   ```bash
   cd /path/to/payguard
   ```

3. Run the cross-platform version:
   ```bash
   python payguard_crossplatform.py
   ```

4. PayGuard will appear in your system tray

### First Launch

When you first launch PayGuard:
1. All protection features are **OFF by default**
2. You'll see the consent screen
3. Choose which features to enable
4. Start browsing safely!

---

## How PayGuard Works

### Privacy-First Architecture

PayGuard is built on three core principles:

1. **No Continuous Monitoring** - We never capture your screen or clipboard in the background
2. **User-Initiated Only** - All scans require your explicit action
3. **Local Processing** - Your data stays on your device

### Detection Layers

PayGuard uses multiple detection methods:

| Layer | Description | Privacy Impact |
|-------|-------------|----------------|
| URL Reputation | Checks URLs against threat databases | URL only sent |
| Visual Fingerprinting | Compares pages to known phishing sites | Local analysis |
| Behavioral Analysis | Detects suspicious page behavior | Local analysis |
| ML Detection | Machine learning threat detection | Local processing |

---

## Features

### 🛡️ Real-Time URL Protection

When enabled, PayGuard checks websites as you browse:
- Compares against 3+ threat intelligence feeds
- Checks domain age (flags new domains)
- Verifies SSL certificates
- Shows trust score in toolbar

### 🔍 On-Demand Screen Scan

Scan your screen for scam content:
1. Click PayGuard icon
2. Click "Scan Screen Now"
3. PayGuard analyzes for:
   - Fake virus warnings
   - Tech support scams
   - Phishing popups
   - Suspicious content

### 📝 Text Analysis

Check suspicious text (emails, messages):
1. Copy the text
2. Click PayGuard icon
3. Click "Scan Text"
4. Paste and analyze

### 🔔 Smart Alerts

PayGuard alerts you to threats with:
- **Low Risk** (Green) - Site appears safe
- **Medium Risk** (Yellow) - Proceed with caution
- **High Risk** (Red) - Danger! Don't proceed

### 🔐 Sensitive Data Redaction

PayGuard automatically masks:
- Password fields
- Credit card numbers
- Social Security Numbers
- Email addresses in forms

This happens **before** any analysis, protecting your sensitive data.

---

## Using PayGuard

### Browser Extension

#### Checking a Website

1. Visit any website
2. Look at PayGuard badge in toolbar:
   - 🟢 **Green (70-100)** - Safe
   - 🟡 **Yellow (40-69)** - Caution
   - 🔴 **Red (0-39)** - Danger
3. Click badge for details

#### Manual Scan

1. Click PayGuard icon
2. Select "Scan Now"
3. View detailed analysis

### Desktop App

#### Interactive Mode

```bash
🛡️ PAYGUARD - PRIVACY-FIRST MODE
================================

Commands:
  s - Scan screen now
  t - Scan text
  i - Show statistics
  q - Quit

PayGuard> s
🔍 Scanning screen...
✅ Screen appears safe
```

---

## Understanding Alerts

### Alert Levels

| Level | When Shown | Action |
|-------|------------|--------|
| 🟢 LOW | Minor concerns | Continue with awareness |
| 🟡 MEDIUM | Potential risk | Verify legitimacy |
| 🔴 HIGH | Likely threat | Stop immediately |

### Alert Information

Each alert includes:
- **Risk Score** - 0-100 confidence level
- **Reasons** - Why we flagged this
- **Signals** - Top 3 detection signals
- **Advice** - What you should do

### Providing Feedback

Help improve PayGuard:
1. Click "Is this wrong?" on any alert
2. Select "Safe" or "Dangerous"
3. Your feedback improves detection

(Feedback is anonymized and only sent if you've opted into telemetry)

---

## Privacy Controls

### Consent Management

Access via: PayGuard Icon → Settings → Privacy

| Setting | What It Controls |
|---------|-----------------|
| URL Checking | Real-time URL reputation checks |
| Page Analysis | Visual fingerprinting of pages |
| Screen Scanning | Manual screen capture scans |
| Clipboard Scanning | Manual clipboard text scans |
| Telemetry | Anonymous improvement data |

### How to Change Settings

1. Click PayGuard icon
2. Go to Settings
3. Toggle features on/off
4. Changes apply immediately

### Data Deletion

To delete all stored data:
1. Settings → Privacy → Data
2. Click "Delete All Data"
3. Confirm deletion

---

## Settings

### Detection Sensitivity

Adjust how sensitive PayGuard is:

| Level | Description |
|-------|-------------|
| Low | Fewer alerts, may miss some threats |
| Medium | Balanced (recommended) |
| High | More alerts, higher false positive rate |

### Alert Preferences

| Setting | Description |
|---------|-------------|
| Quiet Hours | Disable alerts during set times |
| Alert Sounds | Enable/disable notification sounds |
| Digest Mode | Get daily summary instead of instant alerts |

### Advanced

| Setting | Description |
|---------|-------------|
| Offline Mode | Use only local detection |
| Debug Mode | Show detailed logs |
| Export Logs | Download audit logs |

---

## Troubleshooting

### Extension Not Working

1. Check if extension is enabled in `chrome://extensions/`
2. Refresh the page
3. Try disabling and re-enabling PayGuard
4. Check browser console for errors

### No Badge Showing

1. Make sure you're on an HTTP/HTTPS page
2. Internal pages (chrome://) don't show badges
3. Check if backend is running (for local setup)

### False Positives

If PayGuard incorrectly flags a safe site:
1. Click the alert
2. Select "This is safe"
3. Site will be added to your whitelist

### High CPU/Memory Usage

1. Check Settings → Performance
2. Reduce scan frequency
3. Disable unused detection layers

---

## FAQ

### Is PayGuard free?

Yes! PayGuard is open source and free to use.

### Does PayGuard slow down my browser?

No. PayGuard is optimized for performance:
- URL checks < 50ms
- Page analysis < 500ms
- Memory < 50MB
- CPU idle < 2%

### Can PayGuard see my passwords?

No. PayGuard:
- Never reads password values
- Redacts password fields before analysis
- Never transmits sensitive data

### Does PayGuard work offline?

Partially. These features work offline:
- ML-based detection (local model)
- Rule-based detection
- Visual analysis

URL reputation requires internet.

### How do I report a bug?

1. Go to Settings → Help → Report Bug
2. Or file an issue on GitHub

### Where is my data stored?

All your data is stored locally on your device, encrypted with AES-256-GCM. Nothing is sent to servers without your consent.

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+P` | Open PayGuard popup |
| `Ctrl+Shift+S` | Quick screen scan |
| `Ctrl+Shift+T` | Quick text scan |

---

## Getting Help

- **Documentation:** https://payguard.app/docs
- **Support:** https://payguard.app/support
- **GitHub:** https://github.com/payguard/payguard
- **Email:** help@payguard.app

---

## Quick Reference Card

```
┌─────────────────────────────────────┐
│        PAYGUARD QUICK GUIDE         │
├─────────────────────────────────────┤
│                                     │
│  🟢 Green Badge = SAFE              │
│  🟡 Yellow Badge = CAUTION          │
│  🔴 Red Badge = DANGER              │
│                                     │
│  Click badge for details            │
│  "Scan Now" for manual check        │
│                                     │
│  SCAM WARNING SIGNS:                │
│  • Urgent language                  │
│  • Phone numbers to call            │
│  • Fake virus alerts                │
│  • "Your computer is infected"      │
│  • "Call Microsoft support"         │
│                                     │
│  NEVER:                             │
│  ❌ Call numbers from popups        │
│  ❌ Give remote access              │
│  ❌ Enter card details              │
│  ❌ Download unknown software       │
│                                     │
└─────────────────────────────────────┘
```

---

**Stay Safe with PayGuard! 🛡️**

© 2026 PayGuard. All rights reserved.
