#!/bin/bash
# PayGuard Quick Install Script

echo "🛡️ PayGuard Installer"
echo "====================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.9+ first."
    exit 1
fi

# Create app directory
APP_DIR="$HOME/.payguard"
mkdir -p "$APP_DIR"

# Download/copy files
echo "📥 Installing PayGuard..."
cd "$APP_DIR"

# Install dependencies
echo "📦 Installing dependencies..."
python3 -m pip install --user -q rumps requests pillow scikit-learn pandas numpy

# Copy main files
cp -r /Users/ekans/payguard/payguard_menubar_app.py "$APP_DIR/"
cp -r /Users/ekans/payguard/payguard_ml_benchmark.py "$APP_DIR/"
cp -r /Users/ekans/payguard/payguard_threat_intel.py "$APP_DIR/"
cp -r /Users/ekans/payguard/trained_models "$APP_DIR/" 2>/dev/null || true

# Create launch agent for auto-start
PLIST_PATH="$HOME/Library/LaunchAgents/com.payguard.app.plist"
cat > "$PLIST_PATH" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.payguard.app</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>$HOME/.payguard/payguard_menubar_app.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/.payguard/payguard.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/.payguard/payguard.err</string>
</dict>
</plist>
PLIST

# Load the agent
launchctl load "$PLIST_PATH"

echo ""
echo "✅ PayGuard installed successfully!"
echo ""
echo "🛡️ PayGuard is now running in your menu bar."
echo "   Click the shield icon (🛡️) to access features."
echo ""
echo "To uninstall: ~/.payguard/uninstall.sh"
