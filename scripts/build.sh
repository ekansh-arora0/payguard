#!/bin/bash
# Build PayGuard binaries for macOS, Linux, and Windows
# Usage: ./scripts/build.sh [version]

set -e

VERSION=${1:-"1.0.0"}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/dist"
RELEASE_DIR="$BUILD_DIR/release"

echo "🛠️  Building PayGuard v$VERSION"
echo ""

# Clean and create directories
rm -rf "$BUILD_DIR"
mkdir -p "$RELEASE_DIR"

# Install PyInstaller if not present
if ! python3 -c "import PyInstaller" 2>/dev/null; then
    echo "📦 Installing PyInstaller..."
    pip3 install pyinstaller
fi

cd "$PROJECT_DIR"

# ============================================
# Build macOS App
# ============================================
echo "🍎 Building macOS app..."

# Create spec file for macOS
cat > "$BUILD_DIR/payguard_macos.spec" << 'EOF'
# -*- mode: python ; coding: utf-8 -*-
import sys
sys.path.insert(0, '.')

a = Analysis(
    ['payguard_menubar_app.py'],
    pathex=['.'],
    binaries=[],
    datas=[('models', 'models'), ('backend', 'backend')],
    hiddenimports=['rumps', 'requests', 'PIL', 'pkg_resources'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PayGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=True,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.icns' if os.path.exists('assets/icon.icns') else None,
)

app = BUNDLE(
    exe,
    name='PayGuard.app',
    icon='assets/icon.icns' if os.path.exists('assets/icon.icns') else None,
    bundle_identifier='com.payguard.app',
    info_plist={
        'CFBundleShortVersionString': '1.0.0',
        'CFBundleVersion': '1.0.0',
        'LSMinimumSystemVersion': '10.14',
        'LSUIElement': True,
    },
)
EOF

# Build macOS app
python3 -m PyInstaller \
    --clean \
    --noconfirm \
    --windowed \
    --name="PayGuard" \
    --add-data="models:models" \
    --add-data="backend:backend" \
    --hidden-import=rumps \
    --hidden-import=requests \
    --hidden-import=PIL \
    --hidden-import=pkg_resources \
    --icon=assets/icon.icns \
    --distpath="$RELEASE_DIR/macos" \
    payguard_menubar_app.py 2>&1 || echo "macOS build requires macOS machine"

# Create DMG if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    if command -v create-dmg &> /dev/null; then
        echo "📦 Creating macOS DMG..."
        create-dmg \
            --volname "PayGuard Installer" \
            --window-pos 200 120 \
            --window-size 800 400 \
            --icon-size 100 \
            --app-drop-link 600 185 \
            "$RELEASE_DIR/PayGuard-$VERSION.dmg" \
            "$RELEASE_DIR/macos/PayGuard.app"
    else
        echo "⚠️  create-dmg not installed, creating zip instead"
        cd "$RELEASE_DIR/macos"
        zip -r "../PayGuard-$VERSION-macos.zip" "PayGuard.app"
        cd "$PROJECT_DIR"
    fi
fi

# ============================================
# Build Linux Binary
# ============================================
echo "🐧 Building Linux binary..."

python3 -m PyInstaller \
    --clean \
    --noconfirm \
    --windowed \
    --name="payguard" \
    --add-data="models:models" \
    --add-data="backend:backend" \
    --hidden-import=requests \
    --hidden-import=PIL \
    --distpath="$RELEASE_DIR/linux" \
    payguard_menubar_standalone.py 2>&1 || echo "Linux build skipped"

if [ -f "$RELEASE_DIR/linux/payguard" ]; then
    cd "$RELEASE_DIR/linux"
    tar -czf "../PayGuard-$VERSION-linux.tar.gz" payguard
    cd "$PROJECT_DIR"
fi

# ============================================
# Build Windows Binary (cross-compile from macOS/Linux)
# ============================================
echo "🪟 Building Windows binary..."

# For Windows, we need a Windows-specific entry point
cat > "$BUILD_DIR/payguard_windows.py" << 'EOF'
#!/usr/bin/env python3
"""PayGuard for Windows - System tray application"""

import os
import sys
import threading
import logging
from datetime import datetime
from pathlib import Path

try:
    import pystray
    from PIL import Image
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False
    print("Missing dependency: pystray")
    print("Install with: pip install pystray pillow")
    sys.exit(1)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Setup logging
log_dir = Path.home() / "AppData" / "Local" / "PayGuard" / "logs"
log_dir.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "payguard.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PayGuardWindows:
    def __init__(self):
        self.icon = None
        self.api_url = "https://api.payguard.com"
        
    def create_icon(self):
        """Create a simple icon"""
        # Create a simple colored square icon
        from PIL import Image, ImageDraw
        width = 64
        height = 64
        image = Image.new('RGB', (width, height), color='#10b981')
        dc = ImageDraw.Draw(image)
        # Draw a shield shape
        dc.polygon([(32, 8), (56, 20), (56, 40), (32, 56), (8, 40), (8, 20)], fill='white')
        return image
    
    def check_url(self, url):
        """Check a URL for phishing"""
        logger.info(f"Checking URL: {url}")
        
        if not HAS_REQUESTS:
            return {"trust_score": 50, "risk_level": "MEDIUM", "message": "Offline mode"}
        
        try:
            response = requests.post(
                f"{self.api_url}/api/v1/risk",
                json={"url": url},
                timeout=5
            )
            return response.json()
        except Exception as e:
            logger.error(f"API error: {e}")
            return {"trust_score": 50, "risk_level": "MEDIUM", "message": "Connection error"}
    
    def on_check_url(self, icon, item):
        """Manual URL check"""
        import tkinter as tk
        from tkinter import simpledialog, messagebox
        
        root = tk.Tk()
        root.withdraw()
        
        url = simpledialog.askstring("PayGuard", "Enter URL to check:")
        if url:
            result = self.check_url(url)
            risk = result.get('risk_level', 'UNKNOWN')
            score = result.get('trust_score', 50)
            
            if risk == 'HIGH':
                messagebox.showwarning("⚠️ PayGuard Alert", 
                    f"HIGH RISK DETECTED!\n\nTrust Score: {score}/100\n\nThis site appears to be a phishing attempt.")
            elif risk == 'MEDIUM':
                messagebox.showinfo("⚠️ PayGuard Warning",
                    f"Medium Risk\n\nTrust Score: {score}/100\n\nExercise caution with this site.")
            else:
                messagebox.showinfo("✅ PayGuard Safe",
                    f"Low Risk\n\nTrust Score: {score}/100\n\nThis site appears safe.")
        
        root.destroy()
    
    def on_about(self, icon, item):
        """Show about dialog"""
        import tkinter as tk
        from tkinter import messagebox
        
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("About PayGuard",
            "PayGuard v1.0.0\n\nAI-powered phishing detection\n\nProtecting you from scams and fraudulent websites.")
        root.destroy()
    
    def on_exit(self, icon, item):
        """Exit application"""
        icon.stop()
    
    def run(self):
        """Run the system tray application"""
        logger.info("Starting PayGuard Windows")
        
        menu = (
            pystray.MenuItem("Check URL...", self.on_check_url),
            pystray.MenuItem("About", self.on_about),
            pystray.MenuItem("Exit", self.on_exit),
        )
        
        self.icon = pystray.Icon("payguard", self.create_icon(), "PayGuard", menu)
        self.icon.run()

if __name__ == "__main__":
    app = PayGuardWindows()
    app.run()
EOF

# Build Windows executable using Wine (if available) or skip
if command -v wine &> /dev/null; then
    echo "🍷 Using Wine to build Windows binary..."
    wine python -m PyInstaller \
        --clean \
        --noconfirm \
        --windowed \
        --name="PayGuard" \
        --add-data="models;models" \
        --add-data="backend;backend" \
        --hidden-import=pystray \
        --hidden-import=PIL \
        --hidden-import=requests \
        --distpath="$RELEASE_DIR/windows" \
        "$BUILD_DIR/payguard_windows.py"
else
    echo "⚠️  Wine not available, Windows build skipped"
    echo "   To build Windows binary:"
    echo "   1. Install Wine or use a Windows machine"
    echo "   2. Run: pip install pyinstaller pystray pillow requests"
    echo "   3. Run: python -m PyInstaller payguard_windows.py"
fi

if [ -f "$RELEASE_DIR/windows/PayGuard.exe" ]; then
    cd "$RELEASE_DIR/windows"
    zip -r "../PayGuard-$VERSION-windows.zip" PayGuard.exe
    cd "$PROJECT_DIR"
fi

# ============================================
# Create Release Notes
# ============================================
echo "📝 Creating release notes..."

cat > "$RELEASE_DIR/RELEASE_NOTES.md" << EOF
# PayGuard v$VERSION

## Installation

### macOS
\`\`\`bash
curl -fsSL https://payguard.com/install.sh | bash
\`\`\`

Or download and install manually:
- [PayGuard-$VERSION.dmg](PayGuard-$VERSION.dmg) (macOS 10.14+)

### Linux
\`\`\`bash
curl -fsSL https://payguard.com/install.sh | bash
\`\`\`

Or download:
- [PayGuard-$VERSION-linux.tar.gz](PayGuard-$VERSION-linux.tar.gz)

### Windows
\`\`\`powershell
irm https://payguard.com/install.ps1 | iex
\`\`\`

Or download:
- [PayGuard-$VERSION-windows.zip](PayGuard-$VERSION-windows.zip)

## What's New
- 4 ML models for comprehensive phishing detection
- Real-time URL analysis (<50ms response time)
- Visual detection of fake login pages
- Menu bar / system tray integration
- Automatic threat intelligence updates

## System Requirements
- **macOS**: 10.14+ (Mojave or later)
- **Linux**: Ubuntu 18.04+, Debian 10+, or similar
- **Windows**: Windows 10 or later
- **Internet**: Required for real-time threat checking

## Files Included
$(ls -la "$RELEASE_DIR/" | grep -E "\.dmg|\.zip|\.tar\.gz|\.exe")

---
Built with ❤️ by the PayGuard team
EOF

# ============================================
# Summary
# ============================================
echo ""
echo "✅ Build Complete!"
echo ""
echo "📦 Release artifacts in: $RELEASE_DIR"
echo ""
ls -lh "$RELEASE_DIR/"
echo ""
echo "🚀 Next steps:"
echo "   1. Test the binaries on each platform"
echo "   2. Create GitHub release: gh release create v$VERSION $RELEASE_DIR/*"
echo "   3. Update website with new version number"
echo ""
