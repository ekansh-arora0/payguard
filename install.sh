#!/bin/bash
# PayGuard macOS/Linux Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ekansh-arora0/payguard/main/install.sh | bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🛡️  PayGuard Installer${NC}"
echo ""

OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" = "Darwin" ]; then
    PLATFORM="macos"
    echo "📱 Detected: macOS ($ARCH)"
elif [ "$OS" = "Linux" ]; then
    PLATFORM="linux"
    echo "🐧 Detected: Linux ($ARCH)"
else
    echo -e "${RED}❌ Unsupported OS: $OS${NC}"
    exit 1
fi

VERSION="${VERSION:-1.0.0}"
GITHUB_REPO="ekansh-arora0/payguard"

echo "📥 Downloading PayGuard v${VERSION}..."

if [ "$PLATFORM" = "macos" ]; then
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/PayGuard-v${VERSION}-macos.zip"
    INSTALL_DIR="/Applications"
    
    # Download to temp
    TEMP_DIR=$(mktemp -d)
    curl -fsSL "$DOWNLOAD_URL" -o "$TEMP_DIR/PayGuard.zip"
    
    echo "📦 Extracting..."
    unzip -q "$TEMP_DIR/PayGuard.zip" -d "$TEMP_DIR"
    
    echo "🚀 Installing to Applications..."
    cp -R "$TEMP_DIR/PayGuard.app" "$INSTALL_DIR/"
    rm -rf "$TEMP_DIR"
    
    echo "✅ Installed to /Applications/PayGuard.app"
    echo ""
    echo "🚀 Starting PayGuard..."
    open "$INSTALL_DIR/PayGuard.app"
    
else
    # Linux
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/PayGuard-v${VERSION}-linux.tar.gz"
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    
    curl -fsSL "$DOWNLOAD_URL" | tar -xz -C "$INSTALL_DIR"
    chmod +x "$INSTALL_DIR/payguard"
    
    # Add to PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
        echo "📝 Added to PATH"
    fi
    
    echo "✅ Installed to $INSTALL_DIR/payguard"
    echo ""
    echo "🚀 Starting PayGuard..."
    "$INSTALL_DIR/payguard" &
fi

echo ""
echo -e "${GREEN}✨ PayGuard is running!${NC}"
echo ""
echo "Look for the shield icon in your menu bar/system tray"
echo "❤️  Enjoying PayGuard? Star us: https://github.com/payguard/payguard"
