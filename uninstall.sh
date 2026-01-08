#!/bin/bash
# PayGuard Uninstaller

echo "🗑️ Uninstalling PayGuard..."

# Stop the service
launchctl unload "$HOME/Library/LaunchAgents/com.payguard.app.plist" 2>/dev/null
rm -f "$HOME/Library/LaunchAgents/com.payguard.app.plist"

# Remove app directory
rm -rf "$HOME/.payguard"

# Remove from Applications if installed
rm -rf "/Applications/PayGuard.app"

echo "✅ PayGuard uninstalled successfully."
