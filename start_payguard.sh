#!/bin/bash
# PayGuard Startup Script

echo "🛡️ Starting PayGuard..."

# Change to PayGuard directory
cd "$(dirname "$0")"

# Start PayGuard
python3 payguard_menubar.py