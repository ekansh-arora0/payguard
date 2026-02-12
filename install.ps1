# PayGuard Windows Installer
# Usage: Invoke-WebRequest -Uri "https://payguard.com/install.ps1" -UseBasicParsing | Invoke-Expression

$ErrorActionPreference = "Stop"

Write-Host "🛡️  PayGuard Installer for Windows" -ForegroundColor Cyan
Write-Host ""

# Detect architecture
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
Write-Host "📱 Detected: Windows ($arch)" -ForegroundColor Blue

# Set paths
$version = "1.0.0"
$installDir = "$env:LOCALAPPDATA\PayGuard"
$downloadUrl = "https://github.com/payguard/payguard/releases/download/v$version/payguard-windows-$arch.exe"

# Create install directory
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

Write-Host "📥 Downloading PayGuard v$version..." -ForegroundColor Blue
Write-Host "   From: $downloadUrl" -ForegroundColor Gray

try {
    # Download using different methods for compatibility
    if (Get-Command 'Invoke-WebRequest' -ErrorAction SilentlyContinue) {
        Invoke-WebRequest -Uri $downloadUrl -OutFile "$installDir\payguard.exe" -UseBasicParsing
    } else {
        # Fallback for older Windows
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($downloadUrl, "$installDir\payguard.exe")
    }
} catch {
    Write-Host "❌ Download failed. Please check your internet connection." -ForegroundColor Red
    exit 1
}

Write-Host "📦 Installing to $installDir..." -ForegroundColor Blue

# Add to PATH if not already there
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
    Write-Host "📝 Added $installDir to PATH" -ForegroundColor Green
}

# Create Start Menu shortcut
$startMenu = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
$shortcutPath = "$startMenu\PayGuard.lnk"
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($shortcutPath)
$Shortcut.TargetPath = "$installDir\payguard.exe"
$Shortcut.WorkingDirectory = $installDir
$Shortcut.Description = "PayGuard - Phishing Protection"
$Shortcut.Save()

# Also add to startup
$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\PayGuard.lnk"
$StartupShortcut = $WshShell.CreateShortcut($startupPath)
$StartupShortcut.TargetPath = "$installDir\payguard.exe"
$StartupShortcut.WorkingDirectory = $installDir
$StartupShortcut.Save()

Write-Host "✅ Installed to $installDir" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 Starting PayGuard..." -ForegroundColor Blue

# Start PayGuard
Start-Process -FilePath "$installDir\payguard.exe"

Write-Host ""
Write-Host "✨ PayGuard is now running!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Next steps:" -ForegroundColor White
Write-Host "   1. Look for the PayGuard shield icon in your system tray"
Write-Host "   2. Right-click it to configure your settings"
Write-Host "   3. Browse safely - we'll warn you about suspicious sites"
Write-Host ""
Write-Host "💡 Tip: Open a new PowerShell window and run 'payguard --help' for options" -ForegroundColor Gray
Write-Host ""
Write-Host "🐛 Found a bug? Report it at: https://github.com/payguard/payguard/issues" -ForegroundColor Gray
Write-Host "❤️  Enjoying PayGuard? Star us on GitHub!" -ForegroundColor Gray
