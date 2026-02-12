# PayGuard Windows Installer
# Usage: irm https://payguard.com/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host "🛡️  PayGuard Installer" -ForegroundColor Cyan
Write-Host ""

$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
Write-Host "📱 Detected: Windows ($arch)" -ForegroundColor Blue

$version = "${env:VERSION:-1.0.0}"
$repo = "payguard/payguard"
$installDir = "$env:LOCALAPPDATA\PayGuard"
$downloadUrl = "https://github.com/$repo/releases/download/v$version/PayGuard-v$version-windows.zip"

New-Item -ItemType Directory -Force -Path $installDir | Out-Null

Write-Host "📥 Downloading PayGuard v$version..." -ForegroundColor Blue

try {
    $tempFile = "$env:TEMP\PayGuard.zip"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
    
    Write-Host "📦 Extracting..." -ForegroundColor Blue
    Expand-Archive -Path $tempFile -DestinationPath $installDir -Force
    Remove-Item $tempFile
} catch {
    Write-Host "❌ Download failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Installed to $installDir" -ForegroundColor Green

# Add to PATH
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
    Write-Host "📝 Added to PATH" -ForegroundColor Green
}

# Create shortcuts
$WshShell = New-Object -comObject WScript.Shell
$startMenu = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"

$Shortcut = $WshShell.CreateShortcut("$startMenu\PayGuard.lnk")
$Shortcut.TargetPath = "$installDir\PayGuard.exe"
$Shortcut.Save()

$StartupShortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\PayGuard.lnk")
$StartupShortcut.TargetPath = "$installDir\PayGuard.exe"
$StartupShortcut.Save()

Write-Host ""
Write-Host "🚀 Starting PayGuard..." -ForegroundColor Blue
Start-Process -FilePath "$installDir\PayGuard.exe"

Write-Host ""
Write-Host "✨ PayGuard is running!" -ForegroundColor Green
Write-Host "Look for the shield icon in your system tray" -ForegroundColor White
Write-Host ""
Write-Host "❤️  Star us: https://github.com/payguard/payguard" -ForegroundColor Gray
