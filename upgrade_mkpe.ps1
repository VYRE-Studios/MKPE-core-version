# MKPE Upgrade Script - Install New Version with Secrets Vault
# This script upgrades your existing MKPE installation without losing data

param(
    [switch]$Backup,
    [switch]$SideBySide
)

Write-Host "🚀 MKPE Upgrade Script" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host ""

# Paths
$sourcePath = "C:\MKPE\ui_desktop\target\release\mkpe_desktop.exe"
$oldExePath = "C:\MKPE\MKPE_MODERN.exe"
$newExePath = "C:\MKPE\MKPE_v1.1.0.exe"
$configPath = "C:\Kalyx\MKPE\v1.0.0\mkpe_config.json"
$secretsPath = "C:\MKPE\secrets\vault.json"

# Check if new build exists
if (-not (Test-Path $sourcePath)) {
    Write-Host "❌ New build not found at: $sourcePath" -ForegroundColor Red
    Write-Host "Please build the project first with: cd C:\MKPE\ui_desktop && cargo build --release" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ New build found: $sourcePath" -ForegroundColor Green
$newSize = (Get-Item $sourcePath).Length / 1MB
Write-Host "   Size: $($newSize.ToString('0.00')) MB" -ForegroundColor Gray
Write-Host ""

# Backup existing version
if ($Backup) {
    Write-Host "💾 Backing up existing version..." -ForegroundColor Yellow
    if (Test-Path $oldExePath) {
        $backupPath = "C:\MKPE\backups\MKPE_MODERN_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').exe"
        New-Item -ItemType Directory -Path "C:\MKPE\backups" -Force | Out-Null
        Copy-Item -Path $oldExePath -Destination $backupPath
        Write-Host "   ✅ Backup saved to: $backupPath" -ForegroundColor Green
    }
}

# Stop any running MKPE processes
Write-Host "🛑 Stopping any running MKPE processes..." -ForegroundColor Yellow
$processes = Get-Process | Where-Object { $_.Name -like "*mkpe*" -or $_.Name -like "*MKPE*" }
if ($processes) {
    foreach ($proc in $processes) {
        Write-Host "   Stopping: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Gray
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2
    Write-Host "   ✅ Processes stopped" -ForegroundColor Green
} else {
    Write-Host "   ℹ️  No running MKPE processes found" -ForegroundColor Gray
}
Write-Host ""

# Install new version
if ($SideBySide) {
    Write-Host "📦 Installing new version side-by-side..." -ForegroundColor Blue
    Copy-Item -Path $sourcePath -Destination $newExePath -Force
    Write-Host "   ✅ New version installed: $newExePath" -ForegroundColor Green
    Write-Host "   ℹ️  Old version preserved: $oldExePath" -ForegroundColor Gray
} else {
    Write-Host "📦 Upgrading existing installation..." -ForegroundColor Blue
    Copy-Item -Path $sourcePath -Destination $oldExePath -Force
    Write-Host "   ✅ Installation upgraded: $oldExePath" -ForegroundColor Green
}
Write-Host ""

# Create/verify secrets vault directory
Write-Host "🔐 Setting up secrets vault..." -ForegroundColor Blue
$secretsDir = Split-Path $secretsPath
if (-not (Test-Path $secretsDir)) {
    New-Item -ItemType Directory -Path $secretsDir -Force | Out-Null
    Write-Host "   ✅ Secrets directory created: $secretsDir" -ForegroundColor Green
} else {
    Write-Host "   ✅ Secrets directory exists: $secretsDir" -ForegroundColor Green
}

# Create empty vault if it doesn't exist
if (-not (Test-Path $secretsPath)) {
    "[]" | Out-File -FilePath $secretsPath -Encoding UTF8
    Write-Host "   ✅ Empty vault created: $secretsPath" -ForegroundColor Green
} else {
    Write-Host "   ✅ Existing vault preserved: $secretsPath" -ForegroundColor Green
}
Write-Host ""

# Verify config file
Write-Host "⚙️  Verifying configuration..." -ForegroundColor Blue
if (Test-Path $configPath) {
    Write-Host "   ✅ Config file found: $configPath" -ForegroundColor Green
    
    # Read and display protected folders
    $config = Get-Content $configPath | ConvertFrom-Json
    if ($config.service_config.watch_paths) {
        Write-Host "   📁 Protected folders:" -ForegroundColor Gray
        foreach ($path in $config.service_config.watch_paths) {
            Write-Host "      - $path" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "   ⚠️  Config file not found: $configPath" -ForegroundColor Yellow
    Write-Host "   ℹ️  Will be created on first run" -ForegroundColor Gray
}
Write-Host ""

# Display what's new
Write-Host "🎉 What's New in v1.1.0:" -ForegroundColor Cyan
Write-Host "   🔐 Secrets Vault - Track .dcx, .pdf, .rs file creation" -ForegroundColor White
Write-Host "   🛡️  Trust Indicators - Visual trust levels for all files" -ForegroundColor White
Write-Host "   📊 Enhanced Monitoring - Real-time system health tracking" -ForegroundColor White
Write-Host "   🔧 Fixed Icons - System tray icon now works reliably" -ForegroundColor White
Write-Host "   💾 Fixed Persistence - Protected folders now save correctly" -ForegroundColor White
Write-Host ""

# Launch options
Write-Host "🚀 Ready to Launch!" -ForegroundColor Green
Write-Host ""
Write-Host "Choose an option:" -ForegroundColor Yellow
Write-Host "  1. Launch new version now" -ForegroundColor White
Write-Host "  2. View installation details" -ForegroundColor White
Write-Host "  3. Exit (launch manually later)" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Enter choice (1-3)"

switch ($choice) {
    "1" {
        Write-Host ""
        Write-Host "🚀 Launching MKPE v1.1.0..." -ForegroundColor Cyan
        if ($SideBySide) {
            Start-Process -FilePath $newExePath
            Write-Host "   ✅ New version launched: $newExePath" -ForegroundColor Green
        } else {
            Start-Process -FilePath $oldExePath
            Write-Host "   ✅ Upgraded version launched: $oldExePath" -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "💡 Look for the new 'Vault' tab (🔐) in the UI!" -ForegroundColor Cyan
    }
    "2" {
        Write-Host ""
        Write-Host "📋 Installation Details:" -ForegroundColor Cyan
        Write-Host "   Executable: $(if ($SideBySide) { $newExePath } else { $oldExePath })" -ForegroundColor White
        Write-Host "   Config: $configPath" -ForegroundColor White
        Write-Host "   Secrets Vault: $secretsPath" -ForegroundColor White
        Write-Host "   Backup: C:\MKPE\backups\" -ForegroundColor White
    }
    "3" {
        Write-Host ""
        Write-Host "✅ Upgrade complete! Launch manually when ready." -ForegroundColor Green
    }
    default {
        Write-Host ""
        Write-Host "❌ Invalid choice. Exiting." -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "🎉 Upgrade Complete!" -ForegroundColor Green
Write-Host ""
