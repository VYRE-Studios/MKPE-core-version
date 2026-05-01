# MKPE Complete Launcher - Starts both UI and System Tray
# This script launches the full MKPE system with all components

Write-Host "🚀 Launching MKPE Complete System..." -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""

# Check if already running
$existingUI = Get-Process MKPE_MODERN -ErrorAction SilentlyContinue
$existingTray = Get-Process mkpe_tray -ErrorAction SilentlyContinue
$existingService = Get-Process mkpe_service -ErrorAction SilentlyContinue

if ($existingUI -or $existingTray -or $existingService) {
    Write-Host "⚠️ MKPE components already running:" -ForegroundColor Yellow
    if ($existingUI) { Write-Host "   - Desktop UI (PID $($existingUI.Id))" -ForegroundColor Gray }
    if ($existingTray) { Write-Host "   - System Tray (PID $($existingTray.Id))" -ForegroundColor Gray }
    if ($existingService) { Write-Host "   - Background Service (PID $($existingService.Id))" -ForegroundColor Gray }
    Write-Host ""
    
    $choice = Read-Host "Restart all components? (y/N)"
    if ($choice -eq "y" -or $choice -eq "Y") {
        Write-Host "🛑 Stopping existing processes..." -ForegroundColor Yellow
        if ($existingUI) { Stop-Process -Id $existingUI.Id -Force -ErrorAction SilentlyContinue }
        if ($existingTray) { Stop-Process -Id $existingTray.Id -Force -ErrorAction SilentlyContinue }
        if ($existingService) { Stop-Process -Id $existingService.Id -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 2
        Write-Host "   ✅ Stopped" -ForegroundColor Green
    } else {
        Write-Host "✅ Keeping existing processes running" -ForegroundColor Green
        exit 0
    }
}

Write-Host ""
Write-Host "📦 Starting MKPE components..." -ForegroundColor Blue

# 1. Start Background Service
Write-Host "   1/3 Starting background service..." -ForegroundColor Gray
if (Test-Path "C:\Kalyx\MKPE\v1.0.0\service\mkpe_service.exe") {
    Start-Process "C:\Kalyx\MKPE\v1.0.0\service\mkpe_service.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 1
    $svc = Get-Process mkpe_service -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "       ✅ Service running (PID $($svc.Id))" -ForegroundColor Green
    } else {
        Write-Host "       ⚠️ Service not started" -ForegroundColor Yellow
    }
} else {
    Write-Host "       ⚠️ Service not found" -ForegroundColor Yellow
}

# 2. Start System Tray
Write-Host "   2/3 Starting system tray..." -ForegroundColor Gray
if (Test-Path "C:\MKPE\ui_tray\target\release\mkpe_tray.exe") {
    Start-Process "C:\MKPE\ui_tray\target\release\mkpe_tray.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 2
    $tray = Get-Process mkpe_tray -ErrorAction SilentlyContinue
    if ($tray) {
        Write-Host "       ✅ System tray running (PID $($tray.Id))" -ForegroundColor Green
        Write-Host "       💡 Icon visible in system tray" -ForegroundColor Cyan
    } else {
        Write-Host "       ❌ Tray app failed to start" -ForegroundColor Red
    }
} else {
    Write-Host "       ❌ Tray executable not found" -ForegroundColor Red
}

# 3. Start Desktop UI
Write-Host "   3/3 Starting desktop UI..." -ForegroundColor Gray
if (Test-Path "C:\MKPE\MKPE_MODERN.exe") {
    Start-Process "C:\MKPE\MKPE_MODERN.exe"
    Start-Sleep -Seconds 2
    $ui = Get-Process MKPE_MODERN -ErrorAction SilentlyContinue
    if ($ui) {
        Write-Host "       ✅ Desktop UI running (PID $($ui.Id))" -ForegroundColor Green
        Write-Host "       💡 Window should be visible" -ForegroundColor Cyan
    } else {
        Write-Host "       ❌ UI failed to start" -ForegroundColor Red
    }
} else {
    Write-Host "       ❌ UI executable not found" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎉 MKPE Launch Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📊 System Status:" -ForegroundColor Cyan
$allProcs = Get-Process | Where-Object { $_.Name -like "*mkpe*" -or $_.Name -eq "MKPE_MODERN" }
if ($allProcs) {
    $allProcs | Format-Table @{Label="Component";Expression={$_.Name}}, @{Label="PID";Expression={$_.Id}}, @{Label="Memory (MB)";Expression={[math]::Round($_.WorkingSet64/1MB,2)}} -AutoSize
} else {
    Write-Host "   ⚠️ No MKPE processes detected" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "✨ All components running! Check the system tray for the MKPE icon." -ForegroundColor Green
Write-Host ""
