# MKPE Protection Verification Script
Write-Host "🔍 MKPE PROTECTION VERIFICATION" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

# Check if MKPE is running
Write-Host "1. Checking MKPE Process Status:" -ForegroundColor Yellow
$mkpeProcess = Get-Process MKPE_MODERN -ErrorAction SilentlyContinue
if ($mkpeProcess) {
    Write-Host "   ✅ MKPE is running (PID: $($mkpeProcess.Id))" -ForegroundColor Green
    Write-Host "   📊 CPU Usage: $([math]::Round($mkpeProcess.CPU, 2)) seconds" -ForegroundColor White
    Write-Host "   💾 Memory Usage: $([math]::Round($mkpeProcess.WorkingSet/1MB, 2)) MB" -ForegroundColor White
} else {
    Write-Host "   ❌ MKPE is not running" -ForegroundColor Red
}
Write-Host ""

# Check for config file
Write-Host "2. Checking Configuration:" -ForegroundColor Yellow
$configPath = "C:\MKPE\mkpe_config.json"
if (Test-Path $configPath) {
    Write-Host "   ✅ Config file exists" -ForegroundColor Green
    try {
        $config = Get-Content $configPath | ConvertFrom-Json
        if ($config.watch_paths) {
            Write-Host "   📁 Protected folders:" -ForegroundColor White
            $config.watch_paths | ForEach-Object { Write-Host "      • $_" -ForegroundColor Gray }
        } else {
            Write-Host "   ⚠️  No protected folders configured" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   ❌ Config file is corrupted" -ForegroundColor Red
    }
} else {
    Write-Host "   ⚠️  Config file not found (will be created when you add folders)" -ForegroundColor Yellow
}
Write-Host ""

# Check for secrets vault
Write-Host "3. Checking Secrets Vault:" -ForegroundColor Yellow
$vaultPath = "C:\MKPE\secrets_vault.json"
if (Test-Path $vaultPath) {
    Write-Host "   ✅ Secrets vault exists" -ForegroundColor Green
    try {
        $vault = Get-Content $vaultPath | ConvertFrom-Json
        $fileCount = $vault.file_creations.Count
        Write-Host "   📄 Files tracked: $fileCount" -ForegroundColor White
    } catch {
        Write-Host "   ❌ Vault file is corrupted" -ForegroundColor Red
    }
} else {
    Write-Host "   ⚠️  Secrets vault not found (will be created when you add files)" -ForegroundColor Yellow
}
Write-Host ""

# Check for crash logs
Write-Host "4. Checking System Health:" -ForegroundColor Yellow
$crashDir = "C:\MKPE\crash_logs"
if (Test-Path $crashDir) {
    $crashFiles = Get-ChildItem $crashDir -Filter "*.json" | Measure-Object
    if ($crashFiles.Count -gt 0) {
        Write-Host "   ⚠️  Found $($crashFiles.Count) crash log(s)" -ForegroundColor Yellow
        Write-Host "   📋 Latest crash:" -ForegroundColor White
        $latestCrash = Get-ChildItem $crashDir -Filter "*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Write-Host "      • $($latestCrash.Name) - $($latestCrash.LastWriteTime)" -ForegroundColor Gray
    } else {
        Write-Host "   ✅ No crash logs found (system stable)" -ForegroundColor Green
    }
} else {
    Write-Host "   ✅ No crash logs directory (system stable)" -ForegroundColor Green
}
Write-Host ""

# Test file creation in a protected folder
Write-Host "5. Testing Protection (if folders are configured):" -ForegroundColor Yellow
if (Test-Path $configPath) {
    try {
        $config = Get-Content $configPath | ConvertFrom-Json
        if ($config.watch_paths -and $config.watch_paths.Count -gt 0) {
            $testFolder = $config.watch_paths[0]
            if (Test-Path $testFolder) {
                $testFile = Join-Path $testFolder "mkpe_test_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                "MKPE Protection Test - $(Get-Date)" | Out-File -FilePath $testFile -Encoding UTF8
                Start-Sleep -Seconds 1
                if (Test-Path $testFile) {
                    Write-Host "   ✅ Test file created successfully: $testFile" -ForegroundColor Green
                    Write-Host "   🔍 File hash: $((Get-FileHash $testFile -Algorithm SHA256).Hash)" -ForegroundColor White
                    Remove-Item $testFile -Force
                    Write-Host "   🗑️  Test file cleaned up" -ForegroundColor Gray
                } else {
                    Write-Host "   ❌ Test file creation failed" -ForegroundColor Red
                }
            } else {
                Write-Host "   ⚠️  Protected folder does not exist: $testFolder" -ForegroundColor Yellow
            }
        } else {
            Write-Host "   ℹ️  No protected folders to test" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "   ❌ Error testing protection: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "   ℹ️  No config file to test protection" -ForegroundColor Cyan
}
Write-Host ""

Write-Host "🎯 PROTECTION STATUS SUMMARY:" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
if ($mkpeProcess) {
    Write-Host "✅ MKPE is ACTIVE and monitoring" -ForegroundColor Green
    Write-Host "🔵 Status: PROTECTED (Blue ring should be visible)" -ForegroundColor Blue
} else {
    Write-Host "❌ MKPE is OFFLINE" -ForegroundColor Red
    Write-Host "🔴 Status: OFFLINE (Red ring should be visible)" -ForegroundColor Red
}
Write-Host ""
Write-Host "💡 To verify protection is working:" -ForegroundColor Yellow
Write-Host "   1. Look at the MKPE UI - logo should show blue ring if protected" -ForegroundColor White
Write-Host "   2. Click the logo to toggle protection on/off" -ForegroundColor White
Write-Host "   3. Add folders to protect in the 'Folders' tab" -ForegroundColor White
Write-Host "   4. Check the 'Secrets' tab for file tracking" -ForegroundColor White