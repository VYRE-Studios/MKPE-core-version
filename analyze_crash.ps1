# MKPE Crash Analyzer
# Analyzes crash logs and provides diagnostic information

param(
    [switch]$Latest,
    [switch]$All,
    [string]$CrashId
)

Write-Host "🔍 MKPE Crash Analyzer" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host ""

$crashDir = "C:\MKPE\crash_logs"

if (-not (Test-Path $crashDir)) {
    Write-Host "✅ No crashes found!" -ForegroundColor Green
    Write-Host "   Crash log directory doesn't exist yet." -ForegroundColor Gray
    exit 0
}

$crashFiles = Get-ChildItem $crashDir -Filter "*.json" | Sort-Object LastWriteTime -Descending

if ($crashFiles.Count -eq 0) {
    Write-Host "✅ No crashes found!" -ForegroundColor Green
    Write-Host "   No crash log files in directory." -ForegroundColor Gray
    exit 0
}

Write-Host "📊 Found $($crashFiles.Count) crash report(s)" -ForegroundColor Yellow
Write-Host ""

if ($Latest) {
    $crash = $crashFiles[0]
    Write-Host "📋 LATEST CRASH REPORT:" -ForegroundColor Red
    Write-Host "========================" -ForegroundColor Red
    Write-Host ""
    
    $report = Get-Content $crash.FullName | ConvertFrom-Json
    
    Write-Host "Crash ID: $($report.crash_id)" -ForegroundColor White
    Write-Host "Time: $($report.timestamp)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "ERROR MESSAGE:" -ForegroundColor Yellow
    Write-Host "  $($report.panic_message)" -ForegroundColor Red
    Write-Host ""
    
    if ($report.panic_location) {
        Write-Host "LOCATION:" -ForegroundColor Yellow
        Write-Host "  $($report.panic_location)" -ForegroundColor White
        Write-Host ""
    }
    
    Write-Host "SYSTEM INFO:" -ForegroundColor Yellow
    Write-Host "  OS: $($report.system_info.os)" -ForegroundColor White
    Write-Host "  Hostname: $($report.system_info.hostname)" -ForegroundColor White
    Write-Host "  User: $($report.system_info.username)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "PROCESS INFO:" -ForegroundColor Yellow
    Write-Host "  PID: $($report.process_info.pid)" -ForegroundColor White
    Write-Host "  Memory: $($report.process_info.memory_usage_mb) MB" -ForegroundColor White
    Write-Host ""
    
    if ($report.backtrace) {
        Write-Host "BACKTRACE:" -ForegroundColor Yellow
        Write-Host "  (See full report at: $($crash.FullName))" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "Full report: $($crash.FullName)" -ForegroundColor Cyan
    Write-Host "Text report: $($crash.FullName -replace '.json', '.txt')" -ForegroundColor Cyan
    
} elseif ($All) {
    Write-Host "📋 ALL CRASH REPORTS:" -ForegroundColor Yellow
    Write-Host "=====================" -ForegroundColor Yellow
    Write-Host ""
    
    foreach ($crash in $crashFiles) {
        $report = Get-Content $crash.FullName | ConvertFrom-Json
        Write-Host "[$($report.timestamp)] $($report.crash_id)" -ForegroundColor White
        Write-Host "  Error: $($report.panic_message)" -ForegroundColor Red
        if ($report.panic_location) {
            Write-Host "  Location: $($report.panic_location)" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
} elseif ($CrashId) {
    $crash = $crashFiles | Where-Object { $_.BaseName -eq $CrashId }
    if ($crash) {
        Write-Host "📋 CRASH REPORT: $CrashId" -ForegroundColor Yellow
        Write-Host "========================" -ForegroundColor Yellow
        Write-Host ""
        
        Get-Content ($crash.FullName -replace '.json', '.txt')
    } else {
        Write-Host "❌ Crash ID not found: $CrashId" -ForegroundColor Red
    }
} else {
    Write-Host "📋 RECENT CRASHES:" -ForegroundColor Yellow
    Write-Host "==================" -ForegroundColor Yellow
    Write-Host ""
    
    $crashFiles | Select-Object -First 5 | ForEach-Object {
        $report = Get-Content $_.FullName | ConvertFrom-Json
        Write-Host "[$($report.timestamp)] $($report.crash_id)" -ForegroundColor White
        Write-Host "  Error: $($report.panic_message)" -ForegroundColor Red
        Write-Host ""
    }
    
    Write-Host "Use -Latest to see full details of the most recent crash" -ForegroundColor Cyan
    Write-Host "Use -All to list all crashes" -ForegroundColor Cyan
    Write-Host "Use -CrashId <id> to see a specific crash" -ForegroundColor Cyan
}

Write-Host ""
