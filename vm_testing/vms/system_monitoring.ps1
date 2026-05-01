# MKPE System Status Monitoring
# Monitors all VM computers and generates status reports

param(
    [switch]$Continuous,
    [int]$IntervalSeconds = 30
)

function Get-SystemStatus {
    param([string]$ComputerName)
    
    $configPath = "C:\MKPE\vm_testing\vms\$ComputerName\system_config.json"
    if (Test-Path $configPath) {
        return Get-Content $configPath | ConvertFrom-Json
    }
    return $null
}

function Show-SystemDashboard {
    Clear-Host
    Write-Host "📊 MKPE System Monitoring Dashboard" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host "Last Updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    $computers = @(
        "MKPE-WORKSTATION-01",
        "MKPE-TESTING-02",
        "MKPE-CREATIVE-03",
        "MKPE-ENTERPRISE-04", 
        "MKPE-MONITORING-05"
    )
    
    $totalSystems = $computers.Count
    $healthySystems = 0
    $warningSystems = 0
    $criticalSystems = 0
    
    foreach ($computer in $computers) {
        $status = Get-SystemStatus -ComputerName $computer
        if ($status) {
            $statusColor = switch ($status.Status) {
                "Deployed" { "Green"; $healthySystems++ }
                "Recovered" { "Green"; $healthySystems++ }
                {$_ -like "Chaos Event:*"} { "Yellow"; $warningSystems++ }
                default { "Red"; $criticalSystems++ }
            }
            
            Write-Host "🖥️ $($computer.PadRight(20)) " -NoNewline -ForegroundColor $statusColor
            Write-Host "$($status.Status.PadRight(25)) " -NoNewline -ForegroundColor $statusColor
            Write-Host "CPU:$($status.SystemLoad.CPU.ToString().PadLeft(3))% " -NoNewline -ForegroundColor Gray
            Write-Host "MEM:$($status.SystemLoad.Memory.ToString().PadLeft(3))% " -NoNewline -ForegroundColor Gray
            Write-Host "Events:$($status.ChaosEvents.Count)" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
    Write-Host "📈 System Health Overview:" -ForegroundColor Cyan
    Write-Host "  Healthy: $healthySystems/$totalSystems ($( [math]::Round(($healthySystems/$totalSystems)*100, 1) )%)" -ForegroundColor Green
    Write-Host "  Warning: $warningSystems/$totalSystems ($( [math]::Round(($warningSystems/$totalSystems)*100, 1) )%)" -ForegroundColor Yellow  
    Write-Host "  Critical: $criticalSystems/$totalSystems ($( [math]::Round(($criticalSystems/$totalSystems)*100, 1) )%)" -ForegroundColor Red
}

if ($Continuous) {
    Write-Host "🔄 Starting continuous monitoring (Press Ctrl+C to stop)..." -ForegroundColor Cyan
    while ($true) {
        Show-SystemDashboard
        Start-Sleep -Seconds $IntervalSeconds
    }
} else {
    Show-SystemDashboard
}
