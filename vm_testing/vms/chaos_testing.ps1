# MKPE Chaos Testing Script
# Simulates chaos events across the VM environment

param(
    [string]$TargetComputer = "ALL",
    [string]$EventType = "Random",
    [int]$Duration = 60
)

Write-Host "⚡ Starting MKPE Chaos Testing..." -ForegroundColor Red
Write-Host "Target: $TargetComputer" -ForegroundColor Yellow
Write-Host "Event Type: $EventType" -ForegroundColor Yellow
Write-Host "Duration: $Duration seconds" -ForegroundColor Yellow
Write-Host ""

$computers = @(
    "MKPE-WORKSTATION-01",
    "MKPE-TESTING-02",
    "MKPE-CREATIVE-03", 
    "MKPE-ENTERPRISE-04",
    "MKPE-MONITORING-05"
)

if ($TargetComputer -ne "ALL") {
    $computers = @($TargetComputer)
}

$eventTypes = @(
    "NetworkLatency",
    "ResourceExhaustion", 
    "ServiceRestart",
    "DataCorruption",
    "SecurityBreach"
)

foreach ($computer in $computers) {
    $selectedEvent = if ($EventType -eq "Random") { 
        $eventTypes | Get-Random 
    } else { 
        $EventType 
    }
    
    Write-Host "🔥 Triggering $selectedEvent on $computer..." -ForegroundColor Red
    
    # Simulate chaos event
    Start-Sleep -Seconds 3
    
    # Update system config to reflect chaos event
    $configPath = "C:\MKPE\vm_testing\vms\$computer\system_config.json"
    if (Test-Path $configPath) {
        $config = Get-Content $configPath | ConvertFrom-Json
        $config.Status = "Chaos Event: $selectedEvent"
        $config.SystemLoad.CPU = 85
        $config.SystemLoad.Memory = 90
        
        # Add chaos event to log
        $chaosEvent = @{
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
            EventType = $selectedEvent
            Duration = $Duration
            Impact = "Simulated chaos event"
        }
        
        if (-not $config.ChaosEvents) {
            $config.ChaosEvents = @()
        }
        $config.ChaosEvents += $chaosEvent
        
        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
    }
    
    Write-Host "   ⚡ $selectedEvent triggered on $computer" -ForegroundColor Yellow
    
    # Wait for event duration
    Start-Sleep -Seconds $Duration
    
    # Simulate recovery
    Write-Host "🔄 Recovering $computer..." -ForegroundColor Green
    Start-Sleep -Seconds 2
    
    # Update config to show recovery
    if (Test-Path $configPath) {
        $config = Get-Content $configPath | ConvertFrom-Json
        $config.Status = "Recovered"
        $config.SystemLoad.CPU = 25
        $config.SystemLoad.Memory = 45
        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
    }
    
    Write-Host "   ✅ $computer recovered successfully" -ForegroundColor Green
}

Write-Host ""
Write-Host "🎉 Chaos testing completed!" -ForegroundColor Cyan
Write-Host "📊 All systems have been tested and recovered" -ForegroundColor Green
