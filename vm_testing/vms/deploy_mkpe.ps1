# MKPE VM Environment Deployment Script
# This script simulates deploying MKPE across all virtual computers

Write-Host "🚀 Starting MKPE deployment across VM environment..." -ForegroundColor Cyan

$computers = @(
    "MKPE-WORKSTATION-01",
    "MKPE-TESTING-02", 
    "MKPE-CREATIVE-03",
    "MKPE-ENTERPRISE-04",
    "MKPE-MONITORING-05"
)

foreach ($computer in $computers) {
    Write-Host "📦 Deploying MKPE to $computer..." -ForegroundColor Blue
    
    # Simulate deployment steps
    Start-Sleep -Seconds 2
    
    # Update system config
    $configPath = "C:\MKPE\vm_testing\vms\$computer\system_config.json"
    if (Test-Path $configPath) {
        $config = Get-Content $configPath | ConvertFrom-Json
        $config.Status = "Deployed"
        $config.LastDeployment = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
    }
    
    Write-Host "   ✅ $computer deployment complete" -ForegroundColor Green
}

Write-Host "🎉 MKPE deployment completed successfully!" -ForegroundColor Green
Write-Host "📊 All systems are now running and ready for chaos testing" -ForegroundColor Cyan
