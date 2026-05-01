# MKPE Evidence Collection Script
# Collects hard evidence data for legal defensibility and credibility

param(
    [string]$OutputPath = "C:\MKPE\vm_testing\evidence",
    [switch]$IncludeLogs,
    [switch]$IncludeConfigs,
    [switch]$IncludeMetrics
)

Write-Host "📋 MKPE Evidence Collection" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan

# Create evidence directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$collectionTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$evidenceReport = @{
    CollectionTimestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
    CollectionID = "MKPE-EVIDENCE-$collectionTimestamp"
    Collector = "MKPE-VM-Testing-Environment"
    Purpose = "Legal Defensibility and System Credibility"
    Systems = @()
    Summary = @{
        TotalSystems = 0
        HealthySystems = 0
        SystemsWithChaosEvents = 0
        TotalChaosEvents = 0
        AverageRecoveryTime = 0
    }
}

$computers = @(
    "MKPE-WORKSTATION-01",
    "MKPE-TESTING-02",
    "MKPE-CREATIVE-03",
    "MKPE-ENTERPRISE-04",
    "MKPE-MONITORING-05"
)

foreach ($computer in $computers) {
    Write-Host "🔍 Collecting evidence from $computer..." -ForegroundColor Blue
    
    $computerPath = "C:\MKPE\vm_testing\vms\$computer"
    $evidencePath = Join-Path $OutputPath $computer
    
    if (Test-Path $computerPath) {
        New-Item -ItemType Directory -Path $evidencePath -Force | Out-Null
        
        # Collect system configuration
        if ($IncludeConfigs) {
            $configPath = Join-Path $computerPath "system_config.json"
            if (Test-Path $configPath) {
                Copy-Item -Path $configPath -Destination (Join-Path $evidencePath "system_config.json")
            }
            
            $mkpeConfigPath = Join-Path $computerPath "MKPE\service_config.json"
            if (Test-Path $mkpeConfigPath) {
                Copy-Item -Path $mkpeConfigPath -Destination (Join-Path $evidencePath "mkpe_service_config.json")
            }
        }
        
        # Collect logs
        if ($IncludeLogs) {
            $logsPath = Join-Path $computerPath "logs"
            if (Test-Path $logsPath) {
                Copy-Item -Path (Join-Path $logsPath "*") -Destination $evidencePath -Recurse
            }
        }
        
        # Collect metrics and performance data
        if ($IncludeMetrics) {
            $config = Get-Content (Join-Path $computerPath "system_config.json") | ConvertFrom-Json
            $systemEvidence = @{
                ComputerName = $computer
                IPAddress = $config.IPAddress
                Role = $config.Role
                Status = $config.Status
                LastBoot = $config.LastBoot
                MKPEVersion = $config.MKPEVersion
                SystemLoad = $config.SystemLoad
                ChaosEvents = $config.ChaosEvents
                ErrorCount = $config.ErrorLog.Count
                PerformanceMetrics = $config.PerformanceMetrics
            }
            
            $systemEvidence | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $evidencePath "evidence_summary.json") -Encoding UTF8
            
            $evidenceReport.Systems += $systemEvidence
        }
    }
}

# Generate summary report
$evidenceReport.Summary.TotalSystems = $evidenceReport.Systems.Count
$evidenceReport.Summary.HealthySystems = ($evidenceReport.Systems | Where-Object { $_.Status -eq "Deployed" -or $_.Status -eq "Recovered" }).Count
$evidenceReport.Summary.SystemsWithChaosEvents = ($evidenceReport.Systems | Where-Object { $_.ChaosEvents.Count -gt 0 }).Count
$evidenceReport.Summary.TotalChaosEvents = ($evidenceReport.Systems | ForEach-Object { $_.ChaosEvents.Count } | Measure-Object -Sum).Sum

# Generate final evidence report
$evidenceReport | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $OutputPath "evidence_report.json") -Encoding UTF8

Write-Host ""
Write-Host "📊 Evidence Collection Summary:" -ForegroundColor Green
Write-Host "  Total Systems: $($evidenceReport.Summary.TotalSystems)" -ForegroundColor White
Write-Host "  Healthy Systems: $($evidenceReport.Summary.HealthySystems)" -ForegroundColor Green
Write-Host "  Systems with Chaos Events: $($evidenceReport.Summary.SystemsWithChaosEvents)" -ForegroundColor Yellow
Write-Host "  Total Chaos Events: $($evidenceReport.Summary.TotalChaosEvents)" -ForegroundColor Red
Write-Host ""
Write-Host "📁 Evidence collected to: $OutputPath" -ForegroundColor Cyan
Write-Host "🆔 Collection ID: MKPE-EVIDENCE-$collectionTimestamp" -ForegroundColor Cyan
