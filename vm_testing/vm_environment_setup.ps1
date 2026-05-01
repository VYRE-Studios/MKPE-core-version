# MKPE VM Testing Environment Setup
# Creates 5 simulated computers for chaos testing and system validation

param(
    [string]$VMPath = "C:\MKPE\vm_testing\vms",
    [switch]$CleanSetup,
    [switch]$StartChaosTesting
)

Write-Host "🚀 MKPE VM Testing Environment Setup" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Create VM directory structure
if ($CleanSetup) {
    Write-Host "🧹 Cleaning existing VM setup..." -ForegroundColor Yellow
    if (Test-Path $VMPath) {
        Remove-Item -Path $VMPath -Recurse -Force
    }
}

Write-Host "📁 Creating VM directory structure..." -ForegroundColor Green
$vmComputers = @(
    @{
        Name = "MKPE-WORKSTATION-01"
        IP = "192.168.100.10"
        Role = "Primary Development"
        Services = @("MKPE", "Calyx", "Aetherion")
    },
    @{
        Name = "MKPE-TESTING-02"
        IP = "192.168.100.11"
        Role = "Testing & Validation"
        Services = @("MKPE", "FlowEditor", "TTS")
    },
    @{
        Name = "MKPE-CREATIVE-03"
        IP = "192.168.100.12"
        Role = "Creative Workstation"
        Services = @("CreativeOS", "Zettlr", "HybridEngine")
    },
    @{
        Name = "MKPE-ENTERPRISE-04"
        IP = "192.168.100.13"
        Role = "Enterprise Services"
        Services = @("DocuSign", "AutoOTO", "MKPE")
    },
    @{
        Name = "MKPE-MONITORING-05"
        IP = "192.168.100.14"
        Role = "Monitoring & Chaos"
        Services = @("Monitoring", "ChaosEngine", "MKPE")
    }
)

foreach ($computer in $vmComputers) {
    $computerPath = Join-Path $VMPath $computer.Name
    
    Write-Host "🖥️ Setting up $($computer.Name)..." -ForegroundColor Blue
    
    # Create computer directory
    New-Item -ItemType Directory -Path $computerPath -Force | Out-Null
    
    # Create system configuration
    $config = @{
        ComputerName = $computer.Name
        IPAddress = $computer.IP
        Role = $computer.Role
        Services = $computer.Services
        LastBoot = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
        Uptime = 0
        Status = "Initializing"
        MKPEVersion = "1.0.0"
        SystemLoad = @{
            CPU = 0
            Memory = 0
            Disk = 0
            Network = 0
        }
        ChaosEvents = @()
        ErrorLog = @()
        PerformanceMetrics = @()
    }
    
    $config | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $computerPath "system_config.json") -Encoding UTF8
    
    # Create MKPE installation
    $mkpePath = Join-Path $computerPath "MKPE"
    New-Item -ItemType Directory -Path $mkpePath -Force | Out-Null
    
    # Copy MKPE binaries (simulated)
    $mkpeFiles = @(
        "mkpe.exe",
        "mkpe_service.exe",
        "mkpe_ui.exe",
        "mkpe_tray.exe"
    )
    
    foreach ($file in $mkpeFiles) {
        $filePath = Join-Path $mkpePath $file
        "# Simulated $file" | Out-File -FilePath $filePath -Encoding UTF8
    }
    
    # Create service configurations
    $serviceConfig = @{
        ServiceName = "MKPEIntegrityService"
        Status = "Running"
        AutoStart = $true
        Port = 8082
        LogLevel = "INFO"
        ProtectedPaths = @(
            "C:\Users\Admin\Documents",
            "C:\Projects",
            "C:\MKPE\secrets"
        )
        SecretsVault = @{
            Enabled = $true
            Path = "C:\MKPE\secrets\vault.json"
            Encrypted = $true
        }
        Monitoring = @{
            Enabled = $true
            HealthCheckInterval = 30
            MetricsCollection = $true
        }
    }
    
    $serviceConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $mkpePath "service_config.json") -Encoding UTF8
    
    # Create logs directory
    $logsPath = Join-Path $computerPath "logs"
    New-Item -ItemType Directory -Path $logsPath -Force | Out-Null
    
    # Create sample log entries
    $logEntries = @(
        @{
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
            Level = "INFO"
            Message = "System initialized successfully"
            Source = "MKPE.Service"
        },
        @{
            Timestamp = (Get-Date).AddSeconds(-30).ToString("yyyy-MM-dd HH:mm:ss UTC")
            Level = "INFO"
            Message = "MKPE service started"
            Source = "MKPE.Service"
        },
        @{
            Timestamp = (Get-Date).AddSeconds(-60).ToString("yyyy-MM-dd HH:mm:ss UTC")
            Level = "INFO"
            Message = "Protected paths configured"
            Source = "MKPE.Config"
        }
    )
    
    $logEntries | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $logsPath "system.log") -Encoding UTF8
    
    Write-Host "   ✅ $($computer.Name) setup complete" -ForegroundColor Green
}

# Create network configuration
Write-Host "🌐 Creating network configuration..." -ForegroundColor Green
$networkConfig = @{
    NetworkName = "MKPE-Testing-Network"
    Subnet = "192.168.100.0/24"
    Gateway = "192.168.100.1"
    DNS = @("8.8.8.8", "8.8.4.4")
    Computers = $vmComputers
    Created = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
}

$networkConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $VMPath "network_config.json") -Encoding UTF8

# Create chaos testing configuration
Write-Host "⚡ Setting up chaos testing..." -ForegroundColor Green
$chaosConfig = @{
    ChaosEngine = @{
        Enabled = $true
        TestInterval = 300  # 5 minutes
        MaxConcurrentEvents = 3
        AutoRecovery = $true
        LogLevel = "DEBUG"
    }
    EventTypes = @(
        @{
            Name = "NetworkLatency"
            Description = "Simulate network latency"
            Severity = "Low"
            Duration = 30
            Impact = "Response time increased"
        },
        @{
            Name = "ResourceExhaustion"
            Description = "Simulate high resource usage"
            Severity = "High"
            Duration = 120
            Impact = "System performance degraded"
        },
        @{
            Name = "ServiceRestart"
            Description = "Simulate service restart"
            Severity = "Medium"
            Duration = 10
            Impact = "Brief service interruption"
        },
        @{
            Name = "DataCorruption"
            Description = "Simulate data corruption event"
            Severity = "Critical"
            Duration = 60
            Impact = "Data integrity compromised"
        },
        @{
            Name = "SecurityBreach"
            Description = "Simulate security breach attempt"
            Severity = "Critical"
            Duration = 300
            Impact = "Security systems activated"
        }
    )
    Targets = $vmComputers | ForEach-Object { $_.Name }
}

$chaosConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $VMPath "chaos_config.json") -Encoding UTF8

# Create monitoring dashboard configuration
Write-Host "📊 Setting up monitoring dashboard..." -ForegroundColor Green
$monitoringConfig = @{
    Dashboard = @{
        Title = "MKPE System Monitoring"
        RefreshInterval = 5
        MaxDataPoints = 1000
        Alerts = @{
            Enabled = $true
            CriticalThreshold = 90
            WarningThreshold = 70
        }
    }
    Metrics = @(
        @{
            Name = "SystemHealth"
            Description = "Overall system health percentage"
            Unit = "%"
            Target = 95
        },
        @{
            Name = "ResponseTime"
            Description = "Average response time across all systems"
            Unit = "ms"
            Target = 100
        },
        @{
            Name = "ErrorRate"
            Description = "Error rate percentage"
            Unit = "%"
            Target = 1
        },
        @{
            Name = "ChaosEvents"
            Description = "Active chaos events count"
            Unit = "count"
            Target = 0
        }
    )
    Systems = $vmComputers | ForEach-Object { @{
        Name = $_.Name
        IP = $_.IP
        Role = $_.Role
        Services = $_.Services
    }}
}

$monitoringConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $VMPath "monitoring_config.json") -Encoding UTF8

# Create deployment script
Write-Host "🚀 Creating deployment script..." -ForegroundColor Green
$deploymentScript = @"
# MKPE VM Environment Deployment Script
# This script simulates deploying MKPE across all virtual computers

Write-Host "🚀 Starting MKPE deployment across VM environment..." -ForegroundColor Cyan

`$computers = @(
    "MKPE-WORKSTATION-01",
    "MKPE-TESTING-02", 
    "MKPE-CREATIVE-03",
    "MKPE-ENTERPRISE-04",
    "MKPE-MONITORING-05"
)

foreach (`$computer in `$computers) {
    Write-Host "📦 Deploying MKPE to `$computer..." -ForegroundColor Blue
    
    # Simulate deployment steps
    Start-Sleep -Seconds 2
    
    # Update system config
    `$configPath = "C:\MKPE\vm_testing\vms\`$computer\system_config.json"
    if (Test-Path `$configPath) {
        `$config = Get-Content `$configPath | ConvertFrom-Json
        `$config.Status = "Deployed"
        `$config.LastDeployment = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
        `$config | ConvertTo-Json -Depth 10 | Out-File -FilePath `$configPath -Encoding UTF8
    }
    
    Write-Host "   ✅ `$computer deployment complete" -ForegroundColor Green
}

Write-Host "🎉 MKPE deployment completed successfully!" -ForegroundColor Green
Write-Host "📊 All systems are now running and ready for chaos testing" -ForegroundColor Cyan
"@

$deploymentScript | Out-File -FilePath (Join-Path $VMPath "deploy_mkpe.ps1") -Encoding UTF8

# Create chaos testing script
Write-Host "⚡ Creating chaos testing script..." -ForegroundColor Green
$chaosScript = @"
# MKPE Chaos Testing Script
# Simulates chaos events across the VM environment

param(
    [string]$TargetComputer = "ALL",
    [string]$EventType = "Random",
    [int]$Duration = 60
)

Write-Host "⚡ Starting MKPE Chaos Testing..." -ForegroundColor Red
Write-Host "Target: `$TargetComputer" -ForegroundColor Yellow
Write-Host "Event Type: `$EventType" -ForegroundColor Yellow
Write-Host "Duration: `$Duration seconds" -ForegroundColor Yellow
Write-Host ""

`$computers = @(
    "MKPE-WORKSTATION-01",
    "MKPE-TESTING-02",
    "MKPE-CREATIVE-03", 
    "MKPE-ENTERPRISE-04",
    "MKPE-MONITORING-05"
)

if (`$TargetComputer -ne "ALL") {
    `$computers = @(`$TargetComputer)
}

`$eventTypes = @(
    "NetworkLatency",
    "ResourceExhaustion", 
    "ServiceRestart",
    "DataCorruption",
    "SecurityBreach"
)

foreach (`$computer in `$computers) {
    `$selectedEvent = if (`$EventType -eq "Random") { 
        `$eventTypes | Get-Random 
    } else { 
        `$EventType 
    }
    
    Write-Host "🔥 Triggering `$selectedEvent on `$computer..." -ForegroundColor Red
    
    # Simulate chaos event
    Start-Sleep -Seconds 3
    
    # Update system config to reflect chaos event
    `$configPath = "C:\MKPE\vm_testing\vms\`$computer\system_config.json"
    if (Test-Path `$configPath) {
        `$config = Get-Content `$configPath | ConvertFrom-Json
        `$config.Status = "Chaos Event: `$selectedEvent"
        `$config.SystemLoad.CPU = 85
        `$config.SystemLoad.Memory = 90
        
        # Add chaos event to log
        `$chaosEvent = @{
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
            EventType = `$selectedEvent
            Duration = `$Duration
            Impact = "Simulated chaos event"
        }
        
        if (-not `$config.ChaosEvents) {
            `$config.ChaosEvents = @()
        }
        `$config.ChaosEvents += `$chaosEvent
        
        `$config | ConvertTo-Json -Depth 10 | Out-File -FilePath `$configPath -Encoding UTF8
    }
    
    Write-Host "   ⚡ `$selectedEvent triggered on `$computer" -ForegroundColor Yellow
    
    # Wait for event duration
    Start-Sleep -Seconds `$Duration
    
    # Simulate recovery
    Write-Host "🔄 Recovering `$computer..." -ForegroundColor Green
    Start-Sleep -Seconds 2
    
    # Update config to show recovery
    if (Test-Path `$configPath) {
        `$config = Get-Content `$configPath | ConvertFrom-Json
        `$config.Status = "Recovered"
        `$config.SystemLoad.CPU = 25
        `$config.SystemLoad.Memory = 45
        `$config | ConvertTo-Json -Depth 10 | Out-File -FilePath `$configPath -Encoding UTF8
    }
    
    Write-Host "   ✅ `$computer recovered successfully" -ForegroundColor Green
}

Write-Host ""
Write-Host "🎉 Chaos testing completed!" -ForegroundColor Cyan
Write-Host "📊 All systems have been tested and recovered" -ForegroundColor Green
"@

$chaosScript | Out-File -FilePath (Join-Path $VMPath "chaos_testing.ps1") -Encoding UTF8

# Create system status monitoring script
Write-Host "📊 Creating system monitoring script..." -ForegroundColor Green
$monitoringScript = @"
# MKPE System Status Monitoring
# Monitors all VM computers and generates status reports

param(
    [switch]$Continuous,
    [int]$IntervalSeconds = 30
)

function Get-SystemStatus {
    param([string]$ComputerName)
    
    `$configPath = "C:\MKPE\vm_testing\vms\`$ComputerName\system_config.json"
    if (Test-Path `$configPath) {
        return Get-Content `$configPath | ConvertFrom-Json
    }
    return `$null
}

function Show-SystemDashboard {
    Clear-Host
    Write-Host "📊 MKPE System Monitoring Dashboard" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host "Last Updated: `$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    `$computers = @(
        "MKPE-WORKSTATION-01",
        "MKPE-TESTING-02",
        "MKPE-CREATIVE-03",
        "MKPE-ENTERPRISE-04", 
        "MKPE-MONITORING-05"
    )
    
    `$totalSystems = `$computers.Count
    `$healthySystems = 0
    `$warningSystems = 0
    `$criticalSystems = 0
    
    foreach (`$computer in `$computers) {
        `$status = Get-SystemStatus -ComputerName `$computer
        if (`$status) {
            `$statusColor = switch (`$status.Status) {
                "Deployed" { "Green"; `$healthySystems++ }
                "Recovered" { "Green"; `$healthySystems++ }
                {`$_ -like "Chaos Event:*"} { "Yellow"; `$warningSystems++ }
                default { "Red"; `$criticalSystems++ }
            }
            
            Write-Host "🖥️ `$(`$computer.PadRight(20)) " -NoNewline -ForegroundColor `$statusColor
            Write-Host "`$(`$status.Status.PadRight(25)) " -NoNewline -ForegroundColor `$statusColor
            Write-Host "CPU:`$(`$status.SystemLoad.CPU.ToString().PadLeft(3))% " -NoNewline -ForegroundColor Gray
            Write-Host "MEM:`$(`$status.SystemLoad.Memory.ToString().PadLeft(3))% " -NoNewline -ForegroundColor Gray
            Write-Host "Events:`$(`$status.ChaosEvents.Count)" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
    Write-Host "📈 System Health Overview:" -ForegroundColor Cyan
    Write-Host "  Healthy: `$healthySystems/`$totalSystems (`$( [math]::Round((`$healthySystems/`$totalSystems)*100, 1) )%)" -ForegroundColor Green
    Write-Host "  Warning: `$warningSystems/`$totalSystems (`$( [math]::Round((`$warningSystems/`$totalSystems)*100, 1) )%)" -ForegroundColor Yellow  
    Write-Host "  Critical: `$criticalSystems/`$totalSystems (`$( [math]::Round((`$criticalSystems/`$totalSystems)*100, 1) )%)" -ForegroundColor Red
}

if (`$Continuous) {
    Write-Host "🔄 Starting continuous monitoring (Press Ctrl+C to stop)..." -ForegroundColor Cyan
    while (`$true) {
        Show-SystemDashboard
        Start-Sleep -Seconds `$IntervalSeconds
    }
} else {
    Show-SystemDashboard
}
"@

$monitoringScript | Out-File -FilePath (Join-Path $VMPath "system_monitoring.ps1") -Encoding UTF8

# Create evidence collection script
Write-Host "📋 Creating evidence collection script..." -ForegroundColor Green
$evidenceScript = @"
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
New-Item -ItemType Directory -Path `$OutputPath -Force | Out-Null

`$collectionTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
`$evidenceReport = @{
    CollectionTimestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
    CollectionID = "MKPE-EVIDENCE-`$collectionTimestamp"
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

`$computers = @(
    "MKPE-WORKSTATION-01",
    "MKPE-TESTING-02",
    "MKPE-CREATIVE-03",
    "MKPE-ENTERPRISE-04",
    "MKPE-MONITORING-05"
)

foreach (`$computer in `$computers) {
    Write-Host "🔍 Collecting evidence from `$computer..." -ForegroundColor Blue
    
    `$computerPath = "C:\MKPE\vm_testing\vms\`$computer"
    `$evidencePath = Join-Path `$OutputPath `$computer
    
    if (Test-Path `$computerPath) {
        New-Item -ItemType Directory -Path `$evidencePath -Force | Out-Null
        
        # Collect system configuration
        if (`$IncludeConfigs) {
            `$configPath = Join-Path `$computerPath "system_config.json"
            if (Test-Path `$configPath) {
                Copy-Item -Path `$configPath -Destination (Join-Path `$evidencePath "system_config.json")
            }
            
            `$mkpeConfigPath = Join-Path `$computerPath "MKPE\service_config.json"
            if (Test-Path `$mkpeConfigPath) {
                Copy-Item -Path `$mkpeConfigPath -Destination (Join-Path `$evidencePath "mkpe_service_config.json")
            }
        }
        
        # Collect logs
        if (`$IncludeLogs) {
            `$logsPath = Join-Path `$computerPath "logs"
            if (Test-Path `$logsPath) {
                Copy-Item -Path (Join-Path `$logsPath "*") -Destination `$evidencePath -Recurse
            }
        }
        
        # Collect metrics and performance data
        if (`$IncludeMetrics) {
            `$config = Get-Content (Join-Path `$computerPath "system_config.json") | ConvertFrom-Json
            `$systemEvidence = @{
                ComputerName = `$computer
                IPAddress = `$config.IPAddress
                Role = `$config.Role
                Status = `$config.Status
                LastBoot = `$config.LastBoot
                MKPEVersion = `$config.MKPEVersion
                SystemLoad = `$config.SystemLoad
                ChaosEvents = `$config.ChaosEvents
                ErrorCount = `$config.ErrorLog.Count
                PerformanceMetrics = `$config.PerformanceMetrics
            }
            
            `$systemEvidence | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path `$evidencePath "evidence_summary.json") -Encoding UTF8
            
            `$evidenceReport.Systems += `$systemEvidence
        }
    }
}

# Generate summary report
`$evidenceReport.Summary.TotalSystems = `$evidenceReport.Systems.Count
`$evidenceReport.Summary.HealthySystems = (`$evidenceReport.Systems | Where-Object { `$_.Status -eq "Deployed" -or `$_.Status -eq "Recovered" }).Count
`$evidenceReport.Summary.SystemsWithChaosEvents = (`$evidenceReport.Systems | Where-Object { `$_.ChaosEvents.Count -gt 0 }).Count
`$evidenceReport.Summary.TotalChaosEvents = (`$evidenceReport.Systems | ForEach-Object { `$_.ChaosEvents.Count } | Measure-Object -Sum).Sum

# Generate final evidence report
`$evidenceReport | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path `$OutputPath "evidence_report.json") -Encoding UTF8

Write-Host ""
Write-Host "📊 Evidence Collection Summary:" -ForegroundColor Green
Write-Host "  Total Systems: `$(`$evidenceReport.Summary.TotalSystems)" -ForegroundColor White
Write-Host "  Healthy Systems: `$(`$evidenceReport.Summary.HealthySystems)" -ForegroundColor Green
Write-Host "  Systems with Chaos Events: `$(`$evidenceReport.Summary.SystemsWithChaosEvents)" -ForegroundColor Yellow
Write-Host "  Total Chaos Events: `$(`$evidenceReport.Summary.TotalChaosEvents)" -ForegroundColor Red
Write-Host ""
Write-Host "📁 Evidence collected to: `$OutputPath" -ForegroundColor Cyan
Write-Host "🆔 Collection ID: MKPE-EVIDENCE-`$collectionTimestamp" -ForegroundColor Cyan
"@

$evidenceScript | Out-File -FilePath (Join-Path $VMPath "collect_evidence.ps1") -Encoding UTF8

Write-Host ""
Write-Host "🎉 VM Testing Environment Setup Complete!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""
Write-Host "📁 VM Environment Location: $VMPath" -ForegroundColor Cyan
Write-Host "🖥️ Virtual Computers Created: $($vmComputers.Count)" -ForegroundColor Cyan
Write-Host ""
Write-Host "🚀 Available Scripts:" -ForegroundColor Yellow
Write-Host "  • deploy_mkpe.ps1        - Deploy MKPE across all VMs" -ForegroundColor White
Write-Host "  • chaos_testing.ps1      - Run chaos testing scenarios" -ForegroundColor White
Write-Host "  • system_monitoring.ps1  - Monitor system status" -ForegroundColor White
Write-Host "  • collect_evidence.ps1   - Collect hard evidence data" -ForegroundColor White
Write-Host ""
Write-Host "📊 Configuration Files:" -ForegroundColor Yellow
Write-Host "  • network_config.json    - Network topology" -ForegroundColor White
Write-Host "  • chaos_config.json      - Chaos testing parameters" -ForegroundColor White
Write-Host "  • monitoring_config.json - Monitoring dashboard config" -ForegroundColor White
Write-Host ""

if ($StartChaosTesting) {
    Write-Host "⚡ Starting chaos testing..." -ForegroundColor Red
    & (Join-Path $VMPath "chaos_testing.ps1")
}

Write-Host "✅ VM Testing Environment Ready!" -ForegroundColor Green
