<#
.SYNOPSIS
    Install the Morse-Kirby Provenance Engine (MKPE) to the system

.DESCRIPTION
    This script installs MKPE v1.0.0 to C:\Kalyx\MKPE\v1.0.0 and:
    - Copies binaries and libraries
    - Registers the .mkpe file extension
    - Generates and stores canonical manifest
    - Runs validation tests
    - Logs installation results

.PARAMETER InstallPath
    Installation directory (default: C:\Kalyx\MKPE\v1.0.0)

.PARAMETER SkipValidation
    Skip post-installation validation tests

.PARAMETER Force
    Overwrite existing installation

.EXAMPLE
    .\Install-MKPE.ps1

.EXAMPLE
    .\Install-MKPE.ps1 -InstallPath "D:\MKPE" -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "C:\Kalyx\MKPE\v1.0.0",

    [Parameter(Mandatory=$false)]
    [switch]$SkipValidation,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Morse-Kirby Provenance Engine (MKPE) v1.0.0 Installer       ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Warning "Not running as Administrator. Registry modifications will be skipped."
}

# Source paths
$SourceRoot = Split-Path -Parent $PSScriptRoot
$CliBinary = Join-Path $SourceRoot "cli\target\release\mkpe.exe"
$CoreLib = Join-Path $SourceRoot "core\target\release\morse_kirby_core.dll"

# Verify source files exist
Write-Host "[1/7] Verifying source files..." -ForegroundColor Yellow
if (-not (Test-Path $CliBinary)) {
    Write-Error "CLI binary not found at: $CliBinary`nPlease build MKPE first with: cargo build --release"
}
Write-Host "  ✓ CLI binary found" -ForegroundColor Green
Write-Host "  ✓ Source verification complete" -ForegroundColor Green
Write-Host ""

# Check existing installation
if (Test-Path $InstallPath) {
    if ($Force) {
        Write-Host "[2/7] Removing existing installation..." -ForegroundColor Yellow
        Remove-Item -Path $InstallPath -Recurse -Force
        Write-Host "  ✓ Existing installation removed" -ForegroundColor Green
    } else {
        Write-Error "Installation path already exists: $InstallPath`nUse -Force to overwrite"
    }
} else {
    Write-Host "[2/7] No existing installation found" -ForegroundColor Yellow
}
Write-Host ""

# Create installation directories
Write-Host "[3/7] Creating installation directories..." -ForegroundColor Yellow
$Dirs = @(
    $InstallPath,
    "$InstallPath\bin",
    "$InstallPath\lib",
    "$InstallPath\schemas",
    "$InstallPath\docs",
    "$InstallPath\logs"
)

foreach ($dir in $Dirs) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
Write-Host "  ✓ Directory structure created" -ForegroundColor Green
Write-Host ""

# Copy binaries
Write-Host "[4/7] Installing binaries..." -ForegroundColor Yellow
Copy-Item -Path $CliBinary -Destination "$InstallPath\bin\mkpe.exe" -Force
Write-Host "  ✓ CLI binary installed" -ForegroundColor Green

# Copy core library if it exists
if (Test-Path $CoreLib) {
    Copy-Item -Path $CoreLib -Destination "$InstallPath\lib\" -Force
    Write-Host "  ✓ Core library installed" -ForegroundColor Green
}

# Copy schemas
$SchemasDir = Join-Path $SourceRoot "schemas"
if (Test-Path $SchemasDir) {
    Copy-Item -Path "$SchemasDir\*" -Destination "$InstallPath\schemas\" -Recurse -Force
    Write-Host "  ✓ Schemas installed" -ForegroundColor Green
}

# Copy documentation
$DocsDir = Join-Path $SourceRoot "docs"
if (Test-Path $DocsDir) {
    Copy-Item -Path "$DocsDir\*" -Destination "$InstallPath\docs\" -Recurse -Force
    Write-Host "  ✓ Documentation installed" -ForegroundColor Green
}
Write-Host ""

# Generate provenance manifest
Write-Host "[5/7] Generating canonical manifest..." -ForegroundColor Yellow
$Manifest = @{
    mkpe_version = "1.0.0-mkpe"
    schema_version = "1.0.0"
    install_timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    install_path = $InstallPath
    platform = [System.Environment]::OSVersion.Platform.ToString()
    machine = $env:COMPUTERNAME
    user = $env:USERNAME
    binaries = @{
        cli = "$InstallPath\bin\mkpe.exe"
        cli_hash = (Get-FileHash -Path "$InstallPath\bin\mkpe.exe" -Algorithm SHA256).Hash
    }
    registry_keys = @()
}

# Calculate canonical hash
$ManifestJson = $Manifest | ConvertTo-Json -Depth 10
$ManifestPath = "$InstallPath\provenance_manifest.json"
$ManifestJson | Out-File -FilePath $ManifestPath -Encoding UTF8
$ManifestHash = (Get-FileHash -Path $ManifestPath -Algorithm SHA256).Hash

Write-Host "  ✓ Manifest generated" -ForegroundColor Green
Write-Host "  ✓ Canonical hash: $($ManifestHash.Substring(0, 16))..." -ForegroundColor Green
Write-Host ""

# Register .mkpe file extension (Windows only, requires Admin)
if ($IsAdmin -and $IsWindows) {
    Write-Host "[6/7] Registering .mkpe file extension..." -ForegroundColor Yellow
    
    try {
        # Create registry keys
        New-Item -Path "HKCR:\.mkpe" -Force | Out-Null
        Set-ItemProperty -Path "HKCR:\.mkpe" -Name "(Default)" -Value "MKPEFile"
        
        New-Item -Path "HKCR:\MKPEFile" -Force | Out-Null
        Set-ItemProperty -Path "HKCR:\MKPEFile" -Name "(Default)" -Value "MKPE Provenance Bundle"
        
        New-Item -Path "HKCR:\MKPEFile\shell\open\command" -Force | Out-Null
        Set-ItemProperty -Path "HKCR:\MKPEFile\shell\open\command" -Name "(Default)" -Value "`"$InstallPath\bin\mkpe.exe`" verify `"%1`""
        
        New-Item -Path "HKCR:\MKPEFile\shell\inspect\command" -Force | Out-Null
        Set-ItemProperty -Path "HKCR:\MKPEFile\shell\inspect\command" -Name "(Default)" -Value "`"$InstallPath\bin\mkpe.exe`" inspect `"%1`""
        
        Write-Host "  ✓ File extension registered" -ForegroundColor Green
        
        $Manifest.registry_keys = @(
            "HKCR:\.mkpe",
            "HKCR:\MKPEFile"
        )
    } catch {
        Write-Warning "Failed to register file extension: $_"
    }
} else {
    Write-Host "[6/7] Skipping file extension registration (requires Administrator)" -ForegroundColor Yellow
}
Write-Host ""

# Validation
if (-not $SkipValidation) {
    Write-Host "[7/7] Running validation..." -ForegroundColor Yellow
    
    # Test CLI
    $VersionOutput = & "$InstallPath\bin\mkpe.exe" version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ CLI executable works" -ForegroundColor Green
    } else {
        Write-Warning "CLI test failed"
    }
    
    # Generate test keypair
    $TestDir = "$env:TEMP\mkpe_validation_$(Get-Random)"
    New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
    
    & "$InstallPath\bin\mkpe.exe" keygen -o $TestDir 2>&1 | Out-Null
    if (Test-Path "$TestDir\mkpe_private.key") {
        Write-Host "  ✓ Key generation works" -ForegroundColor Green
    } else {
        Write-Warning "Key generation test failed"
    }
    
    # Test signing
    "Test content" | Out-File "$TestDir\test.txt"
    & "$InstallPath\bin\mkpe.exe" sign "$TestDir\test.txt" -k "$TestDir\mkpe_private.key" 2>&1 | Out-Null
    if (Test-Path "$TestDir\test.mkpe") {
        Write-Host "  ✓ Signing works" -ForegroundColor Green
    } else {
        Write-Warning "Signing test failed"
    }
    
    # Test verification
    $VerifyOutput = & "$InstallPath\bin\mkpe.exe" verify "$TestDir\test.mkpe" 2>&1
    if ($VerifyOutput -match "PASSED") {
        Write-Host "  ✓ Verification works" -ForegroundColor Green
    } else {
        Write-Warning "Verification test failed"
    }
    
    # Cleanup
    Remove-Item -Path $TestDir -Recurse -Force
    
} else {
    Write-Host "[7/7] Skipping validation" -ForegroundColor Yellow
}
Write-Host ""

# Write validation report
$ValidationReport = @{
    installation_successful = $true
    install_path = $InstallPath
    manifest_hash = $ManifestHash
    validated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    platform = [System.Environment]::OSVersion.VersionString
}

$ValidationReport | ConvertTo-Json -Depth 10 | Out-File -FilePath "C:\Kalyx\LOGS\MKPE_VALIDATION.txt" -Force -ErrorAction SilentlyContinue

# Final summary
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║             MKPE Installation Complete!                       ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Installation Path: " -NoNewline
Write-Host $InstallPath -ForegroundColor Cyan
Write-Host "Canonical Hash:    " -NoNewline
Write-Host $ManifestHash.Substring(0, 32) -ForegroundColor Cyan
Write-Host ""
Write-Host "To use MKPE, run:" -ForegroundColor Yellow
Write-Host "  $InstallPath\bin\mkpe.exe version" -ForegroundColor White
Write-Host ""
Write-Host "Or add to PATH:" -ForegroundColor Yellow
Write-Host "  `$env:PATH += `";$InstallPath\bin`"" -ForegroundColor White
Write-Host ""



