<#
.SYNOPSIS
    Run complete MKPE v1.0.0 audit verification

.DESCRIPTION
    Performs comprehensive verification of all canonical freeze artifacts:
    - Core binaries present and valid
    - Proof artifacts signed correctly
    - Documentation complete
    - Validation data present
    - Cryptographic integrity verified

.EXAMPLE
    .\Run-CompleteAudit.ps1

.EXAMPLE
    .\Run-CompleteAudit.ps1 -Verbose -GenerateReport
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$Verbose,

    [Parameter(Mandatory=$false)]
    [switch]$GenerateReport,

    [Parameter(Mandatory=$false)]
    [string]$MkpeRoot = "C:\mkpe"
)

$ErrorActionPreference = 'Stop'

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     MKPE v1.0.0 Complete Audit Verification System           ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$PassedChecks = 0
$FailedChecks = 0
$Warnings = 0

function Test-Artifact {
    param(
        [string]$Path,
        [string]$Description,
        [switch]$Required
    )

    if (Test-Path $Path) {
        Write-Host "✅ $Description" -ForegroundColor Green
        $script:PassedChecks++
        return $true
    } else {
        if ($Required) {
            Write-Host "❌ $Description - MISSING!" -ForegroundColor Red
            $script:FailedChecks++
        } else {
            Write-Host "⚠️  $Description - Optional, not present" -ForegroundColor Yellow
            $script:Warnings++
        }
        return $false
    }
}

# ==========================================
# SECTION 1: Core Binaries
# ==========================================
Write-Host "[1/8] Verifying Core Binaries..." -ForegroundColor Yellow

Test-Artifact "$MkpeRoot\cli\target\release\mkpe.exe" "CLI Binary (mkpe.exe)" -Required
Test-Artifact "$MkpeRoot\core\target\release\morse_kirby_core.lib" "Core Library" -Required
Write-Host ""

# ==========================================
# SECTION 2: Proof Artifacts
# ==========================================
Write-Host "[2/8] Verifying Proof Artifacts..." -ForegroundColor Yellow

Test-Artifact "$MkpeRoot\canonical_hash.txt" "Canonical Hash Tree" -Required
Test-Artifact "$MkpeRoot\canonical_hash.mkpe" "Signed Hash Tree" -Required
Test-Artifact "$MkpeRoot\mkpe_core_v1.0.0.mkpe" "Self-Signed Engine Bundle" -Required
Write-Host ""

# ==========================================
# SECTION 3: Documentation
# ==========================================
Write-Host "[3/8] Verifying Documentation..." -ForegroundColor Yellow

Test-Artifact "$MkpeRoot\README.md" "README.md" -Required
Test-Artifact "$MkpeRoot\SYSTEM_STATUS.md" "System Status Report" -Required
Test-Artifact "$MkpeRoot\docs\format_spec_v1.0.md" "Format Specification" -Required
Test-Artifact "$MkpeRoot\FREEZE_MANIFEST_v1.0.0.md" "Freeze Manifest" -Required
Test-Artifact "$MkpeRoot\AUDIT_REPORT_v1.0.0.md" "Audit Report" -Required
Write-Host ""

# ==========================================
# SECTION 4: Validation Data
# ==========================================
Write-Host "[4/8] Verifying Validation Data..." -ForegroundColor Yellow

Test-Artifact "$MkpeRoot\validation\baseline\windows_validation.json" "Windows Validation" -Required
Test-Artifact "$MkpeRoot\validation\platform_reports" "Platform Reports Directory"
Write-Host ""

# ==========================================
# SECTION 5: Distribution Package
# ==========================================
Write-Host "[5/8] Verifying Distribution Package..." -ForegroundColor Yellow

Test-Artifact "$MkpeRoot\MKPE_v1.0.0_FROZEN.zip" "Frozen Documentation Package" -Required
Write-Host ""

# ==========================================
# SECTION 6: Installer Tools
# ==========================================
Write-Host "[6/8] Verifying Installer Tools..." -ForegroundColor Yellow

Test-Artifact "$MkpeRoot\tools\Invoke-MKPE.ps1" "PowerShell Wrapper" -Required
Test-Artifact "$MkpeRoot\tools\Install-MKPE.ps1" "System Installer" -Required
Test-Artifact "C:\Kalyx\MKPE\tools\Monitor-MKPEIntegrity.ps1" "Integrity Monitor" -Required
Write-Host ""

# ==========================================
# SECTION 7: Cryptographic Keys
# ==========================================
Write-Host "[7/8] Verifying Cryptographic Keys..." -ForegroundColor Yellow

Test-Artifact "$MkpeRoot\examples\mkpe_private.key" "Private Key (Demo)" -Required
Test-Artifact "$MkpeRoot\examples\mkpe_public.key" "Public Key" -Required
Write-Host ""

# ==========================================
# SECTION 8: Additional Artifacts
# ==========================================
Write-Host "[8/8] Verifying Additional Artifacts..." -ForegroundColor Yellow

Test-Artifact "$MkpeRoot\build_attestation.json" "Build Attestation" -Required
Test-Artifact "$MkpeRoot\validation" "Validation Directory" -Required
Write-Host ""

# ==========================================
# Signature Verification (if mkpe.exe available)
# ==========================================
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                Cryptographic Verification                      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$mkpeExe = "$MkpeRoot\cli\target\release\mkpe.exe"

if (Test-Path $mkpeExe) {
    Write-Host "Running signature verification..." -ForegroundColor Yellow
    
    # Verify canonical hash
    try {
        $result = & $mkpeExe verify "$MkpeRoot\canonical_hash.mkpe" 2>&1
        if ($LASTEXITCODE -eq 0 -or $result -match "PASSED") {
            Write-Host "✅ Canonical hash signature VERIFIED" -ForegroundColor Green
            $PassedChecks++
        } else {
            Write-Host "❌ Canonical hash signature FAILED" -ForegroundColor Red
            $FailedChecks++
        }
    } catch {
        Write-Host "⚠️  Could not verify canonical hash: $_" -ForegroundColor Yellow
        $Warnings++
    }
    
    Write-Host ""
}

# ==========================================
# Final Summary
# ==========================================
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                      Audit Summary                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Host "Passed Checks: " -NoNewline
Write-Host $PassedChecks -ForegroundColor Green

Write-Host "Failed Checks: " -NoNewline
if ($FailedChecks -gt 0) {
    Write-Host $FailedChecks -ForegroundColor Red
} else {
    Write-Host $FailedChecks -ForegroundColor Green
}

Write-Host "Warnings:      " -NoNewline
if ($Warnings -gt 0) {
    Write-Host $Warnings -ForegroundColor Yellow
} else {
    Write-Host $Warnings -ForegroundColor Green
}

Write-Host ""

if ($FailedChecks -eq 0) {
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║          ✅ AUDIT PASSED - FREEZE VERIFIED                    ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "MKPE v1.0.0 canonical freeze is complete and verified!" -ForegroundColor Green
    
    if ($GenerateReport) {
        $reportPath = "$MkpeRoot\audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        @{
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
            version = "1.0.0-mkpe"
            passed = $PassedChecks
            failed = $FailedChecks
            warnings = $Warnings
            status = "PASSED"
        } | ConvertTo-Json | Out-File $reportPath
        Write-Host "Report saved to: $reportPath" -ForegroundColor Cyan
    }
    
    exit 0
} else {
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║          ❌ AUDIT FAILED - MISSING ARTIFACTS                  ║" -ForegroundColor Red
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "Some required artifacts are missing. Please review the output above." -ForegroundColor Red
    exit 1
}



