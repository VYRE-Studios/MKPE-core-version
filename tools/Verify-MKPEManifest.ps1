# === Verify-MKPEManifest.ps1 ===
# Verifies all files listed in MKPE_v1.0.0_manifest.json are present
# and optionally checks their hashes

$ErrorActionPreference = "Stop"
$Root = "C:\MKPE_Release\v1.0.0"
$ManifestPath = "$Root\MKPE_v1.0.0_manifest.json"

if (-not (Test-Path $ManifestPath)) {
    Write-Host "❌ Manifest not found at $ManifestPath" -ForegroundColor Red
    exit 1
}

$Manifest = Get-Content $ManifestPath | ConvertFrom-Json

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Verifying MKPE Manifest for v$($Manifest.version)          ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$Missing = @()
$Present = 0

# Check directories
Write-Host "[1/3] Verifying directories..." -ForegroundColor Yellow
foreach ($dir in $Manifest.directories) {
    $dirPath = Join-Path $Root $dir
    if (-not (Test-Path $dirPath)) {
        $Missing += "DIR: $dir"
        Write-Host "  ✗ $dir" -ForegroundColor Red
    } else {
        $Present++
        Write-Host "  ✓ $dir" -ForegroundColor Green
    }
}
Write-Host ""

# Check files
Write-Host "[2/3] Verifying files..." -ForegroundColor Yellow
$AllFiles = @(
    $Manifest.executables +
    $Manifest.config_files +
    $Manifest.docs +
    $Manifest.assets +
    $Manifest.service_files +
    $Manifest.proofs
)

foreach ($file in $AllFiles) {
    $filePath = Join-Path $Root $file
    if (-not (Test-Path $filePath)) {
        $Missing += "FILE: $file"
        Write-Host "  ✗ $file" -ForegroundColor Red
    } else {
        $Present++
        Write-Host "  ✓ $file" -ForegroundColor Green
    }
}
Write-Host ""

# Check hashes if present
if ($Manifest.hashes -and $Manifest.hashes.PSObject.Properties.Count -gt 0) {
    Write-Host "[3/3] Verifying file hashes..." -ForegroundColor Yellow
    $HashMismatches = 0
    
    foreach ($entry in $Manifest.hashes.PSObject.Properties) {
        $file = $entry.Name
        $expectedHash = ($entry.Value -split ":")[1]
        
        $filePath = Join-Path $Root $file
        if (Test-Path $filePath) {
            if ($expectedHash -eq "PENDING" -or $expectedHash -eq "TO_BE_CALCULATED" -or $expectedHash -eq "PENDING_IMPLEMENTATION") {
                Write-Host "  ⚠ $file (not yet hashed)" -ForegroundColor Yellow
            } else {
                $actualHash = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToUpper()
                if ($actualHash -eq $expectedHash.ToUpper()) {
                    Write-Host "  ✓ $file" -ForegroundColor Green
                } else {
                    Write-Host "  ✗ $file (HASH MISMATCH)" -ForegroundColor Red
                    $HashMismatches++
                }
            }
        }
    }
    
    if ($HashMismatches -gt 0) {
        Write-Host ""
        Write-Host "❌ $HashMismatches hash mismatch(es) detected!" -ForegroundColor Red
        $Missing += "HASH_MISMATCHES: $HashMismatches"
    }
}
Write-Host ""

# Final summary
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    Verification Summary                        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Present: $Present items" -ForegroundColor Green
Write-Host "Missing: $($Missing.Count) items" -ForegroundColor $(if ($Missing.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host ""

if ($Missing.Count -gt 0) {
    Write-Host "❌ VERIFICATION FAILED" -ForegroundColor Red
    Write-Host ""
    Write-Host "Missing items:" -ForegroundColor Yellow
    $Missing | ForEach-Object { Write-Host "  - $_" }
    Write-Host ""
    exit 1
} else {
    Write-Host "✅ ALL EXPECTED FILES PRESENT AND VERIFIED" -ForegroundColor Green
    Write-Host ""
    Write-Host "Manifest is ready for packaging." -ForegroundColor Cyan
    exit 0
}



