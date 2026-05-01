# === Update-MKPEManifest.ps1 ===
# Refreshes the 'hashes' section of MKPE_v1.0.0_manifest.json
# Run this from an elevated PowerShell window before packaging.

$ErrorActionPreference = "Stop"
$Root = "C:\MKPE_Release\v1.0.0"
$ManifestPath = "$Root\MKPE_v1.0.0_manifest.json"

if (-not (Test-Path $ManifestPath)) {
    Write-Host "❌ Manifest not found at $ManifestPath" -ForegroundColor Red
    exit 1
}

$Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
$NewHashes = @{}

Write-Host "🔄 Recalculating file hashes..." -ForegroundColor Yellow

# Combine all file lists from manifest
$AllFiles = @(
    $Manifest.executables +
    $Manifest.config_files +
    $Manifest.docs +
    $Manifest.assets +
    $Manifest.service_files +
    $Manifest.proofs
)

foreach ($file in $AllFiles) {
    $Path = Join-Path $Root $file
    if (Test-Path $Path) {
        $Hash = (Get-FileHash $Path -Algorithm SHA256).Hash.ToUpper()
        $NewHashes[$file] = "SHA256:$Hash"
        Write-Host "[OK] $file" -ForegroundColor Green
    } else {
        Write-Host "[MISS] $file (will be marked as pending)" -ForegroundColor Yellow
        $NewHashes[$file] = "SHA256:PENDING"
    }
}

$Manifest.hashes = $NewHashes
$Manifest | ConvertTo-Json -Depth 6 | Set-Content $ManifestPath -Encoding UTF8

Write-Host "`n✅ Manifest hashes updated successfully." -ForegroundColor Cyan
Write-Host "File saved: $ManifestPath"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Run Verify-MKPEManifest.ps1 to check integrity"
Write-Host "  2. Sign the manifest: mkpe.exe sign MKPE_v1.0.0_manifest.json"
Write-Host "  3. Build installer with Inno Setup"



