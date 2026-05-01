param(
    [string]$Mkpe = "cargo run --manifest-path ../cli/Cargo.toml --"
)

$ErrorActionPreference = "Stop"

$root = Join-Path $PSScriptRoot "attestation-demo-work"
$keys = Join-Path $root "keys"
$artifact = Join-Path $root "artifact.txt"
$sidecar = Join-Path $root "artifact.txt.mkpe"
$attestation = Join-Path $root "build_attestation.json"

if (Test-Path $root) {
    Remove-Item -Recurse -Force $root
}
New-Item -ItemType Directory -Path $root | Out-Null

Set-Content -Path $artifact -Value "MKPE v1.1.0 attested bytes" -NoNewline

Invoke-Expression "$Mkpe keygen --output `"$keys`""
Invoke-Expression "$Mkpe --format json dna create `"$artifact`" --key `"$keys\mkpe_private.key`" --output `"$sidecar`""
Invoke-Expression "$Mkpe --format json attest generate `"$artifact`" --key `"$keys\mkpe_private.key`" --bundle `"$sidecar`" --output `"$attestation`" --attested-by demo --command `"demo build`""
Invoke-Expression "$Mkpe --format json attest verify `"$attestation`" --subject `"$artifact`" --bundle `"$sidecar`" --public-key `"$keys\mkpe_public.key`""

Write-Output "Attestation demo complete: $root"
