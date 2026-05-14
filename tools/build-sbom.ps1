# tools/build-sbom.ps1
#
# Emits a CycloneDX 1.5 SBOM for every workspace member into ./dist/sbom/.
# Designed to be invoked in CI immediately after `cargo build --workspace
# --locked --frozen --profile dist`, before signing.
#
# Local invocation:
#   pwsh ./tools/build-sbom.ps1
#
# CI invocation (Linux runner under cargo-xwin):
#   pwsh -File ./tools/build-sbom.ps1 -Profile dist -Target x86_64-pc-windows-msvc
#
# The script is intentionally idempotent. Running it twice over an unchanged
# Cargo.lock must produce byte-identical SBOMs (modulo the embedded
# timestamp, which we override via -Reproducible).

[CmdletBinding()]
param(
    [string]$Profile = "release",

    [string]$Target = "x86_64-pc-windows-msvc",

    [string]$OutDir = "dist/sbom",

    # When set, replace serialNumber and timestamp fields with deterministic
    # values derived from the Cargo.lock hash. Required for SLSA L3
    # reproducibility; disable only for ad-hoc local exploration.
    [switch]$Reproducible = $true,

    # If cargo-cyclonedx is missing, install it. CI should always pre-install
    # via a pinned `cargo install --locked --version <X.Y.Z>` step; this is
    # a developer convenience, not a CI mechanism.
    [switch]$AutoInstall
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Require-Tool {
    param([string]$Name, [string]$InstallCmd)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        if ($AutoInstall) {
            Write-Host "Installing $Name..."
            Invoke-Expression $InstallCmd
        } else {
            throw "$Name not found on PATH. Run with -AutoInstall or: $InstallCmd"
        }
    }
}

Require-Tool -Name "cargo"             -InstallCmd "<install rustup>"
Require-Tool -Name "cargo-cyclonedx"   -InstallCmd "cargo install --locked cargo-cyclonedx"

if (-not (Test-Path "Cargo.lock")) {
    throw "Cargo.lock not found. Run 'cargo generate-lockfile' first."
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$lockHash = (Get-FileHash -Algorithm SHA256 Cargo.lock).Hash.ToLower()
Write-Host "Cargo.lock SHA-256: $lockHash"

$args = @(
    "cyclonedx",
    "--format", "json",
    "--describe", "binaries",
    "--spec-version", "1.5",
    "--target", $Target,
    "--all"
)

# cargo-cyclonedx writes one .cdx.json per crate next to its Cargo.toml.
# We move them into $OutDir afterwards so dist/ is the single artifact root.
Write-Host "Generating SBOM (target=$Target, profile=$Profile)..."
& cargo @args
if ($LASTEXITCODE -ne 0) { throw "cargo-cyclonedx failed with exit $LASTEXITCODE" }

# Collect the per-crate SBOMs into dist/sbom/, namespaced by crate.
Get-ChildItem -Recurse -Filter "*.cdx.json" |
    Where-Object { $_.FullName -notlike "*$OutDir*" -and $_.FullName -notlike "*\target\*" } |
    ForEach-Object {
        $crate = Split-Path -Leaf (Split-Path $_.DirectoryName)
        $dest  = Join-Path $OutDir "$crate.cdx.json"
        Move-Item -LiteralPath $_.FullName -Destination $dest -Force
        Write-Host "  -> $dest"
    }

if ($Reproducible) {
    # CycloneDX emits a random serialNumber and a wall-clock timestamp; both
    # break reproducibility. Replace serialNumber with a UUIDv5 derived from
    # the Cargo.lock hash, and pin the timestamp to the lockfile's mtime.
    $lockMtime = (Get-Item Cargo.lock).LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    Get-ChildItem $OutDir -Filter "*.cdx.json" | ForEach-Object {
        $j = Get-Content $_.FullName -Raw | ConvertFrom-Json
        $j.serialNumber = "urn:uuid:" + ([guid]::new($lockHash.Substring(0, 32))).ToString()
        if ($null -ne $j.metadata) {
            $j.metadata.timestamp = $lockMtime
        }
        $j | ConvertTo-Json -Depth 50 | Set-Content -Path $_.FullName -Encoding UTF8 -NoNewline
    }
    Write-Host "Normalized SBOMs for reproducibility (timestamp=$lockMtime)"
}

Write-Host ""
Write-Host "SBOM artifacts:"
Get-ChildItem $OutDir -Filter "*.cdx.json" | Format-Table Name, Length

Write-Host ""
Write-Host "Verify with:"
Write-Host "  cyclonedx validate --input-file $OutDir/<crate>.cdx.json"
