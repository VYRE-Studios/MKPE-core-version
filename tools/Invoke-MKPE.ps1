<#
.SYNOPSIS
    PowerShell wrapper for the MKPE command-line tool

.DESCRIPTION
    Provides convenient PowerShell functions for MKPE operations:
    - Key generation
    - File/directory signing
    - Bundle verification
    - C-DNA validation

.EXAMPLE
    Invoke-MKPE -Command keygen -Output C:\keys

.EXAMPLE
    Invoke-MKPE -Command sign -Path myfile.txt -Key C:\keys\mkpe_private.key

.EXAMPLE
    Invoke-MKPE -Command verify -Path myfile.mkpe -Detailed
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('keygen', 'sign', 'verify', 'bundle', 'inspect', 'hash', 'validate-cdna', 'version')]
    [string]$Command,

    [Parameter(Mandatory=$false)]
    [string]$Path,

    [Parameter(Mandatory=$false)]
    [string]$Key,

    [Parameter(Mandatory=$false)]
    [string]$Output,

    [Parameter(Mandatory=$false)]
    [switch]$Detailed,

    [Parameter(Mandatory=$false)]
    [switch]$Verbose,

    [Parameter(Mandatory=$false)]
    [switch]$Proof,

    [Parameter(Mandatory=$false)]
    [string]$ExportManifest
)

# Locate MKPE executable
$MkpeExe = $null
$PossibleLocations = @(
    "C:\Kalyx\MKPE\v1.0.0\mkpe.exe",
    "C:\mkpe\cli\target\release\mkpe.exe",
    "$PSScriptRoot\..\cli\target\release\mkpe.exe",
    (Get-Command mkpe -ErrorAction SilentlyContinue).Source
)

foreach ($loc in $PossibleLocations) {
    if ($loc -and (Test-Path $loc)) {
        $MkpeExe = $loc
        break
    }
}

if (-not $MkpeExe) {
    Write-Error "MKPE executable not found. Please build MKPE or install it to a standard location."
    exit 1
}

# Build command arguments
$Args = @($Command)

switch ($Command) {
    'keygen' {
        if ($Output) {
            $Args += @('-o', $Output)
        }
    }
    'sign' {
        if (-not $Path) {
            Write-Error "-Path is required for sign command"
            exit 1
        }
        if (-not $Key) {
            Write-Error "-Key is required for sign command"
            exit 1
        }
        $Args += @($Path, '-k', $Key)
        if ($Output) {
            $Args += @('-o', $Output)
        }
    }
    'verify' {
        if (-not $Path) {
            Write-Error "-Path is required for verify command"
            exit 1
        }
        $Args += @($Path)
        if ($Detailed) {
            $Args += '-d'
        }
    }
    'bundle' {
        if (-not $Path) {
            Write-Error "-Path is required for bundle command"
            exit 1
        }
        if (-not $Key) {
            Write-Error "-Key is required for bundle command"
            exit 1
        }
        if (-not $Output) {
            Write-Error "-Output is required for bundle command"
            exit 1
        }
        $Args += @($Path, '-k', $Key, '-o', $Output)
    }
    'inspect' {
        if (-not $Path) {
            Write-Error "-Path is required for inspect command"
            exit 1
        }
        $Args += @($Path)
        if ($ExportManifest) {
            $Args += @('-e', $ExportManifest)
        }
    }
    'hash' {
        if (-not $Path) {
            Write-Error "-Path is required for hash command"
            exit 1
        }
        $Args += @($Path)
    }
    'validate-cdna' {
        if (-not $Path) {
            Write-Error "-Path is required for validate-cdna command"
            exit 1
        }
        $Args += @($Path)
        if ($Proof) {
            $Args += '--proof'
            if ($Key) {
                $Args += @('-k', $Key)
            }
        }
    }
    'version' {
        # No additional arguments needed
    }
}

if ($Verbose) {
    $Args += '-v'
}

# Execute MKPE
Write-Verbose "Executing: $MkpeExe $($Args -join ' ')"
& $MkpeExe @Args



