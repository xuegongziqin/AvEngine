# lib_sysmon.ps1 - pick the Sysmon binary that matches this Windows version.
#
# Sysmon 15.x requires Windows 8.1 / Server 2012 R2 or newer; the last build
# that supports Windows 7 SP1 / Server 2008 R2 is Sysmon 13.x, kept in
# bina\Sysmon\sysmonwin7\. Layout expected by this script:
#
#   bina\Sysmon\Sysmon.exe              x86   modern (15.x)
#   bina\Sysmon\Sysmon64.exe            x64   modern (15.x)
#   bina\Sysmon\Sysmon64a.exe           ARM64 modern (15.x)
#   bina\Sysmon\sysmonwin7\Sysmon.exe   x86   legacy (13.x, Win7/2008R2)
#   bina\Sysmon\sysmonwin7\Sysmon64.exe x64   legacy (13.x, Win7/2008R2)
#
# Selection rule (kept identical in scripts\install.bat, avengine\paths.py
# sysmon_exe() and installer\install.c step_sysmon):
#   Windows 6.0 / 6.1  -> bina\Sysmon\sysmonwin7\   (legacy)
#   anything newer     -> bina\Sysmon\              (modern)
#   arch: x64 -> Sysmon64.exe, ARM64 -> Sysmon64a.exe (modern only), else Sysmon.exe
# If the preferred file is missing the other folder is tried, then a legacy
# Sysmon.exe next to the project root.
#
# Usage:
#   powershell -File lib_sysmon.ps1 -Print        # one line: chosen path (exit 1 if none)
#   powershell -File lib_sysmon.ps1 -Explain      # human readable report
#   . lib_sysmon.ps1; Select-SysmonExe            # returns an object
#
# Testing flags: -ForceVersion 6.1 -ForceArch x64 -Root <dir>

[CmdletBinding()]
param(
    [string]$Root,
    [string]$ForceVersion,
    [string]$ForceArch,
    [switch]$Print,
    [switch]$Explain
)

# Windows version: CurrentMajorVersionNumber exists only on Windows 10+;
# on older systems CurrentVersion holds "6.1" / "6.3" etc. Using the registry
# avoids the GetVersionEx manifest lie that reports 6.2 on Windows 10.
function Get-WindowsVersionInfo {
    $major = 0
    $minor = 0
    $source = 'registry'
    try {
        $key = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $names = @($key.PSObject.Properties | ForEach-Object { $_.Name })
        if ($names -contains 'CurrentMajorVersionNumber') {
            $major = [int]$key.CurrentMajorVersionNumber
            if ($names -contains 'CurrentMinorVersionNumber') {
                $minor = [int]$key.CurrentMinorVersionNumber
            }
        }
        elseif ($names -contains 'CurrentVersion') {
            $parts = ([string]$key.CurrentVersion).Split('.')
            if ($parts.Length -ge 2) {
                $major = [int]$parts[0]
                $minor = [int]$parts[1]
            }
        }
    }
    catch {
        $major = 0
    }
    if ($major -eq 0) {
        # Last resort: .NET view (may under-report on Windows 10+, still enough
        # to tell 6.x apart from anything newer in practice).
        $source = 'dotnet'
        $v = [Environment]::OSVersion.Version
        $major = $v.Major
        $minor = $v.Minor
    }
    New-Object PSObject -Property @{
        Major  = $major
        Minor  = $minor
        Text   = ('{0}.{1}' -f $major, $minor)
        Source = $source
    }
}

# Native architecture, even when running as a 32-bit process on 64-bit Windows.
function Get-NativeArch {
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    if (-not $arch) { $arch = 'X86' }
    switch ($arch.ToUpperInvariant()) {
        'AMD64' { return 'x64' }
        'IA64'  { return 'x64' }
        'ARM64' { return 'ARM64' }
        default { return 'x86' }
    }
}

function Select-SysmonExe {
    [CmdletBinding()]
    param(
        [string]$Root,
        [string]$ForceVersion,
        [string]$ForceArch
    )

    if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
    if (-not $Root) { $Root = (Get-Location).Path }

    if ($ForceVersion) {
        $verText = $ForceVersion
        $verSource = 'forced'
    }
    else {
        $info = Get-WindowsVersionInfo
        $verText = $info.Text
        $verSource = $info.Source
    }
    if ($ForceArch) { $arch = $ForceArch } else { $arch = Get-NativeArch }

    $parts = $verText.Split('.')
    $major = 0
    $minor = 0
    if ($parts.Length -ge 1) { [void][int]::TryParse($parts[0], [ref]$major) }
    if ($parts.Length -ge 2) { [void][int]::TryParse($parts[1], [ref]$minor) }

    $legacy = ($major -eq 6 -and ($minor -eq 0 -or $minor -eq 1))

    $sysmonDir = Join-Path $Root 'bina\Sysmon'
    $modernDir = $sysmonDir
    $legacyDir = Join-Path $sysmonDir 'sysmonwin7'
    if ($legacy) {
        $primaryDir = $legacyDir
        $otherDir = $modernDir
    }
    else {
        $primaryDir = $modernDir
        $otherDir = $legacyDir
    }

    $names = @()
    switch ($arch.ToUpperInvariant()) {
        'X64'   { $names = @('Sysmon64.exe', 'Sysmon.exe') }
        'ARM64' {
            if ($legacy) { $names = @('Sysmon64.exe', 'Sysmon.exe') }
            else { $names = @('Sysmon64a.exe', 'Sysmon64.exe', 'Sysmon.exe') }
        }
        default { $names = @('Sysmon.exe') }
    }

    $candidates = @()
    foreach ($n in $names) { $candidates += (Join-Path $primaryDir $n) }
    foreach ($n in $names) { $candidates += (Join-Path $otherDir $n) }
    $candidates += (Join-Path $Root 'Sysmon.exe')   # legacy layout, kept for compatibility

    $found = $null
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c -PathType Leaf) { $found = $c; break }
    }

    $preferred = Join-Path $primaryDir $names[0]
    New-Object PSObject -Property @{
        Path       = $(if ($found) { $found } else { $preferred })
        Exists     = [bool]$found
        Preferred  = $preferred
        IsFallback = [bool]($found -and ($found -ne $preferred))
        Legacy     = $legacy
        Version    = $verText
        VerSource  = $verSource
        Arch       = $arch
        Candidates = $candidates
    }
}

function Format-SysmonChoice($choice) {
    $lines = @()
    $kind = 'modern'
    if ($choice.Legacy) { $kind = 'legacy (Win7/2008R2)' }
    $lines += ('Windows version : {0} (from {1})' -f $choice.Version, $choice.VerSource)
    $lines += ('Architecture    : {0}' -f $choice.Arch)
    $lines += ('Sysmon family   : {0}' -f $kind)
    if ($choice.Exists) {
        $lines += ('Chosen binary   : {0}' -f $choice.Path)
        if ($choice.IsFallback) {
            $lines += ('                  (fallback: preferred {0} is missing)' -f $choice.Preferred)
        }
    }
    else {
        $lines += ('Chosen binary   : NOT FOUND (expected {0})' -f $choice.Preferred)
        foreach ($c in $choice.Candidates) { $lines += ('                  tried {0}' -f $c) }
    }
    return $lines
}

# Script entry point (skipped when the file is dot-sourced by another script).
if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.MyCommand.Path) {
    $choice = Select-SysmonExe -Root $Root -ForceVersion $ForceVersion -ForceArch $ForceArch
    if ($Explain) {
        Format-SysmonChoice $choice | ForEach-Object { Write-Host $_ }
    }
    if ($Print) {
        if ($choice.Exists) {
            [Console]::Out.WriteLine($choice.Path)
            exit 0
        }
        [Console]::Error.WriteLine(('Sysmon not found, expected {0}' -f $choice.Preferred))
        exit 1
    }
    if (-not $Explain) {
        if ($choice.Exists) { [Console]::Out.WriteLine($choice.Path); exit 0 }
        [Console]::Error.WriteLine(('Sysmon not found, expected {0}' -f $choice.Preferred))
        exit 1
    }
}
