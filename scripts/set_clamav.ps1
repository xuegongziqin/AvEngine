<#
.SYNOPSIS
    Point AvEngine at a ClamAV daemon, or disable ClamAV (YARA-only).

.DESCRIPTION
    ClamAV 1.x is not supported on Windows 7. AvEngine only talks to clamd
    over TCP (config.yaml -> clamav.host/port), so on Windows 7 you can either
    connect to a clamd running on another machine (LAN) or run YARA only.

    This script edits the clamav section of config.yaml. It does not install
    ClamAV and does not require Administrator rights.

.PARAMETER ClamdHost
    clamd host / IP. Use "none" (or an empty string) to disable ClamAV and
    run YARA only.

.PARAMETER Port
    clamd TCP port. Default 3310.

.PARAMETER ConfigYaml
    Path to config.yaml. Default: <repo>\config.yaml.

.EXAMPLE
    .\set_clamav.ps1 -ClamdHost 192.168.1.50

.EXAMPLE
    .\set_clamav.ps1 -ClamdHost none
#>
param(
    [Parameter(Position = 0)]
    [Alias("Host")]
    [string]$ClamdHost = "127.0.0.1",
    [int]$Port = 3310,
    [string]$ConfigYaml = (Join-Path $PSScriptRoot "..\config.yaml")
)

$ErrorActionPreference = "Stop"

# "none" / "off" / empty -> YARA-only
$hostValue = "$ClamdHost".Trim()
if ($hostValue -match '^(none|no|disable|disabled|off|-|yara)$') { $hostValue = "" }

if ($Port -le 0) { $Port = 3310 }

# Create config.yaml from the example if it does not exist yet.
if (-not (Test-Path $ConfigYaml)) {
    $example = Join-Path $PSScriptRoot "..\config.example.yaml"
    if (Test-Path $example) {
        Copy-Item $example $ConfigYaml -Force
    } else {
        $min = "yara:`n  rules_path: `"./rules`"`n`nclamav:`n  host: `"127.0.0.1`"`n  port: 3310`n  timeout: 30`n"
        [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($ConfigYaml), $min, (New-Object System.Text.UTF8Encoding($false)))
    }
}

$full = [System.IO.Path]::GetFullPath($ConfigYaml)
# ReadAllText detects a BOM and otherwise assumes UTF-8, so Chinese comments survive
# on Windows PowerShell 5.1 (Win7), where Get-Content -Raw would use the ANSI codepage.
$yaml = [System.IO.File]::ReadAllText($full)

$timeout = 30
if ($yaml -match '(?m)^\s*timeout:\s*(\d+)') { $timeout = [int]$Matches[1] }

$block = "clamav:`n  host: `"$hostValue`"`n  port: $Port`n  timeout: $timeout"
if ($yaml -match '(?m)^clamav:') {
    $yaml = $yaml -replace '(?ms)^clamav:.*?(?=\n\S|\z)', $block
} else {
    $yaml = $yaml.TrimEnd() + "`n`n" + $block + "`n"
}

[System.IO.File]::WriteAllText($full, $yaml, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "Updated: $full"
if ($hostValue -eq "") {
    Write-Host "ClamAV disabled (YARA-only). 'avengine.exe status' will show ClamAV as unavailable;"
    Write-Host "scanning still uses YARA + Sysmon."
} else {
    Write-Host "clamd target: $hostValue`:$Port"
    Write-Host "Make sure clamd listens there and the firewall allows TCP $Port."
    Write-Host "Verify with:  avengine.exe status"
}
