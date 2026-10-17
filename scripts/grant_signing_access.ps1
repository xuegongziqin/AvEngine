# grant_signing_access.ps1 - 修复签名材料（PFX / 密码）的读取权限
#
# 为什么需要它：
#   gen_signing_cert.ps1 会把 bina\signing\ 与 service\passwd.txt 的 ACL 收紧成
#   "只留 SYSTEM + Administrators"。如果你的构建 shell **没有提权**，Windows 会把令牌里的
#   Administrators 标成 "deny only"，于是签名脚本读不到密码/PFX，报：
#       Get-Content : Access to the path '...\service\passwd.txt' is denied.
#   结果就是：构建显示 BUILD OK，但二进制**没有签名**，而特权服务会拒绝未签名的调用者。
#
# 这个脚本不重新生成证书（指纹不变，不需要重编服务），只修 ACL：
#   * 默认：在 SYSTEM/Administrators 之外，额外给"当前账户"只读权限
#   * -Strict：反过来收紧成仅 SYSTEM/Administrators（之后构建必须提权）
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\grant_signing_access.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\grant_signing_access.ps1 -User "DOMAIN\someone"
#   powershell -ExecutionPolicy Bypass -File scripts\grant_signing_access.ps1 -Strict
#
# 注意：如果当前账户连 ACL 都读不到（"Access is denied"），必须**以管理员身份**运行本脚本。
[CmdletBinding()]
param(
    [string]$User = "",
    [switch]$Strict,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $User) { $User = "$env:USERDOMAIN\$env:USERNAME" }

$dirTargets = @(Join-Path $root 'bina\signing')
$fileTargets = @(
    (Join-Path $root 'service\passwd.txt'),
    (Join-Path $root 'service\signing.json')
)

$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

function Say($msg) { if (-not $Quiet) { Write-Host "[acl] $msg" } }

Say "当前账户: ${User}（提权: ${isElevated}）"

function Get-AclSafe([string]$path) {
    try { return Get-Acl -LiteralPath $path } catch { return $null }
}

function Test-Readable([string]$path) {
    try {
        if (Test-Path -LiteralPath $path -PathType Container) {
            Get-ChildItem -LiteralPath $path -ErrorAction Stop | Out-Null
        } else {
            [void][System.IO.File]::ReadAllBytes($path)
        }
        return $true
    } catch {
        return $false
    }
}

# ---- 先看现状：能不能读 ----
$needElevation = $false
$denied = @()
foreach ($t in ($dirTargets + $fileTargets)) {
    if (-not (Test-Path -LiteralPath $t)) { Say "跳过（不存在）: $t"; continue }
    if (Test-Readable $t) {
        Say "可读: $t"
        continue
    }
    $denied += $t
    Say "不可读: $t"
    if (-not (Get-AclSafe $t)) { $needElevation = $true }
}
if ($denied.Count -eq 0 -and -not $Strict) {
    Say "签名材料已可读，无需修改。"
    exit 0
}
if ($needElevation -and -not $isElevated) {
    [Console]::Error.WriteLine("[acl] 错误：当前权限连 ACL 都读不到，必须以管理员身份运行本脚本。")
    [Console]::Error.WriteLine("[acl] 请复制下面的命令到【管理员】PowerShell 里执行：")
    [Console]::Error.WriteLine("      powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`"")
    exit 5
}

# ---- 应用 ACL ----
$failed = @()
function Invoke-Icacls([string[]]$argsList) {
    $out = & icacls @argsList 2>&1
    if ($LASTEXITCODE -ne 0) {
        $script:failed += ($argsList -join ' ')
        if (-not $Quiet) { Write-Warning ("icacls 失败: " + ($out | Out-String).Trim()) }
        return $false
    }
    return $true
}

foreach ($d in $dirTargets) {
    if (-not (Test-Path -LiteralPath $d)) { continue }
    if ($Strict) {
        Say "收紧目录（仅 SYSTEM/Administrators）: $d"
        [void](Invoke-Icacls @($d, '/inheritance:r', '/grant:r', 'SYSTEM:(OI)(CI)F',
                               'Administrators:(OI)(CI)F', '/T', '/Q'))
    } else {
        Say "授权 ${User} 只读: $d"
        [void](Invoke-Icacls @($d, '/grant', "${User}:(OI)(CI)(R)", '/T', '/Q'))
    }
}
foreach ($f in $fileTargets) {
    if (-not (Test-Path -LiteralPath $f)) { continue }
    if ($Strict) {
        Say "收紧文件（仅 SYSTEM/Administrators）: $f"
        [void](Invoke-Icacls @($f, '/inheritance:r', '/grant:r', 'SYSTEM:F', 'Administrators:F', '/Q'))
    } else {
        Say "授权 ${User} 只读: $f"
        [void](Invoke-Icacls @($f, '/grant', "${User}:(R)", '/Q'))
    }
}

if ($failed.Count -gt 0) {
    [Console]::Error.WriteLine("[acl] 有 " + $failed.Count + " 项修改失败；请以管理员身份重跑本脚本。")
    exit 6
}

# ---- 复核 ----
$stillDenied = @()
foreach ($t in ($dirTargets + $fileTargets)) {
    if ((Test-Path -LiteralPath $t) -and -not (Test-Readable $t)) { $stillDenied += $t }
}
if ($stillDenied.Count -gt 0) {
    [Console]::Error.WriteLine("[acl] 仍然读不到: " + ($stillDenied -join ', '))
    [Console]::Error.WriteLine("[acl] 请尝试以管理员身份运行，或直接改用提权的命令行构建。")
    exit 7
}

Say "完成。现在可以在**非提权**的 shell 里重新签名："
Say "  build.bat     （或只跑签名：scripts\sign_binaries.ps1 -Files <文件>）"
exit 0
