# sign_binaries.ps1 - 用内部自签名证书给 AvEngine 二进制签名
#
# 设计原则：**签名是可选步骤，绝不阻断构建**。
#   * 找不到 signtool.exe、找不到 PFX、密码文件缺失 → 打印警告并以 0 退出；
#     加 -Require 才会以失败退出（发布流水线里可以用它强制要求签名）。
#
# 用法：
#   scripts\sign_binaries.ps1 -Files .\releases\AvEngine-0.1.0\avengine.exe
#   scripts\sign_binaries.ps1 -Files a.exe,b.dll -TimestampUrl http://timestamp.digicert.com
#   scripts\sign_binaries.ps1 -Files a.exe -Verify
#   scripts\sign_binaries.ps1 -Files a.exe -Require
#
# 位置绑定必须关掉：否则 `-Files a.exe b.dll` 会把第二个路径**位置绑定给 -SigningJson**，
# 脚本就去把 DLL 当 JSON 解析（"Invalid JSON primitive: MZ"）——签名静默没做、构建却报 OK。
# 多个文件要用数组：-Files "a.exe","b.dll"
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][string[]]$Files,
    [string]$SigningJson = "",
    [string]$TimestampUrl = "",
    [switch]$Verify,
    [switch]$Require
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $SigningJson) { $SigningJson = Join-Path $root 'service\signing.json' }
# 防御：误把二进制当成配置文件传进来时给出能看懂的报错，而不是 JSON 解析异常
if ($SigningJson -match '\.(exe|dll|sys|obj)$') {
    [Console]::Error.WriteLine("[sign] ERROR: -SigningJson 收到的是程序文件: ${SigningJson}")
    [Console]::Error.WriteLine("[sign] 传多个文件请用数组形式: -Files `"a.exe`",`"b.dll`"")
    exit 2
}

function Fail-Or-Warn([string]$msg) {
    # 不能用 Write-Error：本脚本 $ErrorActionPreference='Stop'，Write-Error 会变成
    # 终止性异常，后面的 exit 1 永远不会执行（退出码变成 0，-Require 形同虚设）。
    if ($Require) {
        [Console]::Error.WriteLine("[sign] ERROR: ${msg}")
        exit 1
    }
    Write-Warning "[sign] ${msg}（跳过签名；构建继续）"
    exit 0
}

# ---- 1. 定位 signtool ----
# 注意：这里刻意不用 "$x += <pipeline>" 累加，也不依赖"空值/单元素数组"的模糊真值判断
# （PowerShell 里 @('') 是真值、@() 是假值，判断写错会静默走错分支）。
$signtool = $null
$fromPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($fromPath) {
    $cand = @($fromPath)[0].Source
    if ($cand -and (Test-Path -LiteralPath $cand)) { $signtool = $cand }
}
if (-not $signtool) {
    foreach ($kit in @("${env:ProgramFiles(x86)}\Windows Kits\10\bin",
                       "${env:ProgramFiles}\Windows Kits\10\bin")) {
        if (-not (Test-Path -LiteralPath $kit)) { continue }
        $found = Get-ChildItem -LiteralPath $kit -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
            Where-Object { Test-Path -LiteralPath $_ }
        if ($found) { $signtool = @($found)[0]; break }
    }
}
if (-not $signtool) { Fail-Or-Warn "找不到 signtool.exe（装 Windows SDK 或用 VS 开发者命令行）" }
Write-Host "[sign] signtool: $signtool"

# ---- 2. 读签名配置 ----
# 判断签名材料的状态必须"试着读 + 分类异常"：
#   * Test-Path 在拒绝访问时会自己抛异常（EAP=Stop 下终止脚本）
#   * [System.IO.File]::Exists 在拒绝访问时返回 false（会被误报成"文件不存在"）
function Test-FileExists([string]$path) {
    try { return [System.IO.File]::Exists($path) } catch { return $false }
}
function Get-MaterialState([string]$path) {
    # readable | missing | denied
    try {
        [void][System.IO.File]::ReadAllBytes($path)
        return "readable"
    } catch [System.IO.FileNotFoundException] {
        return "missing"
    } catch [System.IO.DirectoryNotFoundException] {
        return "missing"
    } catch {
        # UnauthorizedAccessException（ACL 拒绝）与"被独占占用"都归为读不到
        return "denied"
    }
}

if (-not (Test-FileExists $SigningJson)) {
    Fail-Or-Warn "没有 ${SigningJson} —— 请先运行 scripts\gen_signing_cert.ps1"
}
try {
    $cfg = Get-Content -LiteralPath $SigningJson -Raw | ConvertFrom-Json
} catch {
    Fail-Or-Warn "签名配置读不出来: ${SigningJson} —— $($_.Exception.Message)"
}

$states = foreach ($name in @('password_file', 'pfx')) {
    $p = [string]$cfg.$name
    [pscustomobject]@{ path = $p; state = (Get-MaterialState $p) }
}
$missing = @($states | Where-Object { $_.state -eq 'missing' } | ForEach-Object { $_.path })
if ($missing.Count -gt 0) {
    Fail-Or-Warn "签名材料缺失: $($missing -join ', ') —— 请先运行 scripts\gen_signing_cert.ps1"
}
$denied = @($states | Where-Object { $_.state -eq 'denied' } | ForEach-Object { $_.path })
if ($denied.Count -gt 0) {
    Write-Host ""
    Write-Warning "[sign] 读不到签名材料（权限不足或文件被占用）："
    foreach ($d in $denied) { Write-Warning "[sign]     $d" }
    Write-Warning "[sign] 常见原因：gen_signing_cert.ps1 把 ACL 收紧成仅 SYSTEM/Administrators，"
    Write-Warning "[sign]           而未提权的 shell 里 Administrators 是 deny-only。"
    Write-Warning "[sign] 二选一："
    Write-Warning "[sign]   A) 以管理员身份重跑构建（或只重跑本签名脚本）"
    Write-Warning "[sign]   B) 给当前账户补只读权限（不必重生成证书、不必重编服务）："
    Write-Warning "[sign]        powershell -ExecutionPolicy Bypass -File scripts\grant_signing_access.ps1"
    Fail-Or-Warn "签名材料不可读，未签名"
}
$password = (Get-Content -LiteralPath $cfg.password_file -Raw).Trim()

# ---- 2.5 展开 -Files ----
# 调用方式有两种，必须都支持：
#   * 从 PowerShell 调：-Files "a.exe","b.dll"  → 已经是 2 个元素的数组
#   * 从 .bat/cmd 调：  -Files "a.exe,b.dll"    → **cmd 不按逗号拆分**，PowerShell 收到的是
#     一个含逗号的字符串。不展开的话它既不是文件也不会报错，只会"文件不存在，跳过"，
#     然后照样打印"完成"——发布包里的 exe 其实没签名（真实踩过）。
$expanded = @()
foreach ($item in $Files) {
    $candidate = ([string]$item).Trim()
    if (-not $candidate) { continue }
    if ($candidate.Contains(',') -and -not [System.IO.File]::Exists($candidate)) {
        foreach ($part in ($candidate -split ',')) {
            $p = $part.Trim().Trim('"')
            if ($p) { $expanded += $p }
        }
    } else {
        $expanded += $candidate
    }
}
if ($expanded.Count -eq 0) { Fail-Or-Warn "-Files 没给出任何文件" }
$Files = $expanded

# ---- 3. 逐个签名 / 校验 ----
# 签名落地自检：确认"签名真的写进去了，而且签名者是我们钉住的那张证书"。
# 只看 signtool 退出码不够（服务判定的是指纹匹配），但也不能只依赖某一个工具：
#   1) Get-AuthenticodeSignature —— 最好，直接给签名者证书指纹
#   2) signtool verify /pa /v    —— 回退；自签名未装根会报"不受信任的根"，那属于成功
#   3) 两者都不可用 → unverified（signtool sign 已返回 0，不因此判失败）
function Test-SignatureLanded([string]$path, $cfgObj, [string]$signtoolPath) {
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        if ($sig -and $sig.SignerCertificate) {
            $want = [string]$cfgObj.thumbprint_sha1
            if (-not $want) { return @{ result = 'ok'; note = '已签名' } }
            if ($sig.SignerCertificate.Thumbprint -eq $want) {
                $note = if ($sig.Status -eq 'UnknownError') {
                    '已签名（UnknownError = 自签名根不受信任，正常）'
                } else { "已签名（状态 $($sig.Status)）" }
                return @{ result = 'ok'; note = $note }
            }
            return @{ result = 'failed';
                      note = "签名者指纹不符: $($sig.SignerCertificate.Thumbprint) ≠ $want" }
        }
        return @{ result = 'failed'; note = '读不到签名者证书（可能未签名）' }
    } catch {
        try {
            # 原生命令写 stderr 时 EAP=Stop 会把它变成"终止性错误"，于是看不到输出文本 —— 调用
            # 期间临时降级为 Continue，才能拿到 signtool 原文来判断。
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                $out = (& $signtoolPath verify /pa /v $path 2>&1 | Out-String)
                $rc = $LASTEXITCODE
            } finally {
                $ErrorActionPreference = $prevEap
            }
            if ($rc -eq 0) { return @{ result = 'ok'; note = 'signtool verify 通过' } }
            # 自签名证书未装根时 signtool 的原话是 "A certificate chain processed, but terminated
            # in a root certificate which is not trusted by the trust provider." ——
            # 链已构建、文件确实有签名，属于正常情况。
            if ($out -match '0x800B0109|CERT_E_UNTRUSTEDROOT|untrusted root|not trusted by the trust provider|terminated in a root') {
                return @{ result = 'ok'; note = 'signtool verify 通过（根不受信任，自签名正常）' }
            }
            return @{ result = 'failed'; note = 'signtool verify 失败' }
        } catch {
            return @{ result = 'unverified'; note = "校验工具不可用: $($_.Exception.Message)" }
        }
    }
}

$failed = @()
$notFound = @()
$signedOk = @()
$unverified = @()
foreach ($f in $Files) {
    $path = (Resolve-Path -LiteralPath $f -ErrorAction SilentlyContinue)
    if (-not $path) {
        # 调用方点名的文件不存在 = 调用错误（或还没生成），必须计入失败，
        # 不能"警告后跳过"——那会产出"构建成功但没签名"的假象。
        Write-Warning "[sign] 文件不存在: $f"
        $notFound += $f
        continue
    }
    $path = $path.Path
    if ($Verify) {
        Write-Host "[sign] 校验: $path"
        $check = Test-SignatureLanded -path $path -cfgObj $cfg -signtoolPath $signtool
        switch ($check.result) {
            'ok' { Write-Host "[sign]   $($check.note)"; $signedOk += $path }
            'unverified' { Write-Warning "[sign]   $($check.note)"; $unverified += $path }
            default { Write-Warning "[sign]   $($check.note)"; $failed += $path }
        }
        continue
    }
    Write-Host "[sign] 签名: $path"
    $signArgs = @('sign', '/fd', 'sha256', '/f', $cfg.pfx, '/p', $password)
    if ($TimestampUrl) { $signArgs += @('/tr', $TimestampUrl, '/td', 'sha256') }
    $signArgs += $path
    & $signtool @signArgs
    if ($LASTEXITCODE -ne 0) {
        $failed += $path
        continue
    }
    $check = Test-SignatureLanded -path $path -cfgObj $cfg -signtoolPath $signtool
    Write-Host "[sign]   $($check.note)"
    switch ($check.result) {
        'failed' { $failed += $path }
        'unverified' { $unverified += $path; $signedOk += $path }   # sign 已成功，只是校验工具缺失
        default { $signedOk += $path }
    }
}

if ($failed.Count -gt 0 -or $notFound.Count -gt 0) {
    $all = @($failed + $notFound)
    if ($Require) {
        # 同样不能用 Write-Error：EAP=Stop 下它会先抛异常，exit 1 就到不了
        [Console]::Error.WriteLine("[sign] ERROR: 未签名/签名失败: " + ($all -join ', '))
        exit 1
    }
    Write-Warning "[sign] 未签名或签名失败: $($all -join ', ')"
    Write-Host ""
    Write-Warning "[sign] 注意：这些二进制**没有有效签名**。特权服务在目标机上会拒绝它们"
    Write-Warning "[sign]       （CALLER_NOT_SIGNED），因为服务里已经钉住了证书指纹。"
    Write-Warning "[sign]       修好权限后重新签名（不必重编服务）："
    Write-Warning "[sign]         powershell -ExecutionPolicy Bypass -File scripts\grant_signing_access.ps1"
    Write-Warning "[sign]         powershell -File scripts\sign_binaries.ps1 -Files <exe1>,<exe2>"
    exit 0
}
if ($signedOk.Count -eq 0) {
    # 一个都没处理（例如 -Files 全是空串）也不能报"完成"
    if ($Require) { [Console]::Error.WriteLine("[sign] ERROR: 没有任何文件被处理"); exit 1 }
    Write-Warning "[sign] 没有任何文件被签名/校验"
    exit 0
}
$pin = [string]$cfg.thumbprint_sha256
if ($pin.Length -ge 16) { $pin = $pin.Substring(0, 16) + '…' }
Write-Host "[sign] 完成：$($signedOk.Count) 个文件已签名并校验通过（指纹 ${pin}）"
if ($unverified.Count -gt 0) {
    # 明确区分"确认过"和"没工具确认"：后者不能算失败（signtool sign 已成功），但要说清楚
    Write-Warning "[sign] 其中 $($unverified.Count) 个未能二次校验（本机缺 Get-AuthenticodeSignature 与 signtool verify）："
    foreach ($u in $unverified) { Write-Warning "[sign]     $u" }
    Write-Warning "[sign] 可用下面命令复核签名者指纹应为 $($cfg.thumbprint_sha1)："
    Write-Warning "[sign]     signtool verify /pa /v <文件>"
}
exit 0
