# gen_signing_cert.ps1 - 一次性生成 AvEngine 内部代码签名证书
#
# 做什么：
#   1. 读取（必要时生成）256 位随机密码 service\passwd.txt
#   2. 生成自签名代码签名证书（CodeSigning EKU，RSA-3072/SHA-256，默认 5 年）
#   3. 导出 PFX（带密码）与 CER 到 bina\signing\，并收紧 ACL（只留 SYSTEM/Administrators）
#   4. 生成 service\generated\cert_pin.h：服务里**钉住**的证书 SHA-256 指纹
#      （服务不依赖系统根存储信任，只做精确指纹比对）
#   5. 生成 service\signing.json：给签名脚本用（PFX 路径/密码文件/指纹）
#
# 默认**不**把证书装进 LocalMachine\Root：钉指纹比"机器级信任一张自签根"更安全，
# 想装请显式加 -TrustRoot（需要管理员）。
#
# 用法（管理员 PowerShell，仅首次）：
#   scripts\gen_signing_cert.ps1
#   scripts\gen_signing_cert.ps1 -Force -Years 3 -TrustRoot
[CmdletBinding()]
param(
    [string]$Subject = "CN=AvEngine Internal Code Signing",
    [int]$Years = 5,
    [string]$OutDir = "",
    [string]$PasswordFile = "",
    [switch]$Force,
    [switch]$TrustRoot,
    # 默认额外给"当前账户"只读权限：否则非提权的构建 shell 读不到密码/PFX
    # （未提权时令牌里的 Administrators 是 deny-only），签名会静默失败。
    [switch]$NoUserAccess
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'bina\signing' }
if (-not $PasswordFile) { $PasswordFile = Join-Path $root 'service\passwd.txt' }
$pinDir = Join-Path $root 'service\generated'
$pinFile = Join-Path $pinDir 'cert_pin.h'
$pwdScript = Join-Path $PSScriptRoot 'gen_signing_password.py'
$pfxPath = Join-Path $OutDir 'avengine-signing.pfx'
$cerPath = Join-Path $OutDir 'avengine-signing.cer'
$jsonPath = Join-Path $root 'service\signing.json'

function Write-Step($msg) { Write-Host "[signing] $msg" }
# ---- 1. 密码 ----
if (-not (Test-Path -LiteralPath $PasswordFile)) {
    Write-Step "生成 256 位随机密码..."
    $py = Join-Path $root 'venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $py)) { $py = 'python' }
    & $py $pwdScript --out $PasswordFile | ForEach-Object { Write-Host "    $_" }
}
if (-not (Test-Path -LiteralPath $PasswordFile)) { throw "密码文件不存在: $PasswordFile" }
$password = (Get-Content -LiteralPath $PasswordFile -Raw).Trim()
if ($password.Length -lt 32) { throw "密码太短（应为 256 位随机串）: $PasswordFile" }

# ---- 2. 已有证书？----
if ((Test-Path -LiteralPath $pfxPath) -and -not $Force) {
    Write-Step "已存在 PFX: $pfxPath"
    Write-Step "如需重新生成（会换指纹，必须重新构建服务）请加 -Force"
    exit 0
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $pinDir | Out-Null

# ---- 3. 生成自签名证书（代码签名 EKU）----
Write-Step "创建自签名代码签名证书: $Subject"
$notAfter = (Get-Date).AddYears($Years)
$cert = New-SelfSignedCertificate `
    -Type Custom `
    -Subject $Subject `
    -FriendlyName 'AvEngine Internal Code Signing' `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyUsage DigitalSignature `
    -NotAfter $notAfter `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}CA=false')
Write-Step "证书指纹(SHA-1): $($cert.Thumbprint)"

# ---- 4. 导出 PFX / CER ----
$secure = ConvertTo-SecureString -String $password -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $secure | Out-Null
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
Write-Step "已导出: $pfxPath"
Write-Step "已导出: $cerPath"

# ---- 5. 计算 SHA-256 指纹并生成 cert_pin.h ----
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha256.ComputeHash($cert.RawData)
$pin = ($hashBytes | ForEach-Object { $_.ToString('X2') }) -join ''
Write-Step "证书 SHA-256 指纹（服务将钉住它）: $pin"

$pinContent = @"
// cert_pin.h - 由 scripts/gen_signing_cert.ps1 生成，请勿手工编辑
// 服务用它精确比对调用者签名证书；不依赖系统根存储信任。
#pragma once
#define AVPRIV_PINNED_CERT_SHA256 "$pin"
#define AVPRIV_PINNED_CERT_SUBJECT "$Subject"
#define AVPRIV_PIN_CONFIGURED 1
"@
Set-Content -LiteralPath $pinFile -Value $pinContent -Encoding UTF8
Write-Step "已写入: $pinFile"

# ---- 6. signing.json（给签名脚本）----
$json = [ordered]@{
    subject           = $Subject
    thumbprint_sha1   = $cert.Thumbprint
    thumbprint_sha256 = $pin
    pfx               = $pfxPath
    cer               = $cerPath
    password_file     = $PasswordFile
    not_after         = $notAfter.ToString('yyyy-MM-dd')
    created_utc       = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
}
$json | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
Write-Step "已写入: $jsonPath"

# ---- 7. 收紧 ACL：私钥与密码只给 SYSTEM/Administrators，另给当前账户只读 ----
# 为什么要给当前账户只读：未提权的 shell 里令牌中的 Administrators 是 "deny only"，
# 只授权 Administrators 会导致该 shell 读不到密码/PFX，签名静默失败。
# 要严格只留 SYSTEM/管理员（之后构建必须提权），加 -NoUserAccess。
$currentUser = "$env:USERDOMAIN\$env:USERNAME"
function Restrict-Path([string]$path, [switch]$IsDir) {
    try {
        $inherit = if ($IsDir) { '(OI)(CI)' } else { '' }
        & icacls $path /inheritance:r /grant:r "SYSTEM:${inherit}F" "Administrators:${inherit}F" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls 返回 $LASTEXITCODE" }
        if (-not $NoUserAccess) {
            & icacls $path /grant "${currentUser}:${inherit}(R)" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "icacls(/grant) 返回 $LASTEXITCODE" }
        }
        Write-Step ("已收紧权限: {0}{1}" -f $path, $(if ($NoUserAccess) { '' } else { "（额外给 ${currentUser} 只读）" }))
    } catch {
        Write-Warning "收紧权限失败（请手工检查）: $path - $_"
    }
}
Restrict-Path $OutDir -IsDir
if (Test-Path -LiteralPath $PasswordFile) { Restrict-Path $PasswordFile }
if ($NoUserAccess) {
    Write-Step "注意：使用了 -NoUserAccess —— 之后构建/签名必须用管理员身份运行"
}

# ---- 8. 可选：装进机器根存储 ----
if ($TrustRoot) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { Write-Warning "-TrustRoot 需要管理员权限，已跳过" }
    else {
        Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
        Write-Step "已把证书装入 LocalMachine\Root（可选步骤）"
    }
}

Write-Host ''
Write-Step '完成。下一步：'
Write-Host '    1) 重新构建服务（指纹是编译进去的）：service\build_service.bat'
Write-Host '    2) 签名二进制：scripts\sign_binaries.ps1 -Files <文件...>'
Write-Host '    3) 安装服务：service\bin\AvEnginePrivSvc.exe --install'
Write-Host ''
Write-Host '注意：bina\signing\、service\passwd.txt、service\generated\ 都已在 .gitignore 中，'
Write-Host '      不要把私钥或密码提交到代码库，也不要放进发布包。'
